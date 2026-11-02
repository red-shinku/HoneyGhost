/**
 * @file semantic.cc
 * @brief 语义聚合的单线程轮转与停机排空。
 */
#include "agent/semantic/src/semantic.hpp"
#include "agent/util/include/log.hpp"

#include <cstdint>
#include <system_error>
#include <utility>

namespace {

/// 每条线在单轮中最多处理的原始事件数
constexpr std::size_t kBudgetPerLine = 64;

const char* state_name(hng::ComponentState state) noexcept
{
    switch (state) {
        case hng::ComponentState::CONSTRUCTED:
            return "CONSTRUCTED";
        case hng::ComponentState::READY:
            return "READY";
        case hng::ComponentState::RUNNING:
            return "RUNNING";
        case hng::ComponentState::STOPPED:
            return "STOPPED";
    }
    return "UNKNOWN";
}

}  // namespace

Semantic::Semantic(
    hng::EventChannelReader<file_access_data>* raw_file,
    hng::EventChannelReader<struct syscall_event>* raw_syscall,
    hng::EventChannelWriter<hng::file_semantic_data>* out_file,
    hng::EventChannelWriter<hng::syscall_semantic_data>* out_syscall)
    : raw_file_(raw_file),
      raw_syscall_(raw_syscall),
      out_file_(out_file),
      out_syscall_(out_syscall)
{
    const bool file_enabled = raw_file_ != nullptr && out_file_ != nullptr;
    const bool syscall_enabled =
        raw_syscall_ != nullptr && out_syscall_ != nullptr;

    HNG_LOG_INFO("semantic created: file line {}, syscall line {}",
                 file_enabled ? "enabled" : "disabled",
                 syscall_enabled ? "enabled" : "disabled");
    if ((raw_file_ != nullptr) != (out_file_ != nullptr)) {
        HNG_LOG_ERROR(
            "semantic file line misconfigured: raw and output channels must "
            "both be set");
    }
    if ((raw_syscall_ != nullptr) != (out_syscall_ != nullptr)) {
        HNG_LOG_ERROR(
            "semantic syscall line misconfigured: raw and output channels must "
            "both be set");
    }
    if (!file_enabled && !syscall_enabled) {
        HNG_LOG_WARN(
            "semantic has no complete input lines; run() will wait for stop");
    }
    HNG_LOG_DEBUG("semantic budget: {} events per line", kBudgetPerLine);
}

Semantic::~Semantic() = default;

std::size_t Semantic::drain_file(std::size_t budget)
{
    if (!raw_file_ || !out_file_) {
        return 0;
    }
    std::size_t processed = 0;
    while (processed < budget) {
        file_access_data raw;
        if (!raw_file_->try_pop(raw)) {
            break;
        }
        hng::file_semantic_data out;
        file_tool_.transform_one(raw, out);
        // 输出通道满或已关闭时丢弃，计数在通道内
        out_file_->push(std::move(out));
        ++processed;
    }
    return processed;
}

std::size_t Semantic::drain_syscall(std::size_t budget)
{
    if (!raw_syscall_ || !out_syscall_) {
        return 0;
    }
    std::size_t processed = 0;
    while (processed < budget) {
        struct syscall_event raw;
        if (!raw_syscall_->try_pop(raw)) {
            break;
        }
        hng::syscall_semantic_data out;
        syscall_tool_.transform_one(raw, out);
        // 输出通道满或已关闭时丢弃，计数在通道内
        out_syscall_->push(std::move(out));
        ++processed;
    }
    return processed;
}

void Semantic::register_sources()
{
    if (raw_file_ != nullptr && out_file_ != nullptr) {
        loop_.add(raw_file_->fd(), kFileTag);
    }
    if (raw_syscall_ != nullptr && out_syscall_ != nullptr) {
        loop_.add(raw_syscall_->fd(), kSyscallTag);
    }
}

void Semantic::run()
{
    hng::ComponentState expected = hng::ComponentState::READY;
    if (!lifecycle_.compare_exchange_strong(expected,
                                            hng::ComponentState::RUNNING)) {
        HNG_LOG_WARN("semantic run ignored: state is {}", state_name(expected));
        return;
    }

    HNG_LOG_INFO("semantic running");

    std::size_t file_events    = 0;
    std::size_t syscall_events = 0;
    try {
        register_sources();
        hng::EventLoop::Ready ready[hng::EventLoop::capacity()];
        while (!stopped_.load(std::memory_order_acquire)) {
            const std::size_t file_count     = drain_file(kBudgetPerLine);
            const std::size_t syscall_count  = drain_syscall(kBudgetPerLine);
            file_events                     += file_count;
            syscall_events                  += syscall_count;
            if (file_count + syscall_count != 0) {
                continue;
            }
            // 两条输入都取空：它们各自在取空时交还了通知权，此处的阻塞不会
            // 丢唤醒。就绪源由下一轮的排空取走。
            (void)loop_.wait(ready, hng::EventLoop::capacity());
        }
    }
    catch (const std::system_error& error) {
        HNG_LOG_ERROR("semantic event loop failed: {}; stopping", error.what());
    }

    // 采集侧已停机后输入不再增长，排空后退出。
    while (true) {
        const std::size_t file_count     = drain_file(kBudgetPerLine);
        const std::size_t syscall_count  = drain_syscall(kBudgetPerLine);
        file_events                     += file_count;
        syscall_events                  += syscall_count;
        if (file_count + syscall_count == 0) {
            break;
        }
    }

    // 关闭输出通道：读端据此得知不会再有语义事件
    if (out_file_ != nullptr) {
        out_file_->close();
    }
    if (out_syscall_ != nullptr) {
        out_syscall_->close();
    }

    HNG_LOG_INFO(
        "semantic stopped: processed {} file event(s), {} syscall event(s)",
        file_events, syscall_events);
    HNG_LOG_INFO(
        "semantic drops: raw file {}, raw syscall {}, out file {}, out syscall "
        "{}",
        raw_file_ == nullptr ? 0 : raw_file_->dropped() + raw_file_->rejected(),
        raw_syscall_ == nullptr
            ? 0
            : raw_syscall_->dropped() + raw_syscall_->rejected(),
        out_file_ == nullptr ? 0 : out_file_->dropped() + out_file_->rejected(),
        out_syscall_ == nullptr
            ? 0
            : out_syscall_->dropped() + out_syscall_->rejected());

    lifecycle_.store(hng::ComponentState::STOPPED, std::memory_order_release);
}

void Semantic::stop()
{
    if (lifecycle_.load(std::memory_order_acquire) ==
        hng::ComponentState::STOPPED) {
        HNG_LOG_DEBUG("semantic stop ignored: already stopped");
        return;
    }
    if (stopped_.exchange(true, std::memory_order_acq_rel)) {
        HNG_LOG_DEBUG("semantic stop ignored: already requested");
        return;
    }

    const hng::ComponentState before = lifecycle_.load(std::memory_order_acquire);
    HNG_LOG_INFO("semantic stop requested: state {}", state_name(before));

    // 唤醒可能阻塞在事件循环上的语义线程
    loop_.request_stop();

    hng::ComponentState current = before;
    while (current != hng::ComponentState::RUNNING &&
           !lifecycle_.compare_exchange_weak(current,
                                             hng::ComponentState::STOPPED)) {
    }
    if (current != hng::ComponentState::RUNNING &&
        lifecycle_.load(std::memory_order_acquire) ==
            hng::ComponentState::STOPPED) {
        HNG_LOG_INFO("semantic stopped before run: state {}", state_name(before));
    }
}

hng::ComponentState Semantic::state() const
{
    return lifecycle_.load(std::memory_order_acquire);
}
