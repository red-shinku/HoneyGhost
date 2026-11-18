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

/// 每轮最多处理的原始事件数
constexpr std::size_t kBudget = 64;

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
    hng::EventChannelReader<struct syscall_event>* raw_syscall,
    hng::EventChannelWriter<hng::syscall_semantic_data>* out_syscall)
    : raw_syscall_(raw_syscall), out_syscall_(out_syscall)
{
    const bool syscall_enabled =
        raw_syscall_ != nullptr && out_syscall_ != nullptr;

    HNG_LOG_INFO("semantic created: syscall line {}",
                 syscall_enabled ? "enabled" : "disabled");
    if ((raw_syscall_ != nullptr) != (out_syscall_ != nullptr)) {
        HNG_LOG_ERROR(
            "semantic syscall line misconfigured: raw and output channels must "
            "both be set");
    }
    if (!syscall_enabled) {
        HNG_LOG_WARN(
            "semantic has no complete input line; run() will wait for stop");
    }
    HNG_LOG_DEBUG("semantic budget: {} events per round", kBudget);
}

Semantic::~Semantic() = default;

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
    processed_syscall_.fetch_add(processed, std::memory_order_relaxed);
    return processed;
}

void Semantic::register_sources()
{
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

    std::size_t syscall_events = 0;
    try {
        register_sources();
        hng::EventLoop::Ready ready[hng::EventLoop::capacity()];
        while (!stopped_.load(std::memory_order_acquire)) {
            const std::size_t syscall_count  = drain_syscall(kBudget);
            syscall_events                  += syscall_count;
            if (syscall_count != 0) {
                continue;
            }
            // 输入取空时交还了通知权，此处的阻塞不会丢唤醒。
            // 就绪源由下一轮的排空取走。
            (void)loop_.wait(ready, hng::EventLoop::capacity());
        }
    }
    catch (const std::system_error& error) {
        HNG_LOG_ERROR("semantic event loop failed: {}; stopping", error.what());
    }

    // 采集侧已停机后输入不再增长，排空后退出。
    while (true) {
        const std::size_t syscall_count  = drain_syscall(kBudget);
        syscall_events                  += syscall_count;
        if (syscall_count == 0) {
            break;
        }
    }

    // 关闭输出通道：读端据此得知不会再有语义事件
    if (out_syscall_ != nullptr) {
        out_syscall_->close();
    }

    HNG_LOG_INFO("semantic stopped: processed {} syscall event(s)",
                 syscall_events);
    HNG_LOG_INFO("semantic drops: raw syscall {}, out syscall {}",
                 raw_syscall_ == nullptr
                     ? 0
                     : raw_syscall_->dropped() + raw_syscall_->rejected(),
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

hng::SemanticStats Semantic::stats() const
{
    hng::SemanticStats snapshot;
    snapshot.processed_syscall =
        processed_syscall_.load(std::memory_order_relaxed);
    if (raw_syscall_ != nullptr) {
        snapshot.raw_syscall_dropped  = raw_syscall_->dropped();
        snapshot.raw_syscall_rejected = raw_syscall_->rejected();
    }
    if (out_syscall_ != nullptr) {
        snapshot.out_syscall_dropped  = out_syscall_->dropped();
        snapshot.out_syscall_rejected = out_syscall_->rejected();
    }
    return snapshot;
}
