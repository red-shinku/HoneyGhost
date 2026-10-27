/**
 * @file semantic.cc
 * @brief 语义聚合的单线程轮转与停机排空。
 */
#include "agent/semantic/include/semantic.hpp"

#include <chrono>
#include <thread>
#include <utility>

namespace {

/// 每条线在单轮中最多处理的原始事件数
constexpr std::size_t kBudgetPerLine = 64;

/// 两条输入队列都为空时的休眠周期
constexpr std::chrono::milliseconds kIdlePoll{1};

}  // namespace

Semantic::Semantic(hng::SPSC_Queue<file_access_data>* raw_file,
                   hng::SPSC_Queue<struct syscall_event>* raw_syscall,
                   hng::SPSC_Queue<hng::file_semantic_data>* out_file,
                   hng::SPSC_Queue<hng::syscall_semantic_data>* out_syscall)
    : raw_file_(raw_file),
      raw_syscall_(raw_syscall),
      out_file_(out_file),
      out_syscall_(out_syscall)
{
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
        if (!raw_file_->pop(raw)) {
            break;
        }
        hng::file_semantic_data out;
        file_tool_.transform_one(raw, out);
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
        if (!raw_syscall_->pop(raw)) {
            break;
        }
        hng::syscall_semantic_data out;
        syscall_tool_.transform_one(raw, out);
        out_syscall_->push(std::move(out));
        ++processed;
    }
    return processed;
}

void Semantic::run()
{
    hng::ComponentState expected = hng::ComponentState::READY;
    if (!lifecycle_.compare_exchange_strong(expected,
                                            hng::ComponentState::RUNNING)) {
        return;
    }

    while (!stopped_.load(std::memory_order_acquire)) {
        const std::size_t processed =
            drain_file(kBudgetPerLine) + drain_syscall(kBudgetPerLine);
        if (processed == 0) {
            std::this_thread::sleep_for(kIdlePoll);
        }
    }

    // 采集侧已停机后输入队列不再增长，排空后退出。
    while (drain_file(kBudgetPerLine) + drain_syscall(kBudgetPerLine) > 0) {
    }

    lifecycle_.store(hng::ComponentState::STOPPED, std::memory_order_release);
}

void Semantic::stop()
{
    stopped_.store(true, std::memory_order_release);
    hng::ComponentState current = lifecycle_.load(std::memory_order_acquire);
    while (current != hng::ComponentState::RUNNING &&
           !lifecycle_.compare_exchange_weak(current,
                                             hng::ComponentState::STOPPED)) {
    }
}

hng::ComponentState Semantic::state() const
{
    return lifecycle_.load(std::memory_order_acquire);
}
