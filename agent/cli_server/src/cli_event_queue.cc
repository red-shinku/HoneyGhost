/**
 * @file cli_event_queue.cc
 * @brief CLIEventQueue 的实现
 * @author red-shinku
 * @date 2026.10.16
 */

#include "agent/cli_server/src/cli_event_queue.hpp"

#include <chrono>

#include <userver/engine/task/cancel.hpp>

namespace {

/// 挂起的复查周期。取消会被立即投递，故片长只决定多久复查一次状态
constexpr std::chrono::milliseconds kWakeSlice{50};

}  // namespace

CLIEventQueue::CLIEventQueue(std::size_t capacity) : queue_(capacity) {}

void CLIEventQueue::push(const hng::RuntimeEvent& event)
{
    if (!queue_.push(event)) {
        dropped_.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    // 只在取得通知权时唤醒：唤醒的代价与风暴都落在引擎线程上
    if (!notified_.exchange(true, std::memory_order_acq_rel)) {
        wakeup_.Send();
    }
}

bool CLIEventQueue::try_pop(hng::RuntimeEvent& out, std::size_t& cursor)
{
    if (queue_.pop(out, cursor)) {
        return true;
    }
    // 取空后交还通知权：此后生产者的入队必然唤醒
    notified_.store(false, std::memory_order_release);
    // 再查一次，覆盖交还通知权之前的入队
    return queue_.pop(out, cursor);
}

bool CLIEventQueue::wait()
{
    // 超时与取消都返回 false，返回值区分不出二者，故一律重查取消标志；
    // 信号只表示状态可能变化，不再是停止判据
    [[maybe_unused]] const bool signalled = wakeup_.WaitForEventFor(kWakeSlice);
    return !userver::engine::current_task::ShouldCancel();
}

void CLIEventQueue::wake() { wakeup_.Send(); }

void CLIEventQueue::close()
{
    closed_.store(true, std::memory_order_release);
    wakeup_.Send();
}

bool CLIEventQueue::closed() const
{
    return closed_.load(std::memory_order_acquire);
}

uint64_t CLIEventQueue::dropped() const
{
    return dropped_.load(std::memory_order_relaxed);
}
