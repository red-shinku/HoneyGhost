/**
 * @file test_cli_event_queue.cc
 * @brief CLIEventQueue 的单测
 * @details
 * 生产者是普通线程（引擎线程的角色），消费者是 userver 任务；每个用例跑在独立的
 * engine::RunStandalone 实例里。覆盖：
 *  - 容量足够时生产者推入的事件全部取出，不丢事件也不丢唤醒；
 *  - 队列满时入队计入丢弃，取出数与丢弃数之和等于推入数；
 *  - close() 置关闭标志并唤醒正在挂起的消费者；
 *  - 本任务被取消时 wait() 返回 false。
 * @note wait() 的挂起带复查片长，故「丢唤醒」表现为延迟而非卡死；本文件只断言
 * 事件不丢与唤醒成立，不断言唤醒时延。
 * @author red-shinku
 * @date 2026.10.16
 */

#include "agent/cli_server/src/cli_event_queue.hpp"

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <thread>

#include <userver/engine/async.hpp>
#include <userver/engine/run_standalone.hpp>
#include <userver/engine/sleep.hpp>
#include <userver/engine/task/task.hpp>

#include "agent/event_data/include/runtime_event.hpp"

namespace {

int g_fail = 0;

#define CHECK(cond, msg)                                                         \
    do {                                                                         \
        if (!(cond)) {                                                           \
            ++g_fail;                                                            \
            std::fprintf(stderr, "[FAIL] %s:%d  %s\n", __FILE__, __LINE__, msg); \
        }                                                                        \
    } while (0)

/// @brief 在本进程内跑一次协程引擎并执行 payload
/// @note 容器内没有 userfaultfd，协程栈用量监控必须关掉，否则引擎初始化即 abort
void run_in_engine(void (*payload)())
{
    static const userver::engine::TaskProcessorPoolsConfig config = [] {
        userver::engine::TaskProcessorPoolsConfig c;
        c.is_stack_usage_monitor_enabled = false;
        return c;
    }();
    userver::engine::RunStandalone(1, config, payload);
}

/// 等待谓词为真；只能在本任务的上下文里用，故用协程睡眠让出线程
template <typename Predicate>
bool wait_until(Predicate&& pred)
{
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) {
            return true;
        }
        userver::engine::SleepFor(std::chrono::milliseconds(1));
    }
    return pred();
}

hng::RuntimeEvent make_event(uint32_t pid)
{
    hng::RuntimeEvent event{};
    event.runtimeInfo.process   = hng::Process{pid, pid * 10};
    event.runtimeInfo.etype     = hng::EventType::SYSCALL_EVENT;
    event.runtimeInfo.roleID    = 0;
    event.runtimeInfo.contextID = 0;
    return event;
}

// ---- 丢弃计数（不需要协程）----

void run_drop_counting()
{
    CLIEventQueue queue{4};  // 容量取 2 的幂，故实际为 4
    for (uint32_t i = 1; i <= 10; ++i) {
        queue.push(make_event(i));
    }

    CHECK(queue.dropped() == 6, "超出容量的入队应计入丢弃");

    std::size_t cursor = 0;
    hng::RuntimeEvent event{};
    uint32_t kept = 0;
    while (queue.try_pop(event, cursor)) {
        ++kept;
    }
    CHECK(kept == 4, "容量内的入队应全部可取");
    CHECK(kept + queue.dropped() == 10, "取出数与丢弃数之和应等于推入数");
}

// ---- 不丢事件（生产者是普通线程）----

void run_no_lost_event()
{
    constexpr uint32_t kCount = 2000;
    CLIEventQueue queue{4096};  // 容量大于推入数，故不应有丢弃

    std::thread producer([&queue] {
        for (uint32_t i = 1; i <= kCount; ++i) {
            queue.push(make_event(i));
        }
        queue.close();
    });

    uint32_t received  = 0;
    std::size_t cursor = 0;
    for (;;) {
        hng::RuntimeEvent event{};
        if (queue.try_pop(event, cursor)) {
            ++received;
            continue;
        }
        if (queue.closed()) {
            break;  // 已关闭且队列取空
        }
        if (!queue.wait()) {
            break;  // 本任务被取消
        }
    }
    producer.join();

    CHECK(received == kCount, "容量足够时不应丢事件");
    CHECK(queue.dropped() == 0, "未满则不应计丢弃");
}

// ---- close() 唤醒挂起的消费者 ----

void run_close_wakes_waiter()
{
    CLIEventQueue queue{16};
    std::atomic<bool> wait_returned{false};

    auto waiter = userver::engine::AsyncNoTracing([&queue, &wait_returned] {
        queue.wait();
        wait_returned.store(true);
    });

    userver::engine::SleepFor(std::chrono::milliseconds(10));
    CHECK(!wait_returned.load(), "无信号时消费者应挂起");

    queue.close();
    CHECK(wait_until([&wait_returned] { return wait_returned.load(); }),
          "close() 应唤醒挂起的消费者");
    CHECK(queue.closed(), "close() 应置关闭标志");

    waiter.Wait();
}

// ---- 取消后 wait() 返回 false ----

void run_cancel_ends_wait()
{
    CLIEventQueue queue{16};
    std::atomic<bool> wait_result{true};

    auto waiter = userver::engine::AsyncNoTracing(
        [&queue, &wait_result] { wait_result.store(queue.wait()); });

    userver::engine::SleepFor(std::chrono::milliseconds(10));
    waiter.RequestCancel();
    waiter.Wait();

    CHECK(!wait_result.load(), "被取消的任务里 wait() 应返回 false");
}

}  // namespace

int main()
{
    run_drop_counting();
    run_in_engine(run_no_lost_event);
    run_in_engine(run_close_wakes_waiter);
    run_in_engine(run_cancel_ends_wait);

    if (g_fail) {
        std::fprintf(stderr, "TOTAL FAILURES: %d\n", g_fail);
        return 1;
    }
    std::printf("ALL PASS\n");
    return 0;
}
