/**
 * @file test_cli_stream.cc
 * @brief CLIStream 与 CLIStreamManager 的单测
 * @details
 * 引擎走替身，不发真实事件；每个用例跑在独立的 engine::RunStandalone 实例里。
 * 覆盖：
 *  - 订阅成功后引擎持有本流，事件经队列送达，超容量的入队计入丢弃；
 *  - 拆除发出注销，且销号回执到达之前 teardown() 不返回；
 *  - subscribe 被拒时不建订阅，teardown() 只摘表、不等回执；
 *  - teardown() 幂等；
 *  - 停机广播置关闭标志，挂起的消费者随之结束。
 * @author red-shinku
 * @date 2026.10.16
 */

#include "agent/cli_server/src/cli_stream.hpp"

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <utility>

#include <userver/engine/async.hpp>
#include <userver/engine/run_standalone.hpp>
#include <userver/engine/sleep.hpp>
#include <userver/engine/task/task.hpp>

#include "agent/cli_server/src/cli_stream_manager.hpp"
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

/// 引擎替身：订阅是否接受可控；注销只记账，销号回执按需立即触发
class EngineStub final : public SubscriberRegService {
   public:
    /// 为 true 时在 unsubscribe 内立即回执，省去用例手工驱动回执
    bool accept                  = true;
    bool auto_ack                = true;
    int subscribed               = 0;
    int unsubscribed             = 0;
    RuntimeEventSink* sink       = nullptr;
    RuntimeEventSink* last_unsub = nullptr;
    UnsubscribeAck* ack          = nullptr;

    bool subscribe(RuntimeEventSink* s, RuntimeInfoFilter f,
                   UnsubscribeAck* a) override
    {
        ++subscribed;
        sink   = s;
        ack    = a;
        filter = std::move(f);
        return accept;
    }

    void unsubscribe(RuntimeEventSink* s) override
    {
        ++unsubscribed;
        last_unsub = s;
        if (auto_ack && ack != nullptr) {
            ack->on_unsubscribed();
        }
    }

    RuntimeInfoFilter filter;
};

// ---- 投递、丢弃与拆除 ----

void run_delivery_and_teardown()
{
    CLIStreamManager manager{4};
    EngineStub engine;
    CLIStream stream{manager, engine, RuntimeInfoFilter{}, 4};

    CHECK(stream.subscribe(), "订阅被接受");
    CHECK(engine.sink == &stream, "引擎持有本流");
    CHECK(engine.ack == &stream, "本流兼作自己的销号回执");
    CHECK(!stream.finished(), "刚建立的流未结束");

    for (uint32_t i = 1; i <= 6; ++i) {
        engine.sink->on_event(make_event(i));  // 引擎线程的回调形态
    }
    CHECK(stream.dropped() == 2, "超容量的入队计入丢弃");

    std::size_t cursor = 0;
    uint32_t popped    = 0;
    hng::RuntimeEvent event{};
    while (stream.try_pop(event, cursor)) {
        ++popped;
    }
    CHECK(popped == 4, "容量内的事件全部可取");
    CHECK(popped + stream.dropped() == 6, "取出数与丢弃数之和等于推入数");

    stream.teardown();
    CHECK(engine.unsubscribed == 1, "拆除时发出注销");
    CHECK(engine.last_unsub == &stream, "注销的是本流");
    CHECK(stream.finished(), "回执已到，流已结束");
}

// ---- 回执到达之前 teardown() 不返回 ----

void run_teardown_waits_for_ack()
{
    CLIStreamManager manager{4};
    EngineStub engine;
    engine.auto_ack = false;  // 回执由本用例手工触发

    CLIStream stream{manager, engine, RuntimeInfoFilter{}, 16};
    CHECK(stream.subscribe(), "订阅被接受");

    std::atomic<bool> torn_down{false};
    auto task = userver::engine::AsyncNoTracing([&stream, &torn_down] {
        stream.teardown();
        torn_down.store(true);
    });

    CHECK(wait_until([&engine] { return engine.unsubscribed == 1; }),
          "teardown 应发出注销");
    CHECK(!torn_down.load(), "回执未到达时 teardown 不得返回");

    engine.ack->on_unsubscribed();  // 引擎线程的回执

    CHECK(wait_until([&torn_down] { return torn_down.load(); }),
          "回执到达后 teardown 应返回");
    task.Wait();
    CHECK(stream.finished(), "回执后流已结束");
}

// ---- 订阅被拒：只摘表，不等回执 ----

void run_subscribe_rejected()
{
    CLIStreamManager manager{4};
    EngineStub engine;
    engine.accept   = false;
    engine.auto_ack = false;

    CLIStream stream{manager, engine, RuntimeInfoFilter{}, 16};
    CHECK(!stream.subscribe(), "引擎已停机时订阅被拒");

    stream.teardown();  // 未订阅，不应等待任何回执
    CHECK(engine.unsubscribed == 0, "未成立订阅不应发出注销");
}

// ---- 幂等 ----

void run_teardown_idempotent()
{
    CLIStreamManager manager{4};
    EngineStub engine;

    CLIStream stream{manager, engine, RuntimeInfoFilter{}, 16};
    CHECK(stream.subscribe(), "订阅被接受");

    stream.teardown();
    stream.teardown();
    CHECK(engine.unsubscribed == 1, "重复拆除只发一次注销");
}

// ---- 停机广播 ----

void run_shutdown_wakes_consumer()
{
    CLIStreamManager manager{4};
    EngineStub engine;

    CLIStream stream{manager, engine, RuntimeInfoFilter{}, 16};
    CHECK(stream.subscribe(), "订阅被接受");
    CHECK(!manager.shutting_down(), "未停机");

    std::atomic<bool> wait_returned{false};
    auto waiter = userver::engine::AsyncNoTracing([&stream, &wait_returned] {
        stream.wait();
        wait_returned.store(true);
    });

    userver::engine::SleepFor(std::chrono::milliseconds(10));
    CHECK(!wait_returned.load(), "无事件时消费者应挂起");

    manager.shutdown();
    CHECK(manager.shutting_down(), "停机标志已置位");
    CHECK(wait_until([&wait_returned] { return wait_returned.load(); }),
          "停机广播应唤醒挂起的消费者");
    CHECK(stream.finished(), "被要求停止的流已结束");
    waiter.Wait();

    stream.teardown();
    CHECK(engine.unsubscribed == 1, "停机后仍按拆除路径注销");
}

}  // namespace

int main()
{
    run_in_engine(run_delivery_and_teardown);
    run_in_engine(run_teardown_waits_for_ack);
    run_in_engine(run_subscribe_rejected);
    run_in_engine(run_teardown_idempotent);
    run_in_engine(run_shutdown_wakes_consumer);

    if (g_fail) {
        std::fprintf(stderr, "TOTAL FAILURES: %d\n", g_fail);
        return 1;
    }
    std::printf("ALL PASS\n");
    return 0;
}
