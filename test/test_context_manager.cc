/**
 * @file test_context_manager.cc
 * @brief 上下文管理器的单元测试
 * @details
 * 覆盖 ContextManager（注意与工作平面的 test_context_maintainer 无关）：
 *  - 五个写接口经队列在消费线程上落地，注册后 lookup 命中根进程自指；
 *  - 主 context 与附属 context：同键二次注册进附属表，主表视图不变；
 *  - 挂靠：父已落定则继承其 context 根，未落定则空操作并计数；
 *  - 清理：完全删除或注销会删掉 context，残留的成员条目查询失配但不报错；
 *  - 幂等重放与未知注销：不改变表状态，后者计数；
 *  - stop() 语义：run() 之前 stop() 立即返回、已入队任务仍落地、此后入队被拒；
 *  - 多线程并发写入后状态自洽（供 TSAN 构建复验）。
 *
 * @note set_attr 只覆盖「不崩、不动其他状态」：属性没有任何查询入口可观测，
 *       其 UNKNOWN → 其他 的守卫与 ATTACK/EXTRA_ATTACK 钩子都无从断言。
 * @author red_shinku
 * @date 2026.9.19
 */

#include "agent/control_plane/include/context_manager.hpp"

#include <chrono>
#include <cstdio>
#include <functional>
#include <future>
#include <optional>
#include <thread>
#include <vector>

namespace {

int g_fail = 0;

#define CHECK(cond, msg)                                                         \
    do {                                                                         \
        if (!(cond)) {                                                           \
            ++g_fail;                                                            \
            std::fprintf(stderr, "[FAIL] %s:%d  %s\n", __FILE__, __LINE__, msg); \
        }                                                                        \
    } while (0)

using hng::contextattr;

hng::Process proc(uint32_t pid, uint64_t start)
{
    return hng::Process{pid, start};
}

ContextDeriveDecision decision(uint32_t context_id, contextattr attr)
{
    return ContextDeriveDecision{true, context_id, attr};
}

/// 轮询等待断言成立：落地在消费线程上，断言点只能等
bool wait_until(const std::function<bool()>& pred, int timeout_ms = 5000)
{
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return pred();
}

/// 起 run() 线程，析构时停止并 join
class Runner {
   public:
    explicit Runner(ContextManager& manager)
        : manager_(manager), thread_([this] { manager_.run(); })
    {
    }

    ~Runner()
    {
        manager_.stop();
        thread_.join();
    }

    Runner(const Runner&)            = delete;
    Runner& operator=(const Runner&) = delete;

   private:
    ContextManager& manager_;
    std::thread thread_;
};

/// 注册一个 context 根并等它落地，再断言查询命中
void register_root(ContextManager& manager, hng::Process root,
                   uint32_t context_id, const char* what)
{
    manager.register_contextID(root, decision(context_id, contextattr::UNKNOWN),
                               0);
    CHECK(wait_until(
              [&] { return manager.lookup(root).value_or(0) == context_id; }),
          what);
}

/// 用一个新根的注册当屏障：它落地即说明此前的写都已落地
void barrier(ContextManager& manager, uint32_t pid)
{
    manager.register_contextID(proc(pid, pid * 10),
                               decision(pid, contextattr::UNKNOWN), 0);
    CHECK(wait_until(
              [&] { return manager.lookup(proc(pid, pid * 10)).has_value(); }),
          "屏障应落地");
}

void run_register_and_lookup()
{
    ContextManager manager;
    Runner runner(manager);

    register_root(manager, proc(100, 1000), 7, "注册后应能查到该 context");
    CHECK(!manager.lookup(proc(100, 9999)).has_value(),
          "同 pid 不同 start_time 应失配");
    CHECK(!manager.lookup(proc(101, 1000)).has_value(), "未注册进程应失配");
    CHECK(!manager.lookup_extra(proc(100, 1000)).has_value(),
          "未注册附属 context 时应失配");

    // 幂等重放：同键同 contextID，不改变表状态
    manager.register_contextID(proc(100, 1000), decision(7, contextattr::UNKNOWN),
                               0);
    barrier(manager, 200);
    CHECK(manager.lookup(proc(100, 1000)).value_or(0) == 7,
          "幂等重放后主 context 不变");
    CHECK(!manager.lookup_extra(proc(100, 1000)).has_value(),
          "幂等重放不得产生附属 context");
}

void run_extra_context()
{
    ContextManager manager;
    Runner runner(manager);

    register_root(manager, proc(100, 1000), 7, "注册后应能查到该 context");

    // 同键、不同 contextID：进附属表，主表视图不变
    manager.register_contextID(proc(100, 1000),
                               decision(8, contextattr::EXTRA_ATTACK), 0);
    CHECK(wait_until([&] {
              return manager.lookup_extra(proc(100, 1000)).value_or(0) == 8;
          }),
          "同键二次注册应成为附属 context");
    CHECK(manager.lookup(proc(100, 1000)).value_or(0) == 7,
          "附属 context 不得覆盖主 context");

    // 附属 context 的幂等重放
    manager.register_contextID(proc(100, 1000),
                               decision(8, contextattr::EXTRA_ATTACK), 0);
    barrier(manager, 200);
    CHECK(manager.lookup_extra(proc(100, 1000)).value_or(0) == 8,
          "附属 context 幂等重放不变");
}

void run_bind_to_ctxroot()
{
    ContextManager manager;
    Runner runner(manager);

    // 父已落定：子继承父的 context 根
    register_root(manager, proc(100, 1000), 7, "父进程应注册成功");
    manager.bind_to_ctxroot(proc(101, 1001), proc(100, 1000));
    CHECK(wait_until(
              [&] { return manager.lookup(proc(101, 1001)).value_or(0) == 7; }),
          "子进程应继承父进程的 context");
    CHECK(manager.stats().ctxroot_parent_unsettled == 0, "父已落定时不应计数");

    // 父未落定：空操作并计数，归属保持待定
    manager.bind_to_ctxroot(proc(300, 3000), proc(301, 3001));
    CHECK(
        wait_until([&] { return manager.stats().ctxroot_parent_unsettled == 1; }),
        "父未落定应计数");
    CHECK(!manager.lookup(proc(300, 3000)).has_value(),
          "父未落定时归属应保持待定");

    // 补调（父已落定）后归属落定
    manager.bind_to_ctxroot(proc(300, 3000), proc(100, 1000));
    CHECK(wait_until(
              [&] { return manager.lookup(proc(300, 3000)).value_or(0) == 7; }),
          "补调后应继承父进程的 context");
}

void run_cleanup()
{
    ContextManager manager;
    Runner runner(manager);

    // 完全删除 context 根：context 一并清除，残留成员条目查询失配但不报错
    register_root(manager, proc(100, 1000), 7, "根进程应注册成功");
    manager.bind_to_ctxroot(proc(101, 1001), proc(100, 1000));
    CHECK(wait_until(
              [&] { return manager.lookup(proc(101, 1001)).value_or(0) == 7; }),
          "成员应挂靠成功");

    manager.on_process_removed(proc(100, 1000));
    CHECK(
        wait_until([&] { return !manager.lookup(proc(100, 1000)).has_value(); }),
        "根被完全删除后应失配");
    CHECK(!manager.lookup(proc(101, 1001)).has_value(),
          "根已清除时残留成员条目应失配（容错）");

    manager.on_process_removed(proc(101, 1001));
    barrier(manager, 400);
    CHECK(!manager.lookup(proc(101, 1001)).has_value(), "成员被删后仍应失配");

    // 注销：主 context 与同键的附属 context 一并清除
    register_root(manager, proc(200, 2000), 9, "第二个根应注册成功");
    manager.register_contextID(proc(200, 2000),
                               decision(10, contextattr::EXTRA_ATTACK), 0);
    CHECK(wait_until([&] {
              return manager.lookup_extra(proc(200, 2000)).value_or(0) == 10;
          }),
          "附属 context 应注册成功");

    manager.unregister_contextID(proc(200, 2000));
    CHECK(
        wait_until([&] { return !manager.lookup(proc(200, 2000)).has_value(); }),
        "注销后应失配");
    CHECK(!manager.lookup_extra(proc(200, 2000)).has_value(),
          "注销应连同附属 context 一并清除");
    CHECK(manager.stats().unknown_unregister == 0, "已知根的注销不应计数");

    // 注销未注册的根：丢弃并计数
    manager.unregister_contextID(proc(500, 5000));
    CHECK(wait_until([&] { return manager.stats().unknown_unregister == 1; }),
          "注销未注册的根应计数");
}

void run_set_attr()
{
    ContextManager manager;
    Runner runner(manager);

    register_root(manager, proc(100, 1000), 7, "根进程应注册成功");

    // 属性没有查询入口，只覆盖「不崩、不动其他状态」
    manager.set_attr(proc(100, 1000), 7, contextattr::NORMAL);
    manager.set_attr(proc(100, 1000), 7,
                     contextattr::ATTACK);  // 非 UNKNOWN 起不再变更
    manager.set_attr(proc(100, 1000), 8,
                     contextattr::NORMAL);  // contextID 不匹配
    manager.set_attr(proc(999, 9990), 7, contextattr::NORMAL);  // 未注册进程
    barrier(manager, 200);
    CHECK(manager.lookup(proc(100, 1000)).value_or(0) == 7,
          "set_attr 不得影响归属视图");
    CHECK(!manager.lookup(proc(999, 9990)).has_value(),
          "对未注册进程 set_attr 不应产生条目");
}

void run_stop_semantics()
{
    // run() 之前 stop()：run() 立即返回
    {
        ContextManager manager;
        manager.stop();
        manager.stop();  // 幂等

        std::packaged_task<void()> task([&manager] { manager.run(); });
        std::future<void> done = task.get_future();
        std::thread worker(std::move(task));
        const bool returned =
            done.wait_for(std::chrono::seconds(5)) == std::future_status::ready;
        CHECK(returned, "run() 之前 stop() 时 run() 应立即返回");
        if (returned) {
            worker.join();
        }
        else {
            worker.detach();  // 卡住的线程不能 join，交由进程退出兜底
        }
    }

    // 已入队的任务在 stop() 之后仍被落地
    {
        ContextManager manager;
        manager.register_contextID(proc(100, 1000),
                                   decision(7, contextattr::UNKNOWN), 0);
        manager.stop();
        manager.run();
        CHECK(manager.lookup(proc(100, 1000)).value_or(0) == 7,
              "stop() 之后已入队的任务应被落地");
    }

    // stop() 之后的入队被拒（队列契约），不落地
    {
        ContextManager manager;
        manager.stop();
        manager.register_contextID(proc(200, 2000),
                                   decision(9, contextattr::UNKNOWN), 0);
        manager.run();  // 队列为空，应直接返回
        CHECK(!manager.lookup(proc(200, 2000)).has_value(),
              "停止后的入队不得落地");
    }
}

void run_concurrent_writers()
{
    ContextManager manager;
    Runner runner(manager);

    constexpr int kThreads = 4;
    constexpr int kEach    = 100;

    std::vector<std::thread> writers;
    for (int t = 0; t < kThreads; ++t) {
        writers.emplace_back([&manager, t] {
            for (int i = 0; i < kEach; ++i) {
                const uint32_t pid = 1000 + static_cast<uint32_t>(t) * 100 +
                                     static_cast<uint32_t>(i);
                // 同一线程内先注册后注销：队列保序，注销不会先于注册到达
                manager.register_contextID(
                    proc(pid, pid * 10), decision(pid, contextattr::UNKNOWN), 0);
                manager.bind_to_ctxroot(proc(pid + 1, pid * 10 + 1),
                                        proc(pid, pid * 10));
                manager.unregister_contextID(proc(pid, pid * 10));
            }
        });
    }
    for (std::thread& writer : writers) {
        writer.join();
    }

    barrier(manager, 9000);
    for (int t = 0; t < kThreads; ++t) {
        for (int i = 0; i < kEach; ++i) {
            const uint32_t pid =
                1000 + static_cast<uint32_t>(t) * 100 + static_cast<uint32_t>(i);
            CHECK(!manager.lookup(proc(pid, pid * 10)).has_value(),
                  "并发注册注销后不应有残留");
        }
    }
    CHECK(manager.stats().unknown_unregister == 0, "保序下不应出现未知注销");
    CHECK(manager.stats().ctxroot_parent_unsettled == 0,
          "注册先于挂靠落地，不应出现父未落定");
}

}  // namespace

int main()
{
    run_register_and_lookup();
    run_extra_context();
    run_bind_to_ctxroot();
    run_cleanup();
    run_set_attr();
    run_stop_semantics();
    run_concurrent_writers();

    if (g_fail) {
        std::fprintf(stderr, "TOTAL FAILURES: %d\n", g_fail);
        return 1;
    }
    std::printf("ALL PASS\n");
    return 0;
}
