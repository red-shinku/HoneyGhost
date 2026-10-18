/**
 * @file test_process_manager.cc
 * @brief 进程管理器的单元测试
 * @details
 * 覆盖 ProcessManager：
 *  - 注册 / 注销经队列在消费线程上落地，查询按 (pid, start_time) 判等；
 *  - 角色归属转交：真正插入或替换后转交一次，幂等重放不转交；
 *  - pid 复用：旧实例按退役路径处理——无存活子进程时立刻报完全删除，
 *    有子进程时转入虚拟根、待其子进程退出后才报，且不虚增其父进程的孩子计数；
 *  - 完全删除的两条路径：无子进程直接删除、虚拟根计数归零后驱逐，
 *    两条都通知 context 与角色两路清理；
 *  - 未知进程与重复注销：不报、不崩；
 *  - stop() 语义：run() 之前 stop() 立即返回、已入队任务仍落地、此后入队被拒；
 *  - 多线程并发注册 / 注销后状态自洽（供 TSAN 构建复验）。
 * @author red_shinku
 * @date 2026.9.18
 */

#include "agent/control_plane/src/process_manager.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <functional>
#include <future>
#include <mutex>
#include <optional>
#include <thread>
#include <utility>
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

hng::Process proc(uint32_t pid, uint64_t start)
{
    return hng::Process{pid, start};
}

hng::event_head head(uint32_t pid, uint64_t start, uint32_t ppid,
                     uint64_t ppid_start)
{
    hng::event_head ehead{};
    ehead.pid             = pid;
    ehead.pid_start_time  = start;
    ehead.ppid            = ppid;
    ehead.ppid_start_time = ppid_start;
    ehead.type            = hng::EventType::SYSCALL_EVENT;
    return ehead;
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

/// 三个注入点的记录：计数为原子（消费线程写、用例线程读），明细只在停止后读
struct Recorder {
    std::atomic<std::size_t> binds{0};
    std::atomic<std::size_t> ctx_removed{0};
    std::atomic<std::size_t> role_removed{0};

    std::mutex mutex;
    std::vector<std::pair<hng::Process, hng::Process>> bind_detail;
    std::vector<hng::Process> ctx_detail;
    std::vector<hng::Process> role_detail;
};

class FakeContextClear : public ContextClearService {
   public:
    explicit FakeContextClear(Recorder& rec) : rec_(rec) {}

    void on_process_removed(hng::Process p) override
    {
        {
            std::lock_guard lock(rec_.mutex);
            rec_.ctx_detail.push_back(p);
        }
        rec_.ctx_removed.fetch_add(1);
    }

   private:
    Recorder& rec_;
};

class FakeRoleJoin : public RoleJoinService {
   public:
    explicit FakeRoleJoin(Recorder& rec) : rec_(rec) {}

    void bind_to_role(hng::Process child, hng::Process parent) override
    {
        {
            std::lock_guard lock(rec_.mutex);
            rec_.bind_detail.emplace_back(child, parent);
        }
        rec_.binds.fetch_add(1);
    }

   private:
    Recorder& rec_;
};

class FakeRoleClear : public RoleClearService {
   public:
    explicit FakeRoleClear(Recorder& rec) : rec_(rec) {}

    void on_process_removed(hng::Process p) override
    {
        {
            std::lock_guard lock(rec_.mutex);
            rec_.role_detail.push_back(p);
        }
        rec_.role_removed.fetch_add(1);
    }

   private:
    Recorder& rec_;
};

/// 起 run() 线程，析构时停止并 join
class Runner {
   public:
    explicit Runner(ProcessManager& manager)
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
    ProcessManager& manager_;
    std::thread thread_;
};

void run_register_and_lookup()
{
    ProcessManager manager;
    Runner runner(manager);

    manager.register_pid(head(100, 1000, 1, 10));
    CHECK(wait_until([&] { return manager.lookup(proc(100, 1000)).has_value(); }),
          "注册应落地");

    std::optional<hng::ProcessMessage> msg = manager.lookup(proc(100, 1000));
    CHECK(msg.has_value() && msg->pid == 100 && msg->pid_start_time == 1000 &&
              msg->ppid == 1 && msg->ppid_start_time == 10,
          "进程记录应带 ppid 与各自的 start_time");
    CHECK(msg.has_value() && msg->child_count == 0, "新进程的孩子计数应为 0");
    CHECK(!manager.lookup(proc(100, 9999)).has_value(),
          "同 pid 不同 start_time 应失配");
    CHECK(!manager.lookup(proc(101, 1000)).has_value(), "未注册的 pid 应失配");
}

void run_bind_transfer()
{
    Recorder rec;
    FakeRoleJoin join(rec);
    ProcessManager manager;
    manager.set_role_join_service(&join);
    Runner runner(manager);

    manager.register_pid(head(100, 1000, 1, 10));
    CHECK(wait_until([&] { return rec.binds.load() == 1; }), "插入应转交一次");
    {
        std::lock_guard lock(rec.mutex);
        CHECK(rec.bind_detail.size() == 1 &&
                  rec.bind_detail[0].first == proc(100, 1000) &&
                  rec.bind_detail[0].second == proc(1, 10),
              "转交的应是 (新进程, 事件的 ppid)");
    }

    // 幂等重放：同 pid + start_time 已存在，不插入也不转交
    manager.register_pid(head(100, 1000, 1, 10));
    manager.register_pid(head(200, 2000, 1, 10));  // 屏障
    CHECK(wait_until([&] { return rec.binds.load() == 2; }), "屏障应转交");
    CHECK(rec.binds.load() == 2, "幂等重放不得转交");

    // pid 复用：同 pid 不同 start_time，替换旧实例并转交新实例
    manager.register_pid(head(200, 2001, 1, 10));
    CHECK(wait_until([&] { return rec.binds.load() == 3; }), "覆盖应转交");
    CHECK(!manager.lookup(proc(200, 2000)).has_value(), "旧实例应被顶掉");
    CHECK(manager.lookup(proc(200, 2001)).has_value(), "新实例应在");
    CHECK(manager.stats().pid_reused == 1, "pid 复用应计数");
}

void run_pid_reuse()
{
    Recorder rec;
    FakeContextClear ctx(rec);
    FakeRoleClear roles(rec);
    FakeRoleJoin join(rec);
    ProcessManager manager;
    manager.set_context_service(&ctx);
    manager.set_role_clear_service(&roles);
    manager.set_role_join_service(&join);
    Runner runner(manager);

    // 覆盖的旧实例无存活子进程：应立刻报完全删除
    manager.register_pid(head(200, 2000, 1, 10));
    CHECK(wait_until([&] { return manager.lookup(proc(200, 2000)).has_value(); }),
          "注册应落地");
    manager.register_pid(head(200, 2001, 1, 10));  // pid 复用
    CHECK(wait_until([&] {
              return rec.ctx_removed.load() == 1 && rec.role_removed.load() == 1;
          }),
          "无子进程的旧实例应立刻报完全删除");
    CHECK(!manager.lookup(proc(200, 2000)).has_value(), "旧实例应失配");
    CHECK(manager.lookup(proc(200, 2001)).has_value(), "新实例应可查");
    {
        std::lock_guard lock(rec.mutex);
        CHECK(rec.ctx_detail.size() == 1 && rec.ctx_detail[0] == proc(200, 2000),
              "报的应是旧实例");
    }

    // 覆盖的旧实例有存活子进程：转入虚拟根，仍可追溯，且不报完全删除
    manager.register_pid(head(300, 3000, 1, 10));
    manager.register_pid(head(301, 3001, 300, 3000));  // 子进程
    CHECK(wait_until([&] { return manager.lookup(proc(301, 3001)).has_value(); }),
          "子进程应落地");
    CHECK(manager.lookup(proc(300, 3000))->child_count == 1,
          "旧实例的孩子计数应为 1");

    manager.register_pid(head(300, 3002, 1, 10));  // 覆盖，此时旧实例有子
    manager.register_pid(head(500, 5000, 1, 10));  // 屏障
    CHECK(wait_until([&] { return manager.lookup(proc(500, 5000)).has_value(); }),
          "屏障应落地");
    CHECK(rec.ctx_removed.load() == 1 && rec.role_removed.load() == 1,
          "有存活子进程的旧实例不得报完全删除");
    CHECK(manager.lookup(proc(300, 3000)).has_value(),
          "旧实例应留在虚拟根里，仍可追溯");
    CHECK(manager.lookup(proc(300, 3002)).has_value(), "新实例应可查");

    // 子进程退出后，旧实例在虚拟根里的计数归零，此时才报完全删除
    manager.unregister_pid(proc(301, 3001));
    CHECK(wait_until([&] {
              return rec.ctx_removed.load() == 3 && rec.role_removed.load() == 3;
          }),
          "最后一个子进程退出后应报子进程与旧实例两者的完全删除");
    CHECK(!manager.lookup(proc(300, 3000)).has_value(), "被驱逐的旧实例应失配");
    {
        std::lock_guard lock(rec.mutex);
        CHECK(rec.ctx_detail.size() == 3 &&
                  rec.ctx_detail[1] == proc(301, 3001) &&
                  rec.ctx_detail[2] == proc(300, 3000),
              "应先报子进程、后报被驱逐的旧实例");
    }

    // 父进程的孩子计数不得被虚增：爷爷最终仍应能被完全删除
    manager.register_pid(head(400, 4000, 1, 10));      // 爷爷
    manager.register_pid(head(401, 4001, 400, 4000));  // 父
    manager.register_pid(head(401, 4002, 400, 4000));  // 覆盖父
    CHECK(wait_until([&] { return rec.ctx_removed.load() == 4; }),
          "被覆盖的父应报完全删除");
    CHECK(manager.lookup(proc(400, 4000))->child_count == 1,
          "爷爷的孩子计数应仍是 1，不得虚增");

    manager.unregister_pid(proc(401, 4002));
    CHECK(wait_until([&] { return rec.ctx_removed.load() == 5; }),
          "新父退出应报完全删除");
    manager.unregister_pid(proc(400, 4000));
    CHECK(wait_until([&] { return rec.ctx_removed.load() == 6; }),
          "孩子计数不虚增，爷爷退出时才能被完全删除");
    CHECK(!manager.lookup(proc(400, 4000)).has_value(), "爷爷应已失配");
    {
        std::lock_guard lock(rec.mutex);
        CHECK(rec.ctx_detail.back() == proc(400, 4000), "最后报的应是爷爷");
    }

    CHECK(manager.stats().pid_reused == 3, "三次 pid 复用都应计数");
}

void run_resolve()
{
    ProcessManager manager;
    Runner runner(manager);

    CHECK(!manager.resolve(0).has_value(), "pid 0 应返回空");
    CHECK(!manager.resolve(777).has_value(), "未注册的 pid 应返回空");

    manager.register_pid(head(100, 1000, 1, 10));
    CHECK(wait_until([&] {
              auto p = manager.resolve(100);
              return p.has_value() && *p == proc(100, 1000);
          }),
          "注册后应能按 pid 解析");

    // pid 复用：返回当前实例
    manager.register_pid(head(100, 2000, 1, 10));
    CHECK(wait_until([&] {
              auto p = manager.resolve(100);
              return p.has_value() && *p == proc(100, 2000);
          }),
          "pid 复用后应返回新实例");

    // 虚拟根：父进程退出后仍可追溯
    manager.register_pid(head(300, 3000, 1, 10));
    manager.register_pid(head(301, 3001, 300, 3000));
    CHECK(wait_until([&] {
              return manager.lookup(proc(301, 3001)).has_value();
          }),
          "子进程应落地");
    manager.unregister_pid(proc(300, 3000));
    manager.register_pid(head(500, 5000, 1, 10));  // 屏障
    CHECK(wait_until([&] {
              return manager.lookup(proc(500, 5000)).has_value();
          }),
          "屏障应落地");
    CHECK(manager.lookup(proc(300, 3000)).has_value(), "父进程应在虚拟根中");
    std::optional<hng::Process> p = manager.resolve(300);
    CHECK(p.has_value() && *p == proc(300, 3000),
          "虚拟根应能按 pid 解析出 start_time");

    // 子进程退出后虚拟根被驱逐
    manager.unregister_pid(proc(301, 3001));
    manager.register_pid(head(501, 5001, 1, 10));  // 屏障
    CHECK(wait_until([&] {
              return manager.lookup(proc(501, 5001)).has_value();
          }),
          "第二个屏障应落地");
    CHECK(!manager.resolve(300).has_value(), "虚拟根驱逐后应返回空");
}

void run_fully_removed_paths()
{
    Recorder rec;
    FakeContextClear ctx(rec);
    FakeRoleClear roles(rec);
    FakeRoleJoin join(rec);
    ProcessManager manager;
    manager.set_context_service(&ctx);
    manager.set_role_clear_service(&roles);
    manager.set_role_join_service(&join);
    Runner runner(manager);

    // 路径一：无存活子进程 → 直接删除即完全删除
    manager.register_pid(head(100, 1000, 1, 10));
    CHECK(wait_until([&] { return manager.lookup(proc(100, 1000)).has_value(); }),
          "注册应落地");
    manager.unregister_pid(proc(100, 1000));
    CHECK(wait_until([&] {
              return rec.ctx_removed.load() == 1 && rec.role_removed.load() == 1;
          }),
          "无子进程的直接删除应报完全删除");

    // 路径二：有存活子进程 → 先留作虚拟根，子进程被删后才随之驱逐
    manager.register_pid(head(200, 2000, 1, 10));
    manager.register_pid(head(201, 2001, 200, 2000));
    CHECK(wait_until([&] { return manager.lookup(proc(201, 2001)).has_value(); }),
          "子进程应落地");
    CHECK(manager.lookup(proc(200, 2000))->child_count == 1,
          "父进程的孩子计数应为 1");

    manager.unregister_pid(proc(200, 2000));
    // 屏障：注册新进程；此时父进程应已转入虚拟根，仍可追溯
    manager.register_pid(head(300, 3000, 1, 10));
    CHECK(wait_until([&] { return manager.lookup(proc(300, 3000)).has_value(); }),
          "屏障应落地");
    CHECK(manager.lookup(proc(200, 2000)).has_value(),
          "有存活子进程的父进程应留作虚拟根，仍可查");
    CHECK(rec.ctx_removed.load() == 1 && rec.role_removed.load() == 1,
          "留作虚拟根不得报完全删除");

    manager.unregister_pid(proc(201, 2001));
    // 屏障：注册新进程；子进程删除后父进程的虚拟根计数归零，应被驱逐
    manager.register_pid(head(301, 3001, 1, 10));
    CHECK(wait_until([&] {
              return rec.ctx_removed.load() == 3 && rec.role_removed.load() == 3;
          }),
          "子进程删除后应驱逐虚拟根并报两者的完全删除");
    CHECK(!manager.lookup(proc(200, 2000)).has_value(), "被驱逐后应失配");
    CHECK(!manager.lookup(proc(201, 2001)).has_value(), "子进程应失配");

    // 两路清理收到的进程集合应一致
    std::vector<hng::Process> ctx_seen;
    std::vector<hng::Process> role_seen;
    {
        std::lock_guard lock(rec.mutex);
        ctx_seen  = rec.ctx_detail;
        role_seen = rec.role_detail;
    }
    CHECK(ctx_seen == role_seen, "context 与角色两路应收到同一批进程");
    CHECK(ctx_seen.size() == 3, "应恰好报三次完全删除");
}

void run_unknown_and_duplicate()
{
    Recorder rec;
    FakeContextClear ctx(rec);
    FakeRoleClear roles(rec);
    ProcessManager manager;
    manager.set_context_service(&ctx);
    manager.set_role_clear_service(&roles);
    Runner runner(manager);

    // 未知进程的注销：既不在实进程树也不在虚拟根树，静默无操作
    manager.unregister_pid(proc(777, 7777));
    manager.register_pid(head(100, 1000, 1, 10));
    CHECK(wait_until([&] { return manager.lookup(proc(100, 1000)).has_value(); }),
          "注册应落地");

    manager.unregister_pid(proc(100, 1000));
    CHECK(wait_until([&] { return rec.ctx_removed.load() == 1; }),
          "首次注销应报完全删除");
    manager.unregister_pid(proc(100, 1000));  // 重复注销

    manager.register_pid(head(101, 1001, 1, 10));  // 屏障
    CHECK(wait_until([&] { return manager.lookup(proc(101, 1001)).has_value(); }),
          "屏障应落地");
    CHECK(rec.ctx_removed.load() == 1 && rec.role_removed.load() == 1,
          "未知进程与重复注销都不得产生通知");
}

void run_stop_semantics()
{
    // run() 之前 stop()：run() 立即返回
    {
        ProcessManager manager;
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
        ProcessManager manager;
        manager.register_pid(head(100, 1000, 1, 10));
        manager.stop();
        manager.run();
        CHECK(manager.lookup(proc(100, 1000)).has_value(),
              "stop() 之后已入队的任务应被落地");
    }

    // stop() 之后的入队被拒（队列契约），不落地
    {
        ProcessManager manager;
        manager.stop();
        manager.register_pid(head(200, 2000, 1, 10));
        manager.run();  // 队列为空，应直接返回
        CHECK(!manager.lookup(proc(200, 2000)).has_value(),
              "停止后的入队不得落地");
    }
}

void run_concurrent_producers()
{
    Recorder rec;
    FakeContextClear ctx(rec);
    FakeRoleClear roles(rec);
    FakeRoleJoin join(rec);
    ProcessManager manager;
    manager.set_context_service(&ctx);
    manager.set_role_clear_service(&roles);
    manager.set_role_join_service(&join);
    Runner runner(manager);

    constexpr int kThreads = 4;
    constexpr int kEach    = 100;
    constexpr int kTotal   = kThreads * kEach;

    std::vector<std::thread> producers;
    for (int t = 0; t < kThreads; ++t) {
        producers.emplace_back([&manager, t] {
            for (int i = 0; i < kEach; ++i) {
                const uint32_t pid = 1000 + static_cast<uint32_t>(t) * 100 +
                                     static_cast<uint32_t>(i);
                manager.register_pid(head(pid, pid * 10, 1, 10));
                manager.unregister_pid(proc(pid, pid * 10));
            }
        });
    }
    for (std::thread& producer : producers) {
        producer.join();
    }

    CHECK(wait_until([&] {
              return rec.ctx_removed.load() == static_cast<std::size_t>(kTotal) &&
                     rec.role_removed.load() == static_cast<std::size_t>(kTotal);
          }),
          "每个进程注销后都应报完全删除");
    CHECK(rec.binds.load() == static_cast<std::size_t>(kTotal),
          "每个进程注册都应转交一次");

    for (int t = 0; t < kThreads; ++t) {
        for (int i = 0; i < kEach; ++i) {
            const uint32_t pid =
                1000 + static_cast<uint32_t>(t) * 100 + static_cast<uint32_t>(i);
            CHECK(!manager.lookup(proc(pid, pid * 10)).has_value(),
                  "并发注册注销后不应有残留");
        }
    }
}

}  // namespace

int main()
{
    run_register_and_lookup();
    run_bind_transfer();
    run_pid_reuse();
    run_resolve();
    run_fully_removed_paths();
    run_unknown_and_duplicate();
    run_stop_semantics();
    run_concurrent_producers();

    if (g_fail) {
        std::fprintf(stderr, "TOTAL FAILURES: %d\n", g_fail);
        return 1;
    }
    std::printf("ALL PASS\n");
    return 0;
}
