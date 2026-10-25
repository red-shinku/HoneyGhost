/**
 * @file test_process_seed.cc
 * @brief 进程树初始化 seed 与生命周期状态机的单元测试
 * @details
 * 覆盖阶段 1 的 PM seed：
 *  - seed 后 lookup / resolve 与批次一致，child_count 与批次顺序无关；
 *  - 批内重复身份只落一条、同 pid 保留 start_time 较大者、非法条目计数；
 *  - 父缺失照常插入、计 parent_missing、不建立虚拟根；
 *  - seed 不发通知、不转交角色归属，也不改动运行期统计；
 *  - 重复 seed 被拒且树不变；未 seed 的 run() 立即返回；stop 后 seed 被拒；
 *  - seed 后积压 ADD 命中已 seed 身份不重置父计数，新 ADD 正常递增；
 *  - 状态迁移 CONSTRUCTED → READY → RUNNING → STOPPED。
 * @author red_shinku
 * @date 2026.10.25
 */

#include "agent/control_plane/include/process_component.hpp"
#include "agent/control_plane/src/process_manager.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <future>
#include <string>
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

hng::ProcessSeedEntry entry(uint32_t pid, uint64_t start, uint32_t ppid = 0,
                            uint64_t ppid_start = 0, std::string exe = {})
{
    hng::ProcessSeedEntry e;
    e.process         = hng::Process{pid, start};
    e.ppid            = ppid;
    e.ppid_start_time = ppid_start;
    e.exe             = std::move(exe);
    return e;
}

hng::event_head head(uint32_t pid, uint64_t start, uint32_t ppid,
                     uint64_t ppid_start)
{
    hng::event_head ehead{};
    ehead.pid             = pid;
    ehead.pid_start_time  = start;
    ehead.ppid            = ppid;
    ehead.ppid_start_time = ppid_start;
    return ehead;
}

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

/// 退出通知计数
class CountingSink : public ProcessLifecycleSink {
   public:
    void on_process_exited(hng::Process) override
    {
        calls_.fetch_add(1, std::memory_order_relaxed);
    }

    std::size_t calls() const { return calls_.load(std::memory_order_relaxed); }

   private:
    std::atomic<std::size_t> calls_{0};
};

/// 角色继承转交计数
class CountingRoleJoin : public RoleJoinService {
   public:
    void bind_to_role(hng::Process, hng::Process) override
    {
        binds_.fetch_add(1, std::memory_order_relaxed);
    }

    std::size_t binds() const { return binds_.load(std::memory_order_relaxed); }

   private:
    std::atomic<std::size_t> binds_{0};
};

/// 三层树：根 1，子 100/101，孙 200，曾孙 300
hng::ProcessSeedBatch tree_batch()
{
    hng::ProcessSeedBatch batch;
    batch.entries = {
        entry(1, 10, 0, 0, "/sbin/init"),
        entry(100, 1000, 1, 10, "/bin/bash"),
        entry(101, 1010, 1, 10, "/bin/sh"),
        entry(200, 2000, 100, 1000, "/usr/bin/grep"),
        entry(300, 3000, 200, 2000, "/usr/bin/grep"),
    };
    return batch;
}

void check_tree(ProcessManager& manager)
{
    const auto root = manager.lookup(proc(1, 10));
    CHECK(root.has_value(), "根进程应存在");
    CHECK(root.has_value() && root->child_count == 2, "根的孩子计数应为 2");
    CHECK(root.has_value() && root->ppid == 0 && root->ppid_start_time == 0,
          "根没有父进程");
    CHECK(root.has_value() && root->kind == hng::ProcessKind::REAL,
          "seed 的进程应为 REAL");
    CHECK(root.has_value() && root->exe == "/sbin/init", "exe 应取自条目");

    const auto bash = manager.lookup(proc(100, 1000));
    CHECK(bash.has_value() && bash->ppid == 1 && bash->ppid_start_time == 10,
          "父身份应写成条目值");
    CHECK(bash.has_value() && bash->child_count == 1, "子 100 的孩子计数应为 1");

    const auto sh = manager.lookup(proc(101, 1010));
    CHECK(sh.has_value() && sh->child_count == 0, "叶进程孩子计数应为 0");

    const auto grep = manager.lookup(proc(200, 2000));
    CHECK(grep.has_value() && grep->ppid == 100 && grep->ppid_start_time == 1000,
          "父身份应按 (pid, start_time) 匹配");
    CHECK(grep.has_value() && grep->child_count == 1, "孙 200 的孩子计数应为 1");

    const auto leaf = manager.lookup(proc(300, 3000));
    CHECK(leaf.has_value() && leaf->child_count == 0, "曾孙孩子计数应为 0");

    CHECK(!manager.lookup(proc(100, 9999)).has_value(),
          "同 pid 不同 start_time 应失配");

    const auto resolved = manager.resolve(200);
    CHECK(resolved.has_value() && *resolved == proc(200, 2000),
          "resolve 应返回批次中的身份");
    CHECK(!manager.resolve(999).has_value(), "未 seed 的 pid 应返回空");
}

void run_seed_tree()
{
    ProcessManager manager;
    const ProcessSeedReport report = manager.seed(tree_batch());

    CHECK(report.inserted == 5, "五个条目都应插入");
    CHECK(report.duplicate == 0, "不应有批内重复");
    CHECK(report.pid_reused == 0, "不应有 pid 复用");
    CHECK(report.parent_missing == 0, "父进程都在批内");
    CHECK(report.invalid == 0, "不应有非法条目");
    CHECK(report.rejected_state == 0, "首次 seed 不应被状态拒绝");
    CHECK(manager.state() == hng::ComponentState::READY, "seed 后应为 READY");

    check_tree(manager);

    const ProcessManagerStats stats = manager.stats();
    CHECK(stats.pid_reused == 0, "seed 不得改动 pid_reused");
    CHECK(stats.stale_add == 0, "seed 不得改动 stale_add");
    CHECK(stats.parent_missing == 0, "seed 不得改动 parent_missing");
    CHECK(stats.tombstone_depth == 0, "seed 不得写墓碑");
}

void run_child_count_order()
{
    hng::ProcessSeedBatch forward  = tree_batch();
    hng::ProcessSeedBatch backward = tree_batch();
    std::reverse(backward.entries.begin(), backward.entries.end());

    ProcessManager a;
    ProcessManager b;
    CHECK(a.seed(forward).inserted == 5, "正序批次应全部插入");
    CHECK(b.seed(backward).inserted == 5, "逆序批次应全部插入");

    check_tree(a);
    check_tree(b);
}

void run_selection()
{
    ProcessManager manager;
    hng::ProcessSeedBatch batch;
    batch.entries = {
        entry(100, 1000),  // 同 pid 较小 start_time，被顶掉
        entry(100, 2000),  // 保留
        entry(100, 2000),  // 批内重复
        entry(200, 2000),  // 保留
        entry(0, 5000),    // pid 为 0
        entry(300, 0),     // start_time 为 0
    };

    const ProcessSeedReport report = manager.seed(batch);
    CHECK(report.inserted == 2, "每个 pid 只保留一个身份");
    CHECK(report.pid_reused == 1, "被顶掉的条目应计 pid 复用");
    CHECK(report.duplicate == 1, "同身份第二条应计重复");
    CHECK(report.invalid == 2, "pid 或 start_time 为 0 应计非法");
    CHECK(report.parent_missing == 0, "都是根，不应计父缺失");

    CHECK(!manager.lookup(proc(100, 1000)).has_value(),
          "较小 start_time 的身份不得落地");
    CHECK(manager.lookup(proc(100, 2000)).has_value(), "保留的身份应落地");
    CHECK(manager.lookup(proc(200, 2000)).has_value(), "另一个身份应落地");
}

void run_parent_missing()
{
    ProcessManager manager;
    hng::ProcessSeedBatch batch;
    batch.entries = {
        entry(10, 100), entry(20, 200, 99, 0),  // 父不在批内
        entry(30, 300, 10, 0),                  // 父在批内但 start_time 未知
        entry(40, 400, 10, 100)                 // 正常父子
    };

    const ProcessSeedReport report = manager.seed(batch);
    CHECK(report.inserted == 4, "父缺失的节点照常插入");
    CHECK(report.parent_missing == 2, "父不在批内或 start_time 未知都应计数");
    CHECK(report.rejected_state == 0, "正常 seed 不应被拒");

    const auto orphan = manager.lookup(proc(20, 200));
    CHECK(orphan.has_value(), "父缺失的节点应可查");
    CHECK(
        orphan.has_value() && orphan->ppid == 99 && orphan->ppid_start_time == 0,
        "未知父保持未知");
    CHECK(!manager.resolve(99).has_value(), "不得为缺失的父建立虚拟根");
    CHECK(!manager.lookup(proc(99, 0)).has_value(), "不得插入父记录");

    const auto unknown_start = manager.lookup(proc(30, 300));
    CHECK(unknown_start.has_value() && unknown_start->child_count == 0,
          "父 start_time 未知的节点自身计数为 0");

    const auto parent = manager.lookup(proc(10, 100));
    CHECK(parent.has_value() && parent->child_count == 1,
          "只有身份可解析的子进程才递增父计数");

    const ProcessManagerStats stats = manager.stats();
    CHECK(stats.parent_missing == 0, "seed 的父缺失不写入运行期统计");
}

void run_no_notifications()
{
    CountingSink sink;
    CountingRoleJoin join;
    ProcessManager manager;
    manager.add_process_lifecycle_sink(&sink);
    manager.set_role_join_service(&join);

    manager.seed(tree_batch());
    CHECK(sink.calls() == 0, "seed 不得发退出通知");
    CHECK(join.binds() == 0, "seed 不得转交角色归属");
}

void run_rejected_seeds()
{
    ProcessManager manager;
    hng::ProcessSeedBatch first;
    first.entries = {entry(1, 10)};
    CHECK(manager.seed(first).inserted == 1, "首次 seed 应落地");

    hng::ProcessSeedBatch second;
    second.entries                   = {entry(2, 20)};
    const ProcessSeedReport rejected = manager.seed(second);
    CHECK(rejected.rejected_state == 1, "重复 seed 应被状态拒绝");
    CHECK(rejected.inserted == 0 && rejected.invalid == 0,
          "被拒的 seed 不应写入任何统计");
    CHECK(manager.lookup(proc(1, 10)).has_value(), "原树应保持");
    CHECK(!manager.lookup(proc(2, 20)).has_value(), "第二次批次不得落地");
}

void run_stop_before_seed()
{
    ProcessManager manager;
    manager.stop();
    CHECK(manager.state() == hng::ComponentState::STOPPED,
          "未 READY 时 stop 应直接置 STOPPED");

    hng::ProcessSeedBatch batch;
    batch.entries                  = {entry(1, 10)};
    const ProcessSeedReport report = manager.seed(batch);
    CHECK(report.rejected_state == 1, "stop 之后 seed 应被拒绝");
    CHECK(!manager.lookup(proc(1, 10)).has_value(), "被拒的 seed 不得写入");
    CHECK(manager.state() == hng::ComponentState::STOPPED,
          "被拒的 seed 不应改变状态");
}

void run_run_requires_seed()
{
    ProcessManager manager;

    std::packaged_task<void()> task([&manager] { manager.run(); });
    std::future<void> done = task.get_future();
    std::thread worker(std::move(task));
    const bool returned =
        done.wait_for(std::chrono::seconds(5)) == std::future_status::ready;
    CHECK(returned, "未 seed 的 run() 应立即返回");
    if (returned) {
        worker.join();
    }
    else {
        worker.detach();  // 卡住的线程不能 join，交由进程退出兜底
    }
    CHECK(manager.state() == hng::ComponentState::CONSTRUCTED,
          "未 seed 的 run() 不得改变状态");
}

void run_backlog_add()
{
    ProcessManager manager;
    hng::ProcessSeedBatch batch;
    batch.entries = {entry(1, 10), entry(100, 1000, 1, 10)};
    CHECK(manager.seed(batch).inserted == 2, "初始树应落地");
    CHECK(manager.lookup(proc(1, 10))->child_count == 1, "父计数初值为 1");

    CountingSink sink;
    CountingRoleJoin join;
    manager.add_process_lifecycle_sink(&sink);
    manager.set_role_join_service(&join);

    Runner runner(manager);

    // 积压 ADD 命中已 seed 的同一身份：幂等，不重置 child_count
    manager.register_pid(head(100, 1000, 1, 10));
    manager.register_pid(head(500, 5000, 0, 0));  // 屏障
    CHECK(wait_until([&] { return manager.lookup(proc(500, 5000)).has_value(); }),
          "屏障应落地");
    CHECK(manager.lookup(proc(100, 1000))->child_count == 0,
          "同身份重放不得重置自身计数");
    CHECK(manager.lookup(proc(1, 10))->child_count == 1,
          "同身份重放不得重置父计数");
    CHECK(manager.stats().pid_reused == 0, "同身份重放不得计 pid 复用");
    CHECK(sink.calls() == 0, "同身份重放不得发退出通知");

    // seed 后的新 ADD 正常落地并递增父计数
    manager.register_pid(head(101, 1010, 1, 10));
    CHECK(wait_until([&] { return manager.lookup(proc(101, 1010)).has_value(); }),
          "新进程应落地");
    CHECK(manager.lookup(proc(1, 10))->child_count == 2, "新 ADD 应递增父计数");
    CHECK(manager.lookup(proc(101, 1010))->ppid_start_time == 10,
          "新 ADD 的父 start_time 应来自事件");
    CHECK(sink.calls() == 0, "正常 ADD 不应发退出通知");
}

void run_component_seed()
{
    auto component = hng::make_process_component();
    CHECK(component->state() == hng::ComponentState::CONSTRUCTED,
          "组件初始应为 CONSTRUCTED");

    hng::ProcessSeedBatch batch;
    batch.entries                  = {entry(1, 10, 0, 0, "/sbin/init"),
                                      entry(100, 1000, 1, 10, "/bin/bash")};
    const ProcessSeedReport report = component->seed_service().seed(batch);
    CHECK(report.inserted == 2, "经组件 seed_service 应写入两条");
    CHECK(component->state() == hng::ComponentState::READY,
          "经组件 seed 后应为 READY");

    const auto child = component->lookup_service().lookup(proc(100, 1000));
    CHECK(child.has_value() && child->exe == "/bin/bash",
          "组件查询面应看到 seed 结果");
    CHECK(component->stats().parent_missing == 0, "经组件 seed 不改动运行期统计");
}

void run_state_machine()
{
    ProcessManager manager;
    CHECK(manager.state() == hng::ComponentState::CONSTRUCTED,
          "初始状态应为 CONSTRUCTED");

    CHECK(manager.seed(tree_batch()).inserted == 5, "seed 应落地");
    CHECK(manager.state() == hng::ComponentState::READY, "seed 后应为 READY");

    std::thread worker([&manager] { manager.run(); });
    CHECK(wait_until(
              [&] { return manager.state() == hng::ComponentState::RUNNING; }),
          "run() 应进入 RUNNING");
    manager.stop();
    worker.join();
    CHECK(manager.state() == hng::ComponentState::STOPPED,
          "run() 返回后应为 STOPPED");
}

}  // namespace

int main()
{
    run_seed_tree();
    run_child_count_order();
    run_selection();
    run_parent_missing();
    run_no_notifications();
    run_rejected_seeds();
    run_stop_before_seed();
    run_run_requires_seed();
    run_backlog_add();
    run_component_seed();
    run_state_machine();

    if (g_fail) {
        std::fprintf(stderr, "TOTAL FAILURES: %d\n", g_fail);
        return 1;
    }
    std::printf("ALL PASS\n");
    return 0;
}
