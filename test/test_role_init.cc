/**
 * @file test_role_init.cc
 * @brief 角色初始化期的单元测试
 * @details
 * 覆盖阶段 3 的初始化入口：
 *  - RoleSourceBarrier：未登记即就绪、未全上报超时、全部可用、有源不可用、
 *    未登记源的上报被忽略、重复上报以最后一次为准；
 *  - drain()：run() 之前同步落地 JOIN / BIND / EXIT，不改状态，之后的事件
 *    仍由 run() 消费；
 *  - 状态机：未 reconcile 的 run 被拒、reconcile 置 READY、重复 reconcile 与
 *    stop 后的 reconcile 被拒、run 置 RUNNING、stop 后置 STOPPED；
 *  - barrier()：RUNNING 后返回时此前入队的事件已落地、消费线程被占住时超时、
 *    停止后的入队被拒；
 *  - 幽灵清理：不在完整快照内且已退出则删、仍存活则留、无存活结论计 UNKNOWN、
 *    不完整快照跳过；
 *  - 补绑定：逆序批内父先子后、沿链继承、父无角色计忽略且不暂存、子已有归属
 *    不改写；
 *  - cgroup 重读：空结果保留原成员并计数、非空结果 adopt 并通知、不产生等待项。
 * @author red_shinku
 * @date 2026.10.25
 */

#include "agent/control_plane/include/role_seed_service.hpp"
#include "agent/control_plane/src/role_manager.hpp"
#include "agent/event_data/include/process_seed.hpp"
#include "agent/role_discovery/include/role_source_barrier.hpp"

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <mutex>
#include <optional>
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

using hng::role::RoleAction;
using hng::role::RoleEvent;
using hng::role::RoleSource;

/// 记录型出口：记录回调序列
class RecordingSink : public RoleLifecycleSink {
   public:
    enum class Kind { JOINED, LEFT, MP_CHANGED, MEMBERS_ADDED };

    struct Call {
        Kind kind;
        uint32_t roleID;
        std::vector<hng::Process> members;  ///< 仅 MEMBERS_ADDED 非空
    };

    void on_role_joined(const hng::Role& role) override
    {
        add(Kind::JOINED, role);
    }

    void on_role_left(const hng::Role& role) override { add(Kind::LEFT, role); }

    void on_role_main_process_changed(const hng::Role& role) override
    {
        add(Kind::MP_CHANGED, role);
    }

    void on_role_members_changed(const hng::Role& role,
                                 const std::vector<hng::Process>& added) override
    {
        add(Kind::MEMBERS_ADDED, role, added);
    }

    std::vector<Call> calls()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return calls_;
    }

    void clear()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        calls_.clear();
    }

   private:
    void add(Kind kind, const hng::Role& role,
             const std::vector<hng::Process>& members = {})
    {
        std::lock_guard<std::mutex> lock(mutex_);
        calls_.push_back(Call{kind, role.roleID, members});
    }

    std::mutex mutex_;
    std::vector<Call> calls_;
};

/// 在加入回调里阻塞的出口：用来把消费线程固定在 land 上，验证 barrier 超时
class BlockingSink : public RoleLifecycleSink {
   public:
    void on_role_joined(const hng::Role&) override { block(); }

    void on_role_left(const hng::Role&) override {}

    void on_role_main_process_changed(const hng::Role&) override {}

    void on_role_members_changed(const hng::Role&,
                                 const std::vector<hng::Process>&) override
    {
    }

    /// 等到出口已进入阻塞；超时返回 false
    bool wait_entered()
    {
        std::unique_lock<std::mutex> lock(mutex_);
        return cv_.wait_for(lock, std::chrono::seconds(5),
                            [this] { return entered_; });
    }

    void release()
    {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            released_ = true;
        }
        cv_.notify_all();
    }

   private:
    void block()
    {
        std::unique_lock<std::mutex> lock(mutex_);
        entered_ = true;
        cv_.notify_all();
        cv_.wait_for(lock, std::chrono::seconds(5), [this] { return released_; });
    }

    std::mutex mutex_;
    std::condition_variable cv_;
    bool entered_  = false;
    bool released_ = false;
};

/// 轮询等待条件成立；超时返回最后一次判定
bool wait_until(const std::function<bool()>& predicate)
{
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (std::chrono::steady_clock::now() < deadline) {
        if (predicate()) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return predicate();
}

hng::Process proc(uint32_t pid, uint64_t start)
{
    return hng::Process{pid, start};
}

hng::ProcessSeedEntry seed_entry(uint32_t pid, uint64_t start, uint32_t ppid = 0,
                                 uint64_t ppid_start = 0)
{
    hng::ProcessSeedEntry entry;
    entry.process         = proc(pid, start);
    entry.ppid            = ppid;
    entry.ppid_start_time = ppid_start;
    return entry;
}

RoleEvent mk_join(const std::string& key, uint32_t pid, uint64_t start,
                  std::vector<hng::Process> members = {})
{
    RoleEvent event;
    event.action                        = RoleAction::JOIN;
    event.payload.identity.instance_key = key;
    event.payload.identity.type_key     = "nginx";
    event.payload.identity.source       = RoleSource::SYSTEMD;
    event.payload.main_process          = proc(pid, start);
    event.payload.member_processes      = std::move(members);
    return event;
}

/// 以不完整空批对账：只推进状态，不清理、不补绑定、不重读
void finish_initialization(RoleManager& manager)
{
    hng::ProcessSeedBatch batch;
    batch.complete = false;
    manager.reconcile(batch);
}

// ============================================================
// RoleSourceBarrier
// ============================================================

void run_barrier_without_expect()
{
    RoleSourceBarrier barrier;
    CHECK(barrier.wait(std::chrono::milliseconds(50)),
          "未登记任何源时应立即就绪");
    CHECK(!barrier.timed_out(), "未登记任何源时不得记为超时");
}

void run_barrier_timeout()
{
    RoleSourceBarrier barrier;
    barrier.expect(RoleSource::SYSTEMD);
    barrier.expect(RoleSource::CONTAINERD);
    barrier.ready(RoleSource::SYSTEMD, true);

    CHECK(!barrier.wait(std::chrono::milliseconds(20)), "尚有源未上报时不得就绪");
    CHECK(barrier.timed_out(), "未全部上报应记为超时");
}

void run_barrier_all_ready()
{
    RoleSourceBarrier barrier;
    barrier.expect(RoleSource::SYSTEMD);
    barrier.expect(RoleSource::CONTAINERD);
    barrier.ready(RoleSource::SYSTEMD, true);
    barrier.ready(RoleSource::CONTAINERD, true);
    CHECK(barrier.wait(std::chrono::milliseconds(20)), "全部源上报可用时应就绪");
    CHECK(!barrier.timed_out(), "全部上报不得记为超时");

    // 未登记源的上报被忽略
    barrier.ready(RoleSource::UNSPECIFIED, false);
    CHECK(barrier.wait(std::chrono::milliseconds(20)), "未登记源的上报应被忽略");

    // 重复上报以最后一次为准
    barrier.ready(RoleSource::CONTAINERD, false);
    CHECK(!barrier.wait(std::chrono::milliseconds(20)),
          "最后一次上报不可用时不得就绪");
    barrier.ready(RoleSource::CONTAINERD, true);
    CHECK(barrier.wait(std::chrono::milliseconds(20)), "改回可用后应就绪");
}

void run_barrier_unavailable()
{
    RoleSourceBarrier barrier;
    barrier.expect(RoleSource::CONTAINERD);
    barrier.ready(RoleSource::CONTAINERD, false);
    CHECK(!barrier.wait(std::chrono::milliseconds(50)), "有源不可用时应不就绪");
    CHECK(!barrier.timed_out(), "不可用由 ready() 给出，不是超时");
}

// ============================================================
// drain 与状态机
// ============================================================

void run_drain_before_run()
{
    RecordingSink sink;
    RoleManager manager;
    manager.add_lifecycle_sink(&sink);

    manager.on_role_event(mk_join("a", 100, 1000, {proc(101, 1001)}));
    manager.bind_to_role(proc(102, 1002), proc(100, 1000));
    manager.on_process_exited(proc(101, 1001));
    manager.drain();

    CHECK(manager.state() == hng::ComponentState::CONSTRUCTED,
          "drain 不应改变状态");
    const uint32_t role = manager.lookup(proc(100, 1000)).value_or(0);
    CHECK(role != 0, "JOIN 应在 drain 中落地");
    CHECK(manager.lookup(proc(102, 1002)).value_or(0) == role,
          "BIND 应在 drain 中落地");
    CHECK(!manager.lookup(proc(101, 1001)).has_value(), "EXIT 应在 drain 中落地");

    std::vector<RecordingSink::Call> calls = sink.calls();
    CHECK(calls.size() == 3, "drain 期间的通知应直达出口");
    CHECK(calls[0].kind == RecordingSink::Kind::JOINED && calls[0].roleID == role,
          "第一条应为加入");

    // drain 之后新到的事件留给 run()
    manager.on_role_event(mk_join("b", 200, 2000));
    finish_initialization(manager);
    std::thread consumer([&manager] { manager.run(); });
    CHECK(wait_until(
              [&] { return manager.state() == hng::ComponentState::RUNNING; }),
          "对账后 run() 应进入 RUNNING");
    CHECK(wait_until([&] { return manager.lookup(proc(200, 2000)).has_value(); }),
          "drain 之后入队的事件应由 run() 消费");
    manager.stop();
    consumer.join();
}

void run_state_machine()
{
    RecordingSink sink;
    RoleManager manager;
    manager.add_lifecycle_sink(&sink);
    CHECK(manager.state() == hng::ComponentState::CONSTRUCTED,
          "初始状态应为 CONSTRUCTED");

    manager.run();
    CHECK(manager.state() == hng::ComponentState::CONSTRUCTED,
          "未 reconcile 的 run 应立即返回且不改状态");

    hng::ProcessSeedBatch empty;
    empty.complete                  = false;
    const RoleReconcileReport first = manager.reconcile(empty);
    CHECK(first.rejected_state == 0, "首次 reconcile 不得被拒");
    CHECK(!first.snapshot_complete, "报告应反映批次不完整");
    CHECK(manager.state() == hng::ComponentState::READY,
          "reconcile 后应为 READY");

    const RoleReconcileReport second = manager.reconcile(empty);
    CHECK(second.rejected_state == 1, "重复 reconcile 应被拒并计数");
    CHECK(manager.state() == hng::ComponentState::READY,
          "被拒的 reconcile 不改状态");

    CHECK(!manager.barrier(std::chrono::milliseconds(10)),
          "READY 但未 RUNNING 时 barrier 应返回 false");

    std::thread consumer([&manager] { manager.run(); });
    CHECK(wait_until(
              [&] { return manager.state() == hng::ComponentState::RUNNING; }),
          "READY 后 run 应进入 RUNNING");

    manager.on_role_event(mk_join("late", 300, 3000));
    CHECK(manager.barrier(std::chrono::seconds(5)), "RUNNING 后 barrier 应完成");
    CHECK(manager.lookup(proc(300, 3000)).has_value(),
          "barrier 返回时此前入队的事件应已落地");

    manager.stop();
    CHECK(!manager.barrier(std::chrono::milliseconds(10)),
          "停止后的入队应被拒，barrier 返回 false");
    consumer.join();
    CHECK(manager.state() == hng::ComponentState::STOPPED,
          "run() 返回后应为 STOPPED");

    const RoleReconcileReport after_stop = manager.reconcile(empty);
    CHECK(after_stop.rejected_state == 1, "stop 后的 reconcile 应被拒");
    CHECK(!manager.barrier(std::chrono::milliseconds(10)),
          "非 RUNNING 时 barrier 应返回 false");
}

void run_barrier_timeout_while_busy()
{
    BlockingSink sink;
    RoleManager manager;
    manager.add_lifecycle_sink(&sink);
    manager.drain();
    finish_initialization(manager);

    std::thread consumer([&manager] { manager.run(); });
    CHECK(wait_until(
              [&] { return manager.state() == hng::ComponentState::RUNNING; }),
          "消费线程应进入 RUNNING");

    manager.on_role_event(mk_join("a", 100, 1000));
    CHECK(sink.wait_entered(), "加入通知应在出口内阻塞");
    CHECK(!manager.barrier(std::chrono::milliseconds(20)),
          "消费线程被占住时 barrier 应超时");
    sink.release();

    manager.stop();
    consumer.join();
}

// ============================================================
// 幽灵清理
// ============================================================

void run_ghost_pruning()
{
    // 快照完整：不在批内且 /proc 说已退出 → 清理
    {
        bool dead = false;  // 加入时仍存活，对账时才由 /proc 判为退出
        RoleManagerProbe probe;
        probe.is_exited = [&dead](hng::Process p) {
            return dead && p.pid == 101;
        };
        RoleManager manager(probe);
        manager.on_role_event(
            mk_join("a", 100, 1000, {proc(101, 1001), proc(102, 1002)}));
        manager.drain();
        dead = true;

        hng::ProcessSeedBatch batch;
        batch.entries.push_back(seed_entry(100, 1000));
        const RoleReconcileReport report = manager.reconcile(batch);
        CHECK(report.ownership_entries == 3, "归属表应含锚点与两个成员");
        CHECK(report.pruned == 1, "已退出且不在快照的成员应被清理");
        CHECK(report.proc_unknown == 0, "有存活结论时不应计未知");
        CHECK(!manager.lookup(proc(101, 1001)).has_value(), "幽灵成员应删除");
        CHECK(manager.lookup(proc(102, 1002)).has_value(), "仍存活的成员应保留");
        CHECK(manager.lookup(proc(100, 1000)).has_value(), "快照内的锚点应保留");
    }

    // 快照完整：不在批内但 /proc 说仍存活 → 保留
    {
        RoleManagerProbe probe;
        probe.is_exited = [](hng::Process) { return false; };
        RoleManager manager(probe);
        manager.on_role_event(mk_join("a", 100, 1000, {proc(101, 1001)}));
        manager.drain();

        hng::ProcessSeedBatch batch;
        batch.entries.push_back(seed_entry(100, 1000));
        const RoleReconcileReport report = manager.reconcile(batch);
        CHECK(report.pruned == 0 && report.proc_unknown == 0, "存活成员不得清理");
        CHECK(manager.lookup(proc(101, 1001)).has_value(),
              "快照后仍存活的成员应保留");
    }

    // 未注入存活视图：无结论，按 UNKNOWN 保留
    {
        RoleManager manager;
        manager.on_role_event(mk_join("a", 100, 1000, {proc(101, 1001)}));
        manager.drain();

        hng::ProcessSeedBatch batch;
        batch.entries.push_back(seed_entry(100, 1000));
        const RoleReconcileReport report = manager.reconcile(batch);
        CHECK(report.proc_unknown == 1, "无存活结论的条目应计未知");
        CHECK(report.pruned == 0, "无结论时不得清理");
        CHECK(manager.lookup(proc(101, 1001)).has_value(), "无结论时应保留");
    }

    // 快照不完整：跳过幽灵清理
    {
        bool dead = false;
        RoleManagerProbe probe;
        probe.is_exited = [&dead](hng::Process) { return dead; };
        RoleManager manager(probe);
        manager.on_role_event(mk_join("a", 100, 1000, {proc(101, 1001)}));
        manager.drain();
        dead = true;

        hng::ProcessSeedBatch batch;
        batch.complete = false;
        batch.entries.push_back(seed_entry(100, 1000));
        const RoleReconcileReport report = manager.reconcile(batch);
        CHECK(report.pruned == 0 && report.proc_unknown == 0,
              "不完整快照应跳过幽灵清理");
        CHECK(manager.lookup(proc(101, 1001)).has_value(),
              "不完整快照不得删除归属");
    }
}

// ============================================================
// 补绑定
// ============================================================

void run_bind_adoption()
{
    // 批内逆序也能父先子后，并沿链传播
    {
        RecordingSink sink;
        RoleManager manager;
        manager.add_lifecycle_sink(&sink);
        manager.on_role_event(mk_join("a", 100, 1000));
        manager.drain();
        sink.clear();

        hng::ProcessSeedBatch batch;
        batch.entries.push_back(seed_entry(102, 1002, 101, 1001));
        batch.entries.push_back(seed_entry(101, 1001, 100, 1000));
        batch.entries.push_back(seed_entry(100, 1000));
        const RoleReconcileReport report = manager.reconcile(batch);

        const uint32_t role = manager.lookup(proc(100, 1000)).value_or(0);
        CHECK(role != 0, "锚点应已有归属");
        CHECK(report.bind_adopted == 2, "子与孙都应由初始化期补绑定继承");
        CHECK(report.bind_ignored == 0, "父都有归属时不得计忽略");
        CHECK(manager.lookup(proc(101, 1001)).value_or(0) == role &&
                  manager.lookup(proc(102, 1002)).value_or(0) == role,
              "继承应沿父子链传播");

        std::vector<RecordingSink::Call> calls = sink.calls();
        CHECK(calls.size() == 2, "每个新增成员应各通知一次");
        CHECK(calls[0].kind == RecordingSink::Kind::MEMBERS_ADDED &&
                  calls[0].roleID == role && calls[0].members.size() == 1 &&
                  calls[0].members[0] == proc(101, 1001),
              "先补绑定子进程");
        CHECK(calls[1].kind == RecordingSink::Kind::MEMBERS_ADDED &&
                  calls[1].members.size() == 1 &&
                  calls[1].members[0] == proc(102, 1002),
              "再补绑定孙进程");
        CHECK(manager.stats().bind_deferred == 0 &&
                  manager.stats().bind_resolved == 0 &&
                  manager.stats().bind_rejected == 0,
              "初始化期补绑定不得进入等待表");
    }

    // 父不在任何角色：忽略，不暂存
    {
        RoleManager manager;
        manager.drain();

        hng::ProcessSeedBatch batch;
        batch.entries.push_back(seed_entry(300, 3000));
        batch.entries.push_back(seed_entry(301, 3001, 300, 3000));
        const RoleReconcileReport report = manager.reconcile(batch);
        CHECK(report.bind_ignored == 1, "父无角色时应计忽略");
        CHECK(report.bind_adopted == 0, "父无角色时不得补绑定");
        CHECK(!manager.lookup(proc(301, 3001)).has_value(), "子进程不得有归属");
        CHECK(manager.stats().bind_deferred == 0,
              "初始化期不进入运行期 bind 等待表");
    }

    // 子已有归属：保留首条，不改写
    {
        RoleManager manager;
        manager.on_role_event(mk_join("a", 100, 1000));
        manager.on_role_event(mk_join("b", 200, 2000, {proc(201, 2001)}));
        manager.drain();

        hng::ProcessSeedBatch batch;
        batch.entries.push_back(seed_entry(201, 2001, 100, 1000));
        batch.entries.push_back(seed_entry(100, 1000));
        batch.entries.push_back(seed_entry(200, 2000));
        const RoleReconcileReport report = manager.reconcile(batch);

        const uint32_t role_a = manager.lookup(proc(100, 1000)).value_or(0);
        const uint32_t role_b = manager.lookup(proc(200, 2000)).value_or(0);
        CHECK(role_a != 0 && role_b != 0 && role_a != role_b,
              "两个角色应各自建立");
        CHECK(report.bind_adopted == 0 && report.bind_ignored == 0,
              "已有归属的子进程不改写也不计忽略");
        CHECK(manager.lookup(proc(201, 2001)).value_or(0) == role_b,
              "子进程应保留原角色的归属");
    }
}

// ============================================================
// cgroup 重读
// ============================================================

void run_cgroup_resync()
{
    // 空结果：保留原成员并计数
    {
        std::vector<hng::Process> reread;
        RoleManagerProbe probe;
        probe.read_members = [&reread](const std::string&) { return reread; };
        RecordingSink sink;
        RoleManager manager(probe);
        manager.add_lifecycle_sink(&sink);

        RoleEvent join           = mk_join("a", 100, 1000, {proc(101, 1001)});
        join.payload.cgroup_path = "/cg/a";
        manager.on_role_event(join);
        manager.on_role_event(mk_join("b", 200, 2000));  // cgroup 路径为空
        manager.drain();
        sink.clear();
        const uint32_t role_a = manager.lookup(proc(100, 1000)).value_or(0);

        hng::ProcessSeedBatch batch;
        batch.complete                   = false;
        const RoleReconcileReport report = manager.reconcile(batch);
        CHECK(report.roles_resynced == 1, "只有非空 cgroup 路径的角色才重读");
        CHECK(report.cgroup_read_empty == 1,
              "只有非空 cgroup 路径的空结果才计数");
        CHECK(manager.lookup(proc(101, 1001)).value_or(0) == role_a,
              "空结果应保留原成员");
        CHECK(sink.calls().empty(), "空结果不产生成员通知");
    }

    // 非空结果：adopt 并通知
    {
        std::vector<hng::Process> reread;
        bool serve = false;
        RoleManagerProbe probe;
        probe.read_members = [&reread, &serve](const std::string&) {
            return serve ? reread : std::vector<hng::Process>{};
        };
        RecordingSink sink;
        RoleManager manager(probe);
        manager.add_lifecycle_sink(&sink);

        RoleEvent join           = mk_join("a", 100, 1000);
        join.payload.cgroup_path = "/cg/a";
        manager.on_role_event(join);
        manager.drain();
        sink.clear();
        const uint32_t role = manager.lookup(proc(100, 1000)).value_or(0);

        serve               = true;
        reread              = {proc(102, 1002), proc(103, 1003)};
        hng::ProcessSeedBatch batch;
        batch.complete                   = false;
        const RoleReconcileReport report = manager.reconcile(batch);

        CHECK(report.cgroup_read_empty == 0, "重读到成员时不得计空读");
        CHECK(report.roles_resynced == 1, "应重读该角色");
        CHECK(manager.lookup(proc(102, 1002)).value_or(0) == role &&
                  manager.lookup(proc(103, 1003)).value_or(0) == role,
              "重读成员应被 adopt");

        std::vector<RecordingSink::Call> calls = sink.calls();
        CHECK(calls.size() == 1 &&
                  calls[0].kind == RecordingSink::Kind::MEMBERS_ADDED &&
                  calls[0].roleID == role && calls[0].members.size() == 2,
              "重读新增成员应通知一次");
        CHECK(manager.stats().bind_deferred == 0 &&
                  manager.stats().bind_resolved == 0 &&
                  manager.stats().bind_ignored == 0,
              "对账不得产生等待项");
    }
}

}  // namespace

int main()
{
    run_barrier_without_expect();
    run_barrier_timeout();
    run_barrier_all_ready();
    run_barrier_unavailable();
    run_drain_before_run();
    run_state_machine();
    run_barrier_timeout_while_busy();
    run_ghost_pruning();
    run_bind_adoption();
    run_cgroup_resync();

    if (g_fail) {
        std::fprintf(stderr, "TOTAL FAILURES: %d\n", g_fail);
        return 1;
    }
    std::printf("ALL PASS\n");
    return 0;
}
