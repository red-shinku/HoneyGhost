/**
 * @file test_role_manager.cc
 * @brief 角色管理器的单元测试
 * @details
 * 覆盖 RoleManager（队列为占位实现，不含队列选型）：
 *  - 三类事件经队列落地：加入、退出、锚点更换，出口恰好一次；
 *  - 出口回调内反查：加入必命中、退出必失配；
 *  - 加入时重读补上「枚举 → 落地」窗口的 fork，锚点无条件并入，退出不重读；
 *  - bind_to_role 与 on_process_exited 经同一条队列落地，不产通知；
 *  - bind 先于 JOIN 时暂存、JOIN 后应用；父已归属时直接应用；
 *  - 锚点未变的周期 JOIN 补写成员并产生成员新增通知，不产生生命周期通知；
 *  - 存活过滤：死锚点整条拒绝、死成员不进表、LEAVE 不过滤；
 *  - 等待表容量与 TTL 降级；
 *  - members()：按记录的 cgroup 路径实时重枚举、角色不存在为空、
 *    路径不可读时返回已收集结果且不改动任何表；
 *  - 入口幂等重放与未知实例键不产通知；
 *  - 多个下行出口：都恰好收到、按注册顺序、空指针忽略、重复注册即重复通知；
 *  - stop() 幂等、run() 之前 stop() 时 run() 立即返回、已入队的事件仍被落地、
 *    停止后的入队被拒并计数；
 *  - 多生产者并发推送后表状态自洽（并发用例供 TSAN 构建复验）。
 * @author red_shinku
 * @date 2026.9.17
 */

#include "agent/control_plane/src/role_manager.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <future>
#include <mutex>
#include <optional>
#include <string>
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

using hng::role::RoleAction;
using hng::role::RoleEvent;
using hng::role::RoleSource;

/// 不存在的 cgroup 路径：交给真实读取器时读不到任何进程
constexpr const char* kDeadCgroup = "/nonexistent-hng/cgroup";

/// 记录型出口：记录回调序列，并可在回调内反查
class RecordingSink : public RoleLifecycleSink {
   public:
    enum class Kind { JOINED, LEFT, MP_CHANGED, MEMBERS_ADDED };

    struct Call {
        Kind kind;
        uint32_t roleID;
        hng::role_label_t roleLabel;
        std::vector<hng::Process> members;  ///< 仅 MEMBERS_ADDED 非空
        bool probe_hit;                     ///< 回调内反查的结果
    };

    /// 回调内执行的反查；留空则 probe_hit 恒为 true
    std::function<bool(uint32_t role_id)> probe;

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

    /// 等到已收到 n 次回调；超时返回 false
    bool wait_calls(std::size_t n)
    {
        std::unique_lock lock(mutex_);
        return cv_.wait_for(lock, std::chrono::seconds(5),
                            [&] { return calls_.size() >= n; });
    }

    std::vector<Call> calls()
    {
        std::lock_guard lock(mutex_);
        return calls_;
    }

   private:
    void add(Kind kind, const hng::Role& role,
             const std::vector<hng::Process>& members = {})
    {
        // 反查在回调内、sink 锁外执行，与被测组件不构成嵌套加锁
        const bool hit = probe ? probe(role.roleID) : true;
        {
            std::lock_guard lock(mutex_);
            calls_.push_back(
                Call{kind, role.roleID, role.roleLabel, members, hit});
        }
        cv_.notify_all();
    }

    std::mutex mutex_;
    std::condition_variable cv_;
    std::vector<Call> calls_;
};

/// 起 run() 线程，析构时停止并 join
class Runner {
   public:
    explicit Runner(RoleManager& manager)
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
    RoleManager& manager_;
    std::thread thread_;
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

/// 可控时钟：主线程推进、消费线程读取，故用原子量
struct FakeClock {
    std::atomic<int64_t> ticks{0};

    hng::RelationTimePoint now() const
    {
        return hng::RelationTimePoint(std::chrono::nanoseconds(ticks.load()));
    }

    void advance(std::chrono::milliseconds delta)
    {
        ticks.fetch_add(delta.count() * 1'000'000);
    }
};

RoleEvent mk_join(const std::string& key, uint32_t pid, uint64_t start,
                  std::vector<hng::Process> members = {})
{
    RoleEvent event;
    event.action                            = RoleAction::JOIN;
    event.payload.identity.instance_key     = key;
    event.payload.identity.type_key         = "nginx";
    event.payload.identity.attributes["ns"] = "hng";
    event.payload.identity.source           = RoleSource::SYSTEMD;
    event.payload.main_process              = proc(pid, start);
    event.payload.cgroup_path               = kDeadCgroup;
    event.payload.member_processes          = std::move(members);
    return event;
}

RoleEvent mk_other(RoleAction action, const std::string& key, uint32_t pid,
                   uint64_t start)
{
    RoleEvent event;
    event.action                        = action;
    event.payload.identity.instance_key = key;
    event.payload.identity.type_key     = "nginx";
    event.payload.identity.source       = RoleSource::SYSTEMD;
    event.payload.main_process          = proc(pid, start);
    event.payload.cgroup_path           = kDeadCgroup;
    return event;
}

void run_join()
{
    RecordingSink sink;
    RoleManager manager;
    manager.add_lifecycle_sink(&sink);
    Runner runner(manager);

    sink.probe = [&](uint32_t role_id) {
        return manager.lookup(proc(100, 1000)).value_or(0) == role_id;
    };
    manager.on_role_event(mk_join("a", 100, 1000, {proc(101, 1001)}));
    CHECK(sink.wait_calls(2), "加入与成员新增应各通知一次");

    std::vector<RecordingSink::Call> calls = sink.calls();
    CHECK(calls.size() == 2 && calls[0].kind == RecordingSink::Kind::JOINED,
          "加入应恰好通知一次 JOINED");
    CHECK(calls[0].roleID == 1, "roleID 应自 1 起");
    CHECK(calls[0].roleLabel == "a", "出口应携带 systemd 的 unit 名");
    CHECK(calls[0].probe_hit, "出口回调内反查应命中");
    CHECK(calls[1].kind == RecordingSink::Kind::MEMBERS_ADDED &&
              calls[1].roleID == 1 && calls[1].members.size() == 2,
          "加入落地应附带一次成员新增通知：锚点与载荷成员");

    const uint32_t role = calls[0].roleID;
    CHECK(manager.lookup(proc(100, 1000)).value_or(0) == role, "锚点应归属");
    CHECK(manager.lookup(proc(101, 1001)).value_or(0) == role, "载荷成员应归属");
    std::optional<hng::Role> view = manager.role(role);
    CHECK(view.has_value() && view->roleLabel == "a",
          "roleLabel 应取 unit 名（实例键）");
    std::optional<hng::role::RoleIdentity> identity = manager.identity(role);
    CHECK(identity.has_value() && identity->instance_key == "a" &&
              identity->attributes.at("ns") == "hng",
          "身份应原样保留");
}

void run_roles()
{
    RecordingSink sink;
    RoleManager manager;
    manager.add_lifecycle_sink(&sink);
    Runner runner(manager);

    CHECK(manager.roles().empty(), "无角色时应为空");

    manager.on_role_event(mk_join("a", 100, 1000));
    manager.on_role_event(mk_join("b", 200, 2000));
    CHECK(sink.wait_calls(4), "两个加入都应通知");

    std::vector<hng::Role> all = manager.roles();
    CHECK(all.size() == 2 && all[0].roleID == 1 && all[0].roleLabel == "a" &&
              all[1].roleID == 2 && all[1].roleLabel == "b",
          "roles 应按 roleID 升序转发全部角色");

    manager.on_role_event(mk_other(RoleAction::LEAVE, "a", 0, 0));
    CHECK(sink.wait_calls(5), "退出应通知");
    all = manager.roles();
    CHECK(all.size() == 1 && all[0].roleID == 2, "退出后不应含该角色");
}

void run_supervision()
{
    RecordingSink sink;
    RoleManager manager;
    manager.add_lifecycle_sink(&sink);
    Runner runner(manager);

    CHECK(manager.supervised_roles().empty(), "未登记时应为空");

    manager.on_role_event(mk_join("a", 100, 1000));
    CHECK(sink.wait_calls(2), "加入应通知");
    const uint32_t role = sink.calls()[0].roleID;

    manager.set_supervised(role + 100, true);
    CHECK(manager.supervised_roles().empty(), "未知 roleID 应忽略");

    manager.set_supervised(role, true);
    std::vector<hng::Role> supervised = manager.supervised_roles();
    CHECK(supervised.size() == 1 && supervised[0].roleID == role &&
              supervised[0].roleLabel == "a",
          "应返回已登记角色");

    manager.on_role_event(mk_other(RoleAction::LEAVE, "a", 0, 0));
    CHECK(sink.wait_calls(3), "退出应通知");
    CHECK(manager.supervised_roles().empty(), "退出后应自动移除登记");
}

void run_main_process()
{
    RecordingSink sink;
    RoleManager manager;
    manager.add_lifecycle_sink(&sink);
    Runner runner(manager);

    CHECK(!manager.main_process(1).has_value(), "未知 roleID 应返回空");

    manager.on_role_event(mk_join("a", 100, 1000));
    CHECK(sink.wait_calls(2), "加入应通知");
    const uint32_t role              = sink.calls()[0].roleID;

    std::optional<hng::Process> main = manager.main_process(role);
    CHECK(main.has_value() && *main == proc(100, 1000), "应转发锚点");

    manager.on_process_exited(proc(100, 1000));
    manager.on_role_event(mk_join("barrier", 900, 9000));
    CHECK(sink.wait_calls(3), "屏障事件应通知");
    CHECK(!manager.main_process(role).has_value(), "锚点删除后应返回空");
}

void run_leave()
{
    RecordingSink sink;
    RoleManager manager;
    manager.add_lifecycle_sink(&sink);
    Runner runner(manager);

    manager.on_role_event(mk_join("a", 100, 1000, {proc(101, 1001)}));
    CHECK(sink.wait_calls(2), "加入应通知一次");
    const uint32_t role = sink.calls()[0].roleID;

    // 回调内反查：此刻起该 roleID 与它的进程条目都应已失配
    sink.probe          = [&](uint32_t role_id) {
        return !manager.lookup(proc(100, 1000)).has_value() &&
               !manager.lookup(proc(101, 1001)).has_value() &&
               !manager.role(role_id).has_value();
    };
    manager.on_role_event(mk_other(RoleAction::LEAVE, "a", 0, 0));
    CHECK(sink.wait_calls(3), "退出应通知一次");

    std::vector<RecordingSink::Call> calls = sink.calls();
    CHECK(calls[2].kind == RecordingSink::Kind::LEFT && calls[2].roleID == role,
          "退出应通知同一个 roleID");
    CHECK(calls[2].probe_hit, "退出回调内反查应失配");
    CHECK(!manager.lookup(proc(100, 1000)).has_value(), "退出后锚点应失配");
    CHECK(!manager.lookup(proc(101, 1001)).has_value(), "退出后成员应失配");
    CHECK(!manager.role(role).has_value() && !manager.identity(role).has_value(),
          "退出后角色视图与身份应一并失配");

    // 未知实例键的退出：不产通知
    manager.on_role_event(mk_other(RoleAction::LEAVE, "zz", 0, 0));
    manager.on_role_event(mk_join("b", 200, 2000, {}));
    CHECK(sink.wait_calls(5), "屏障事件应通知");
    CHECK(sink.calls().size() == 5, "未知实例键的退出不得产通知");
    CHECK(manager.stats().store.unknown_instance == 1, "未知实例键应计数");
}

void run_join_reread()
{
    RecordingSink sink;
    std::string seen_path;
    RoleManagerProbe probe;
    probe.read_members = [&](const std::string& path) {
        seen_path = path;
        // 枚举之后才 fork 出来的 worker：只有重读能看见
        return std::vector<hng::Process>{proc(202, 2002)};
    };
    RoleManager manager(probe);
    manager.add_lifecycle_sink(&sink);
    Runner runner(manager);

    RoleEvent event           = mk_join("a", 100, 1000, {proc(101, 1001)});
    event.payload.cgroup_path = "/sys/fs/cgroup/system.slice/a.service";
    manager.on_role_event(event);
    CHECK(sink.wait_calls(2), "加入应通知一次");

    CHECK(seen_path == "/sys/fs/cgroup/system.slice/a.service",
          "重读应使用载荷的 cgroup 路径");
    CHECK(manager.lookup(proc(202, 2002)).has_value(), "重读结果应被归属");
    CHECK(manager.lookup(proc(101, 1001)).has_value(), "载荷成员应被归属");
    CHECK(manager.lookup(proc(100, 1000)).has_value(), "锚点应被归属");
}

void run_anchor_transitions()
{
    RecordingSink sink;
    RoleManager manager;
    manager.add_lifecycle_sink(&sink);
    Runner runner(manager);

    manager.on_role_event(mk_join("a", 100, 1000, {}));
    CHECK(sink.wait_calls(2), "加入应通知一次");
    const uint32_t role = sink.calls()[0].roleID;

    // 锚点更换的回调内反查：角色记录在、新锚点已归属
    sink.probe          = [&](uint32_t role_id) {
        return manager.lookup(proc(200, 2000)).value_or(0) == role_id &&
               manager.role(role_id).has_value();
    };

    // 同实例键同锚点的重放，以及与 MAIN_PROCESS_CHANGE 同路的锚点更换
    manager.on_role_event(mk_join("a", 100, 1000, {}));
    manager.on_role_event(
        mk_other(RoleAction::MAIN_PROCESS_CHANGE, "a", 200, 2000));
    CHECK(sink.wait_calls(4), "锚点更换应通知");
    manager.on_role_event(mk_join("a", 300, 3000, {}));
    CHECK(sink.wait_calls(6), "异锚点的加入应归一为锚点更换");

    std::vector<RecordingSink::Call> calls = sink.calls();
    CHECK(calls.size() == 6, "幂等重放不得产生命周期通知");
    const RecordingSink::Kind expected[] = {
        RecordingSink::Kind::JOINED,     RecordingSink::Kind::MEMBERS_ADDED,
        RecordingSink::Kind::MP_CHANGED, RecordingSink::Kind::MEMBERS_ADDED,
        RecordingSink::Kind::MP_CHANGED, RecordingSink::Kind::MEMBERS_ADDED};
    for (std::size_t i = 0; i < calls.size(); ++i) {
        CHECK(calls[i].kind == expected[i] && calls[i].roleID == role,
              "锚点更换应通知同一个 roleID，且成员通知紧跟其生命周期通知");
        if (i > 0) CHECK(calls[i].probe_hit, "回调内反查应命中");
    }
    CHECK(manager.lookup(proc(300, 3000)).value_or(0) == role, "新锚点应归属");
}

void run_bind_and_removed()
{
    RecordingSink sink;
    RoleManager manager;
    manager.add_lifecycle_sink(&sink);
    Runner runner(manager);

    // 父未归属：bind 先暂存，父 JOIN 后子应被 adopt
    manager.bind_to_role(proc(101, 1001), proc(100, 1000));
    manager.on_role_event(mk_join("a", 100, 1000, {}));
    CHECK(sink.wait_calls(2), "加入应通知一次");
    const uint32_t role = sink.calls()[0].roleID;
    CHECK(manager.lookup(proc(101, 1001)).value_or(0) == role,
          "父 JOIN 后暂存的 bind 应被应用");
    CHECK(manager.stats().bind_deferred == 1, "暂存应计数");
    CHECK(manager.stats().bind_resolved == 1, "应用暂存应计数");

    // 父已归属：继承；进程退出后条目清掉
    manager.bind_to_role(proc(102, 1002), proc(100, 1000));
    manager.on_process_exited(proc(102, 1002));
    manager.on_process_exited(proc(100, 1000));
    manager.on_role_event(mk_join("b", 400, 4000, {}));
    CHECK(sink.wait_calls(5), "屏障事件应通知");

    // a：JOINED + 锚点与暂存子进程的成员通知 + 直接 bind 的成员通知；
    // b：JOINED + 锚点的成员通知。退出入口不产通知。
    std::vector<RecordingSink::Call> calls = sink.calls();
    CHECK(calls.size() == 5, "退出不得产通知，bind 应产成员通知");
    CHECK(calls[2].kind == RecordingSink::Kind::MEMBERS_ADDED &&
              calls[2].roleID == role && calls[2].members.size() == 1 &&
              calls[2].members[0] == proc(102, 1002),
          "父已归属的 bind 应立即通知新增成员");
    CHECK(!manager.lookup(proc(102, 1002)).has_value(), "删除后应无残留");
    CHECK(!manager.lookup(proc(100, 1000)).has_value(), "锚点的归属应被删");
    CHECK(manager.role(role).has_value(), "锚点退出不改变角色存在性");
    CHECK(manager.stats().store.anchors_removed == 1, "锚点已删应计入 gauge");
}

void run_members()
{
    RecordingSink sink;
    std::string seen_path;
    RoleManagerProbe probe;
    probe.read_members = [&](const std::string& path) {
        seen_path = path;
        return std::vector<hng::Process>{proc(900, 9000)};
    };
    RoleManager manager(probe);
    manager.add_lifecycle_sink(&sink);
    Runner runner(manager);

    RoleEvent event           = mk_join("a", 100, 1000, {});
    event.payload.cgroup_path = "/sys/fs/cgroup/system.slice/a.service";
    manager.on_role_event(event);
    CHECK(sink.wait_calls(2), "加入应通知一次");
    const uint32_t role               = sink.calls()[0].roleID;

    std::vector<hng::Process> members = manager.members(role);
    CHECK(seen_path == "/sys/fs/cgroup/system.slice/a.service",
          "members 应使用记录里的 cgroup 路径");
    CHECK(members.size() == 1 && members[0].pid == 900,
          "members 应原样返回重枚举结果");
    CHECK(manager.members(role + 1).empty(), "未知 roleID 应返回空");

    // 不注入 probe：真实读取器读不存在的路径，只返回已收集结果
    RecordingSink dead_sink;
    RoleManager dead_manager;
    dead_manager.add_lifecycle_sink(&dead_sink);
    Runner dead_runner(dead_manager);

    dead_manager.on_role_event(mk_join("m", 500, 5000, {proc(501, 5001)}));
    CHECK(dead_sink.wait_calls(2), "加入应通知一次");
    const uint32_t dead_role = dead_sink.calls()[0].roleID;

    CHECK(dead_manager.members(dead_role).empty(), "不可读路径应返回已收集结果");
    CHECK(dead_manager.lookup(proc(500, 5000)).value_or(0) == dead_role &&
              dead_manager.lookup(proc(501, 5001)).has_value(),
          "读失败不得改动任何表");
    CHECK(dead_manager.stats().cgroup_read_empty == 1,
          "重读未返回任何进程应计数");

    // cgroup 路径为空：不重读、不计数
    RoleEvent no_cgroup = mk_join("n", 600, 6000, {});
    no_cgroup.payload.cgroup_path.clear();
    dead_manager.on_role_event(no_cgroup);
    CHECK(dead_sink.wait_calls(4), "加入应通知一次");
    CHECK(dead_manager.stats().cgroup_read_empty == 1,
          "cgroup 路径为空时不应计数");
}

void run_multiple_sinks()
{
    RecordingSink first;
    RecordingSink second;

    // 借 probe 记录到达顺序：它在各自回调内执行
    std::vector<std::string> order;
    std::mutex order_mutex;
    auto note = [&](const char* tag) {
        return [&order, &order_mutex, tag](uint32_t) {
            std::lock_guard lock(order_mutex);
            order.push_back(tag);
            return true;
        };
    };
    first.probe  = note("first");
    second.probe = note("second");

    RoleManager manager;
    manager.add_lifecycle_sink(&first);
    manager.add_lifecycle_sink(nullptr);  // 空指针忽略
    manager.add_lifecycle_sink(&second);
    Runner runner(manager);

    manager.on_role_event(mk_join("a", 100, 1000, {}));
    manager.on_role_event(
        mk_other(RoleAction::MAIN_PROCESS_CHANGE, "a", 200, 2000));
    manager.on_role_event(mk_other(RoleAction::LEAVE, "a", 0, 0));
    CHECK(second.wait_calls(5), "两个出口都应收到五次通知");

    std::vector<RecordingSink::Call> a = first.calls();
    std::vector<RecordingSink::Call> b = second.calls();
    CHECK(a.size() == 5 && b.size() == 5, "每个出口应恰好收到五次通知");
    for (std::size_t i = 0; i < a.size() && i < b.size(); ++i) {
        CHECK(a[i].kind == b[i].kind && a[i].roleID == b[i].roleID,
              "两个出口收到的通知应一致");
    }
    CHECK(a[0].kind == RecordingSink::Kind::JOINED &&
              a[1].kind == RecordingSink::Kind::MEMBERS_ADDED &&
              a[2].kind == RecordingSink::Kind::MP_CHANGED &&
              a[3].kind == RecordingSink::Kind::MEMBERS_ADDED &&
              a[4].kind == RecordingSink::Kind::LEFT,
          "通知顺序应为加入 → 成员新增 → 锚点更换 → 成员新增 → 退出");

    const std::vector<std::string> expected{"first", "second", "first", "second",
                                            "first", "second", "first", "second",
                                            "first", "second"};
    std::lock_guard lock(order_mutex);
    CHECK(order == expected, "同一次跃迁应按注册顺序通知到每个出口");

    // 同一实现重复注册：同一跃迁收到重复通知
    RecordingSink twice;
    RoleManager duplicated;
    duplicated.add_lifecycle_sink(&twice);
    duplicated.add_lifecycle_sink(&twice);
    Runner duplicated_runner(duplicated);
    duplicated.on_role_event(mk_join("d", 700, 7000, {}));
    CHECK(twice.wait_calls(4), "同一实现重复注册应收到重复通知");
    std::vector<RecordingSink::Call> repeated = twice.calls();
    CHECK(repeated.size() == 4 &&
              repeated[0].kind == RecordingSink::Kind::JOINED &&
              repeated[1].kind == RecordingSink::Kind::JOINED &&
              repeated[2].kind == RecordingSink::Kind::MEMBERS_ADDED &&
              repeated[3].kind == RecordingSink::Kind::MEMBERS_ADDED,
          "重复注册应按注册顺序收到两份生命周期与成员通知");
}

void run_stop_semantics()
{
    // run() 之前 stop()：run() 立即返回
    {
        RoleManager manager;
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

    // 已入队的事件在 stop() 之后仍被落地
    {
        RecordingSink sink;
        RoleManager manager;
        manager.add_lifecycle_sink(&sink);
        manager.on_role_event(mk_join("a", 100, 1000, {}));
        manager.stop();
        manager.run();
        CHECK(sink.calls().size() == 2, "stop() 之后已入队的事件应被落地");
    }

    // stop() 之后的三类入队都被拒并计数，且不进入落地
    {
        RoleManager manager;
        manager.stop();
        manager.on_role_event(mk_join("a", 100, 1000, {}));
        manager.bind_to_role(proc(1, 1), proc(2, 2));
        manager.on_process_exited(proc(3, 3));
        CHECK(manager.stats().queue_rejected == 3,
              "停止后三类入队都应被拒并计数");

        manager.run();  // 队列为空，应直接返回
        CHECK(manager.stats().store.rejected == 0 &&
                  manager.stats().store.unknown_instance == 0,
              "被拒的事件不得进入落地");
    }
}

void run_concurrent_producers()
{
    RecordingSink sink;
    RoleManager manager;
    manager.add_lifecycle_sink(&sink);
    Runner runner(manager);

    constexpr int kThreads = 4;
    constexpr int kRoles   = 50;
    constexpr int kTotal   = kThreads * kRoles;

    std::vector<std::thread> producers;
    for (int t = 0; t < kThreads; ++t) {
        producers.emplace_back([&manager, t] {
            for (int i = 0; i < kRoles; ++i) {
                const uint32_t pid = 1000 + static_cast<uint32_t>(t) * 100 +
                                     static_cast<uint32_t>(i);
                const std::string key =
                    "r" + std::to_string(t) + "-" + std::to_string(i);
                manager.on_role_event(mk_join(key, pid, pid * 10));
                manager.bind_to_role(proc(pid + 1, pid * 10 + 1),
                                     proc(pid, pid * 10));
                manager.on_process_exited(proc(pid + 2, pid * 10 + 2));
            }
        });
    }
    for (std::thread& producer : producers) {
        producer.join();
    }

    CHECK(sink.wait_calls(kTotal * 3), "全部加入与成员新增应通知完");
    CHECK(sink.calls().size() == static_cast<std::size_t>(kTotal) * 3,
          "每个角色应恰好通知三次：加入、锚点新增、fork 继承新增");
    std::size_t joined = 0;
    std::size_t added  = 0;
    for (const RecordingSink::Call& call : sink.calls()) {
        if (call.kind == RecordingSink::Kind::JOINED) {
            ++joined;
        }
        else if (call.kind == RecordingSink::Kind::MEMBERS_ADDED) {
            CHECK(call.members.size() == 1, "每次成员通知应恰好一个进程");
            ++added;
        }
    }
    CHECK(joined == static_cast<std::size_t>(kTotal) &&
              added == static_cast<std::size_t>(kTotal) * 2,
          "加入通知与成员通知的次数应分别为角色数与两倍角色数");

    for (int t = 0; t < kThreads; ++t) {
        for (int i = 0; i < kRoles; ++i) {
            const uint32_t pid =
                1000 + static_cast<uint32_t>(t) * 100 + static_cast<uint32_t>(i);
            std::optional<uint32_t> role = manager.lookup(proc(pid, pid * 10));
            CHECK(role.has_value(), "并发推送后每个锚点都应有归属");
            CHECK(manager.identity(role.value_or(0)).has_value(),
                  "归属应能解析到角色记录");
        }
    }
    CHECK(manager.stats().store.unknown_instance == 0, "不得出现未知实例键");
    CHECK(manager.stats().store.owner_conflict == 0, "各角色的成员集不相交");
}

void run_bind_after_join()
{
    RecordingSink sink;
    RoleManager manager;
    manager.add_lifecycle_sink(&sink);
    Runner runner(manager);

    manager.on_role_event(mk_join("a", 100, 1000, {}));
    CHECK(sink.wait_calls(2), "加入应通知一次");
    const uint32_t role = sink.calls()[0].roleID;

    manager.bind_to_role(proc(102, 1002), proc(100, 1000));
    manager.bind_to_role(proc(102, 1002), proc(100, 1000));  // 已有归属
    manager.on_role_event(mk_join("barrier", 900, 9000));
    CHECK(sink.wait_calls(5), "屏障事件应通知");

    CHECK(manager.lookup(proc(102, 1002)).value_or(0) == role,
          "父已归属时 bind 应直接应用");
    CHECK(
        manager.stats().bind_deferred == 0 && manager.stats().bind_resolved == 0,
        "直接应用不应计入等待表计数");
    CHECK(manager.stats().bind_ignored == 1, "已有归属的 bind 应计忽略");
}

void run_periodic_join()
{
    RecordingSink sink;
    RoleManager manager;
    manager.add_lifecycle_sink(&sink);
    Runner runner(manager);

    manager.on_role_event(mk_join("a", 100, 1000, {proc(101, 1001)}));
    CHECK(sink.wait_calls(2), "加入应通知一次");
    const uint32_t role = sink.calls()[0].roleID;

    // 锚点未变、成员集变宽：补写新成员，产生成员通知而不产生生命周期通知
    manager.on_role_event(
        mk_join("a", 100, 1000, {proc(101, 1001), proc(102, 1002)}));
    manager.on_role_event(mk_join("barrier", 900, 9000));
    CHECK(sink.wait_calls(5), "屏障事件应通知");

    std::vector<RecordingSink::Call> calls = sink.calls();
    CHECK(calls.size() == 5, "锚点未变的 JOIN 只产生成员通知");
    CHECK(calls[2].kind == RecordingSink::Kind::MEMBERS_ADDED &&
              calls[2].roleID == role && calls[2].members.size() == 1 &&
              calls[2].members[0] == proc(102, 1002),
          "周期 JOIN 应就新增成员通知一次");
    CHECK(calls[3].kind == RecordingSink::Kind::JOINED && calls[3].roleID != role,
          "第四个通知应来自屏障事件");
    CHECK(manager.lookup(proc(102, 1002)).value_or(0) == role,
          "周期 JOIN 应补写新成员");
}

void run_dead_anchor_filter()
{
    RecordingSink sink;
    RoleManagerProbe probe;
    probe.is_exited = [](hng::Process p) { return p.pid == 100; };
    RoleManager manager(probe);
    manager.add_lifecycle_sink(&sink);
    Runner runner(manager);

    manager.on_role_event(mk_join("dead", 100, 1000));
    manager.on_role_event(mk_join("alive", 200, 2000));
    CHECK(sink.wait_calls(2), "存活锚点应通知");

    CHECK(sink.calls().size() == 2, "已退出锚点不得产生通知");
    CHECK(!manager.lookup(proc(100, 1000)).has_value(), "已退出锚点不得写入归属");
    CHECK(manager.lookup(proc(200, 2000)).value_or(0) == sink.calls()[0].roleID,
          "存活锚点应正常归属");
    CHECK(manager.stats().dead_anchor_rejected == 1, "死锚点 JOIN 应计数");

    // MAIN_PROCESS_CHANGE 同样过滤
    manager.on_role_event(
        mk_other(RoleAction::MAIN_PROCESS_CHANGE, "alive", 100, 1000));
    manager.on_role_event(mk_join("barrier", 901, 9001));
    CHECK(sink.wait_calls(4), "屏障事件应通知");

    CHECK(sink.calls().size() == 4, "死锚点的锚点更换不得通知");
    CHECK(manager.stats().dead_anchor_rejected == 2,
          "死锚点 MAIN_PROCESS_CHANGE 应计数");
    CHECK(manager.main_process(sink.calls()[0].roleID).value_or(proc(0, 0)) ==
              proc(200, 2000),
          "死锚点不得覆盖记录的锚点");

    // store 墓碑同样拒绝迟到 JOIN
    RecordingSink tombstone_sink;
    RoleManager tombstone_manager;
    tombstone_manager.add_lifecycle_sink(&tombstone_sink);
    Runner tombstone_runner(tombstone_manager);

    tombstone_manager.on_process_exited(proc(400, 4000));
    tombstone_manager.on_role_event(mk_join("late", 400, 4000));
    tombstone_manager.on_role_event(mk_join("barrier", 902, 9002));
    CHECK(tombstone_sink.wait_calls(2), "屏障事件应通知");
    CHECK(tombstone_sink.calls().size() == 2, "store 墓碑命中的 JOIN 不得通知");
    CHECK(!tombstone_manager.lookup(proc(400, 4000)).has_value(),
          "store 墓碑命中的锚点不得写入");
    CHECK(tombstone_manager.stats().dead_anchor_rejected == 1,
          "store 墓碑拒绝应计数");
    CHECK(tombstone_manager.stats().tombstone_depth == 1,
          "角色管理器快照应反映墓碑当前深度");
}

void run_dead_member_filter()
{
    RecordingSink sink;
    RoleManagerProbe probe;
    probe.is_exited = [](hng::Process p) { return p.pid == 101 || p.pid == 103; };
    probe.read_members = [](const std::string&) {
        return std::vector<hng::Process>{proc(103, 1003), proc(104, 1004)};
    };
    RoleManager manager(probe);
    manager.add_lifecycle_sink(&sink);
    Runner runner(manager);

    RoleEvent event = mk_join("a", 100, 1000, {proc(101, 1001), proc(102, 1002)});
    event.payload.cgroup_path = "/sys/fs/cgroup/system.slice/a.service";
    manager.on_role_event(event);
    CHECK(sink.wait_calls(2), "加入应通知一次");

    const uint32_t role = sink.calls()[0].roleID;
    CHECK(!manager.lookup(proc(101, 1001)).has_value(),
          "已退出的载荷成员不得进入关系表");
    CHECK(!manager.lookup(proc(103, 1003)).has_value(),
          "已退出的重读成员不得进入关系表");
    CHECK(manager.lookup(proc(102, 1002)).value_or(0) == role &&
              manager.lookup(proc(104, 1004)).value_or(0) == role &&
              manager.lookup(proc(100, 1000)).value_or(0) == role,
          "存活成员与锚点应正常归属");
    CHECK(manager.stats().dead_member_rejected == 2, "被过滤的成员应计数");
}

void run_leave_with_liveness()
{
    bool dead = false;
    RoleManagerProbe probe;
    probe.is_exited = [&dead](hng::Process) { return dead; };

    RecordingSink sink;
    RoleManager manager(probe);
    manager.add_lifecycle_sink(&sink);
    Runner runner(manager);

    manager.on_role_event(mk_join("a", 100, 1000, {proc(101, 1001)}));
    CHECK(sink.wait_calls(2), "加入应通知一次");
    const uint32_t role = sink.calls()[0].roleID;

    dead                = true;
    manager.on_role_event(mk_other(RoleAction::LEAVE, "a", 0, 0));
    CHECK(sink.wait_calls(3), "LEAVE 应通知");
    CHECK(sink.calls()[2].kind == RecordingSink::Kind::LEFT &&
              sink.calls()[2].roleID == role,
          "LEAVE 应正常退出");
    CHECK(!manager.role(role).has_value(), "退出后角色记录应删除");
    CHECK(manager.stats().dead_anchor_rejected == 0, "LEAVE 不做存活过滤");
}

void run_late_adopt_stats()
{
    RecordingSink sink;
    RoleManager manager;
    manager.add_lifecycle_sink(&sink);
    Runner runner(manager);

    manager.on_process_exited(proc(101, 1001));
    manager.on_role_event(mk_join("a", 100, 1000, {proc(101, 1001)}));
    CHECK(sink.wait_calls(2), "加入应通知一次");

    const uint32_t role = sink.calls()[0].roleID;
    CHECK(wait_until([&] { return manager.stats().late_adopt_rejected == 1; }),
          "死成员应计迟到 adopt");
    CHECK(manager.stats().tombstone_depth == 1, "墓碑深度应反映当前条数");
    CHECK(!manager.lookup(proc(101, 1001)).has_value(), "死成员不得归属");
    CHECK(manager.lookup(proc(100, 1000)).value_or(0) == role, "锚点仍应归属");
}

void run_bind_capacity_and_expiry()
{
    // 容量为 0：bind 被拒，不产生归属
    RoleRelationOptions no_capacity;
    no_capacity.bind_pending.capacity = 0;
    {
        RecordingSink sink;
        RoleManagerProbe probe;
        RoleManager manager(probe, no_capacity);
        manager.add_lifecycle_sink(&sink);
        Runner runner(manager);

        manager.bind_to_role(proc(101, 1001), proc(100, 1000));
        manager.on_role_event(mk_join("a", 100, 1000, {}));
        CHECK(sink.wait_calls(2), "加入应通知一次");

        CHECK(manager.stats().bind_rejected == 1, "容量为 0 时 bind 应被拒绝");
        CHECK(!manager.lookup(proc(101, 1001)).has_value(),
              "被拒绝的 bind 不得产生归属");
    }

    // TTL 过期：过期等待项在锚点后续落地时不得被应用
    FakeClock clock;
    RoleRelationOptions ttl;
    ttl.bind_pending.ttl = std::chrono::milliseconds(100);
    ttl.now              = [&clock] { return clock.now(); };

    RecordingSink sink;
    RoleManagerProbe probe;
    RoleManager manager(probe, ttl);
    manager.add_lifecycle_sink(&sink);
    Runner runner(manager);

    manager.bind_to_role(proc(102, 1002), proc(100, 1000));
    manager.on_role_event(mk_join("a", 200, 2000));
    CHECK(sink.wait_calls(2), "屏障事件应通知");
    CHECK(wait_until([&] { return manager.stats().bind_deferred == 1; }),
          "bind 应先暂存");

    clock.advance(std::chrono::milliseconds(101));
    manager.on_role_event(mk_join("b", 300, 3000));
    CHECK(sink.wait_calls(4), "屏障事件应通知");
    CHECK(wait_until([&] { return manager.stats().bind_expired == 1; }),
          "过期等待项应在落地末尾清理");

    manager.on_role_event(mk_join("c", 100, 1000));
    CHECK(sink.wait_calls(6), "加入应通知一次");
    CHECK(!manager.lookup(proc(102, 1002)).has_value(),
          "过期等待项不得在锚点落地时被应用");
    CHECK(manager.lookup(proc(100, 1000)).has_value(), "锚点仍应归属");
}

}  // namespace

int main()
{
    run_join();
    run_roles();
    run_supervision();
    run_main_process();
    run_leave();
    run_join_reread();
    run_anchor_transitions();
    run_bind_and_removed();
    run_members();
    run_multiple_sinks();
    run_stop_semantics();
    run_concurrent_producers();
    run_bind_after_join();
    run_periodic_join();
    run_dead_anchor_filter();
    run_dead_member_filter();
    run_leave_with_liveness();
    run_late_adopt_stats();
    run_bind_capacity_and_expiry();

    if (g_fail) {
        std::fprintf(stderr, "TOTAL FAILURES: %d\n", g_fail);
        return 1;
    }
    std::printf("ALL PASS\n");
    return 0;
}
