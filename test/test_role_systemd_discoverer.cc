/**
 * @file test_role_systemd_discoverer.cc
 * @brief systemd 角色发现器的表驱动单元测试
 * @details
 * 覆盖 agent/control_plane/role_discovery 的 SystemdSignalTranslator 与
 * SystemdRoleDiscoverer：
 *  - 信号翻译：首次 MainPID 非 0 触发加入、activating 且 MainPID 为 0 不产出、
 *    自动重启产出 LEAVE + JOIN、无 LEAVE 介入的 MainPID 变化产出主进程更换；
 *  - 载荷：锚点、cgroup_path、member_processes、就绪程度属性；
 *  - 过滤：忽略前缀与全称、后缀、白名单、Type=oneshot 照常归类；
 *  - 属性快照维护：重复与重放的输入不产出，UnitRemoved 丢弃快照，
 *    UnitNew 与 JobRemoved 都不触发重取，滞后的 inactive 不读成离开，
 *    RemainAfterExit 的 active (exited) 由 MainPID 归零给出退出；
 *  - 对外形态：stop() 先于 run()、stop() 幂等、run() 返回后不再产出事件。
 *
 * 消息序列录自本机真实 systemd 257：
 *   sudo busctl monitor --match="type='signal',sender='org.freedesktop.systemd1'"
 *   sudo systemd-run --unit=hng-probe-svc --property=Type=simple /bin/sleep 4
 *   sudo systemd-run --unit=hng-probe-once --property=Type=oneshot /bin/true
 * 其中的 MainPID 取值、ActiveState/SubState 迁移顺序与两个接口的划分均照实转写。
 *
 * @author red_shinku
 * @date 2026.9.12
 */

#include "agent/control_plane/role_discovery/include/role_cgroup_reader.hpp"
#include "agent/control_plane/role_discovery/include/role_systemd_discoverer.hpp"

#include <cstdio>
#include <map>
#include <optional>
#include <string>
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

using hng::Process;
using hng::role::RoleAction;
using hng::role::RoleEvent;
using hng::role::RoleSignalTable;
using hng::role::SystemdProbe;
using hng::role::SystemdRoleDiscoverer;
using hng::role::SystemdSignal;
using hng::role::SystemdSignalKind;
using hng::role::SystemdSignalTranslator;
using hng::role::SystemdTranslation;
using hng::role::SystemdUnitDelta;
using hng::role::SystemdUnitFilter;
using hng::role::SystemdUnitSnapshot;

/// 录制样本中出现的对象路径（unit 名经 D-Bus 转义，不得自行反解）
constexpr const char* kSvcPath =
    "/org/freedesktop/systemd1/unit/hng_2dprobe_2dsvc_2eservice";
constexpr const char* kOncePath =
    "/org/freedesktop/systemd1/unit/hng_2dprobe_2donce_2eservice";

/// 源侧给出的相对 cgroup 路径（systemd 的 ControlGroup 即此形态）
constexpr const char* kCgroupRelative = "/system.slice/hng-probe-svc.service";

/// 载荷里应当是可直接打开的绝对路径
std::string kCgroup()
{
    return hng::role::RoleCgroupReader::absolute(kCgroupRelative);
}

/// 探针替身：进程启动时间表与 cgroup 成员表
struct FakeSystem {
    std::map<uint32_t, uint64_t> start_times;
    std::map<std::string, std::vector<Process>> members;

    SystemdProbe probe()
    {
        SystemdProbe p;
        p.read_process = [this](uint32_t pid) -> std::optional<Process> {
            auto it = start_times.find(pid);
            if (it == start_times.end()) {
                return std::nullopt;
            }
            return Process{pid, it->second};
        };
        p.read_members = [this](const std::string& cgroup) {
            auto it = members.find(cgroup);
            if (it == members.end()) {
                return std::vector<Process>();
            }
            return it->second;
        };
        return p;
    }
};

/// 翻译层 + 状态表的最小组合，收集产出的事件与待补快照
class Harness {
   public:
    Harness(const SystemdUnitFilter& filter, SystemdProbe probe)
        : translator_(filter, probe)
    {
    }

    void feed(const SystemdSignal& signal)
    {
        absorb(translator_.on_signal(signal));
    }

    void feed_snapshot(const std::string& object_path,
                       const SystemdUnitSnapshot& snapshot)
    {
        absorb(translator_.on_snapshot(object_path, snapshot));
    }

    const std::vector<RoleEvent>& events() const { return events_; }

    /// 取走本批待补快照的对象路径（去重后）
    std::vector<std::string> take_pending()
    {
        std::vector<std::string> out = pending_;
        pending_.clear();
        return out;
    }

    void clear_pending() { pending_.clear(); }

   private:
    void absorb(const SystemdTranslation& translation)
    {
        for (const std::string& path : translation.pending_snapshots) {
            pending_.push_back(path);
        }
        for (const auto& observation : translation.observations) {
            if (std::optional<RoleEvent> event = table_.submit(observation)) {
                events_.push_back(*event);
            }
        }
    }

    SystemdSignalTranslator translator_;
    RoleSignalTable table_;
    std::vector<RoleEvent> events_;
    std::vector<std::string> pending_;
};

/// 构造完整的 unit 快照，只填关心的字段
SystemdUnitSnapshot mk_snapshot(const std::string& id, uint32_t main_pid,
                                const std::string& active_state,
                                const std::string& sub_state,
                                const std::string& service_type = "simple",
                                const std::string& cgroup       = kCgroup())
{
    SystemdUnitSnapshot snapshot;
    snapshot.id            = id;
    snapshot.load_state    = "loaded";
    snapshot.active_state  = active_state;
    snapshot.sub_state     = sub_state;
    snapshot.service_type  = service_type;
    snapshot.main_pid      = main_pid;
    snapshot.control_group = cgroup;
    return snapshot;
}

SystemdUnitDelta delta_main_pid(uint32_t pid)
{
    SystemdUnitDelta delta;
    delta.main_pid = pid;
    return delta;
}

SystemdUnitDelta delta_unit_state(const std::string& active_state,
                                  const std::string& sub_state)
{
    SystemdUnitDelta delta;
    delta.active_state = active_state;
    delta.sub_state    = sub_state;
    return delta;
}

SystemdSignal sig_properties(const std::string& object_path,
                             const SystemdUnitDelta& delta)
{
    SystemdSignal signal;
    signal.kind        = SystemdSignalKind::UNIT_PROPERTIES;
    signal.object_path = object_path;
    signal.delta       = delta;
    return signal;
}

SystemdSignal sig_unit_new(const std::string& unit_id,
                           const std::string& object_path)
{
    SystemdSignal signal;
    signal.kind        = SystemdSignalKind::UNIT_NEW;
    signal.unit_id     = unit_id;
    signal.object_path = object_path;
    return signal;
}

SystemdSignal sig_unit_removed(const std::string& unit_id,
                               const std::string& object_path)
{
    SystemdSignal signal;
    signal.kind        = SystemdSignalKind::UNIT_REMOVED;
    signal.unit_id     = unit_id;
    signal.object_path = object_path;
    return signal;
}

SystemdSignal sig_job_removed(const std::string& unit_id,
                              const std::string& result)
{
    SystemdSignal signal;
    signal.kind       = SystemdSignalKind::JOB_REMOVED;
    signal.unit_id    = unit_id;
    signal.job_result = result;
    return signal;
}

SystemdSignal sig_name_owner_changed(const std::string& new_owner)
{
    SystemdSignal signal;
    signal.kind      = SystemdSignalKind::NAME_OWNER_CHANGED;
    signal.new_owner = new_owner;
    return signal;
}

/// 断言某一动作的事件数为期望值
void expect_actions(const std::vector<RoleEvent>& events,
                    const std::vector<RoleAction>& expected, const char* what)
{
    CHECK(events.size() == expected.size(), what);
    if (events.size() != expected.size()) {
        std::fprintf(stderr, "        期望 %zu 个事件，实得 %zu 个\n",
                     expected.size(), events.size());
        return;
    }
    for (std::size_t i = 0; i < expected.size(); ++i) {
        CHECK(events[i].action == expected[i], what);
    }
}

// ============================================================
// 1. 首次 MainPID 非 0 触发加入
// ============================================================

void test_join_on_first_main_pid()
{
    FakeSystem system;
    system.start_times[4751]  = 881234567ULL;
    system.members[kCgroup()] = {Process{4751, 881234567ULL},
                                 Process{4752, 881234600ULL}};

    Harness harness(SystemdUnitFilter(), system.probe());

    // 录制的真实顺序：UnitNew → Service 接口的 MainPID → Unit 接口的状态
    harness.feed(sig_unit_new("hng-probe-svc.service", kSvcPath));
    harness.feed(sig_properties(kSvcPath, delta_main_pid(4751)));

    // 首次见到该 unit，增量里没有 Id 与 ControlGroup，先请求完整快照。
    // UnitNew 只登记不补快照——向尚未载入的 unit 对象取属性会使 systemd
    // 就地载入该对象，载入/卸载成环
    const std::vector<std::string> pending = harness.take_pending();
    CHECK(pending.size() == 1, "只有首次 PropertiesChanged 请求补快照");
    CHECK(!pending.empty() && pending[0] == kSvcPath,
          "请求的是该 unit 的对象路径");
    CHECK(harness.events().empty(), "补快照之前不得产出事件");

    // GetAll 回来：此刻 MainPID 已确定，即便尚未 READY 也应立即发布
    harness.feed_snapshot(kSvcPath, mk_snapshot("hng-probe-svc.service", 4751,
                                                "activating", "start"));
    expect_actions(harness.events(), {RoleAction::JOIN},
                   "首次 MainPID 非 0 产出加入");

    const RoleEvent& join = harness.events()[0];
    CHECK(join.payload.identity.instance_key == "hng-probe-svc.service",
          "实例键为 unit 名");
    CHECK(join.payload.identity.type_key == "hng-probe-svc",
          "类型键去掉 unit 后缀");
    CHECK(join.payload.main_process.pid == 4751, "锚点为主进程");
    CHECK(join.payload.main_process.pid_start_time == 881234567ULL,
          "锚点携带 pid_start_time");
    CHECK(join.payload.cgroup_path == kCgroup(), "载荷携带 cgroup 路径");
    CHECK(join.payload.member_processes.size() == 2,
          "成员补齐覆盖 cgroup 内全部进程");
    CHECK(join.payload.identity.attributes.at("active_state") == "activating",
          "就绪程度作为属性携带，不阻塞发布");
    CHECK(join.payload.identity.attributes.at("sub_state") == "start",
          "SubState 作为属性携带");
    CHECK(join.payload.identity.attributes.at("service_type") == "simple",
          "Type 作为属性携带");
}

// ============================================================
// 2. activating 且 MainPID 为 0 不发布
// ============================================================

void test_activating_without_main_pid_publishes_nothing()
{
    FakeSystem system;
    system.start_times[4751]  = 881234567ULL;
    system.members[kCgroup()] = {Process{4751, 881234567ULL}};

    Harness harness(SystemdUnitFilter(), system.probe());

    harness.feed_snapshot(
        kSvcPath, mk_snapshot("hng-probe-svc.service", 0, "activating", "start"));
    CHECK(harness.events().empty(), "activating 且 MainPID 为 0 不产出事件");

    // MainPID 出现即发布，此时 ActiveState 仍为 activating
    harness.feed(sig_properties(kSvcPath, delta_main_pid(4751)));
    expect_actions(harness.events(), {RoleAction::JOIN}, "MainPID 出现即发布");

    // READY 后转 active：锚点未变，不产出多余动作
    harness.feed(sig_properties(kSvcPath, delta_unit_state("active", "running")));
    expect_actions(harness.events(), {RoleAction::JOIN},
                   "转 active 不产出多余动作");
}

// ============================================================
// 3. 自动重启：LEAVE + JOIN，不合并、不出主进程更换
// ============================================================

void test_auto_restart_is_leave_then_join()
{
    FakeSystem system;
    system.start_times[100]   = 111ULL;
    system.start_times[200]   = 222ULL;
    system.members[kCgroup()] = {Process{100, 111ULL}, Process{101, 112ULL}};

    Harness harness(SystemdUnitFilter(), system.probe());
    harness.feed_snapshot(
        kSvcPath, mk_snapshot("hng-probe-svc.service", 100, "active", "running"));
    expect_actions(harness.events(), {RoleAction::JOIN}, "前置：先加入");

    // 崩溃重启：MainPID 先归零，状态随后进入 activating/auto-restart，不经过
    // inactive
    harness.feed(sig_properties(kSvcPath, delta_main_pid(0)));
    expect_actions(harness.events(), {RoleAction::JOIN, RoleAction::LEAVE},
                   "MainPID 归零即发布退出");

    harness.feed(
        sig_properties(kSvcPath, delta_unit_state("activating", "auto-restart")));
    expect_actions(harness.events(), {RoleAction::JOIN, RoleAction::LEAVE},
                   "auto-restart 只是属性，不额外产出事件");

    // 重新拉起：换成新的主进程，是普通加入而非主进程更换
    system.members[kCgroup()] = {Process{200, 222ULL}};
    harness.feed(sig_properties(kSvcPath, delta_main_pid(200)));
    expect_actions(harness.events(),
                   {RoleAction::JOIN, RoleAction::LEAVE, RoleAction::JOIN},
                   "自动重启表现为 LEAVE + JOIN");

    const RoleEvent& leave = harness.events()[1];
    CHECK(leave.payload.identity.instance_key == "hng-probe-svc.service",
          "退出事件携带实例键");
    CHECK(leave.payload.cgroup_path == kCgroup(),
          "退出载荷由状态表缓存补齐，仍带 cgroup 路径");
    CHECK(leave.payload.main_process.pid == 100, "退出载荷带原锚点");
    CHECK(leave.payload.member_processes.empty(), "退出事件的成员列表为空");

    const RoleEvent& rejoin = harness.events()[2];
    CHECK(rejoin.payload.main_process.pid == 200, "重新加入带新锚点");
    CHECK(rejoin.payload.member_processes.size() == 1, "重新加入重新枚举成员");
}

// ============================================================
// 4. 无 LEAVE 介入的 MainPID 变化 → 主进程更换
// ============================================================

void test_main_pid_handover_without_leave()
{
    FakeSystem system;
    system.start_times[100]   = 111ULL;
    system.start_times[200]   = 222ULL;
    system.members[kCgroup()] = {Process{100, 111ULL}};

    Harness harness(SystemdUnitFilter(), system.probe());
    harness.feed_snapshot(
        kSvcPath, mk_snapshot("hng-probe-svc.service", 100, "active", "running"));
    expect_actions(harness.events(), {RoleAction::JOIN}, "前置：先加入");

    // sd_notify(MAINPID=...) 原地交接：unit 从未离开 active
    system.members[kCgroup()] = {Process{200, 222ULL}, Process{201, 223ULL}};
    harness.feed(sig_properties(kSvcPath, delta_main_pid(200)));
    expect_actions(harness.events(),
                   {RoleAction::JOIN, RoleAction::MAIN_PROCESS_CHANGE},
                   "无 LEAVE 介入的 MainPID 变化产出主进程更换");

    const RoleEvent& change = harness.events()[1];
    CHECK(change.payload.main_process.pid == 200, "携带新的主进程锚点");
    CHECK(change.payload.main_process.pid_start_time == 222ULL,
          "新锚点携带新的启动时间");
    CHECK(change.payload.member_processes.size() == 2, "重新枚举 cgroup 成员");
    CHECK(change.payload.identity.instance_key == "hng-probe-svc.service",
          "实例键不变");
}

// ============================================================
// 5. 重复与重放的输入不产出多余动作
// ============================================================

void test_replay_produces_no_extra_actions()
{
    FakeSystem system;
    system.start_times[4751]  = 881234567ULL;
    system.members[kCgroup()] = {Process{4751, 881234567ULL}};

    Harness harness(SystemdUnitFilter(), system.probe());
    const SystemdUnitSnapshot snapshot =
        mk_snapshot("hng-probe-svc.service", 4751, "activating", "start");

    harness.feed_snapshot(kSvcPath, snapshot);
    expect_actions(harness.events(), {RoleAction::JOIN}, "首次快照产出加入");

    // 重连后无条件重放同一份快照，状态表可重入，不产出
    harness.feed_snapshot(kSvcPath, snapshot);
    harness.feed_snapshot(kSvcPath, snapshot);
    expect_actions(harness.events(), {RoleAction::JOIN}, "重放的快照不产出");

    // 重复的增量同理
    harness.feed(sig_properties(kSvcPath, delta_main_pid(4751)));
    harness.feed(
        sig_properties(kSvcPath, delta_unit_state("activating", "start")));
    expect_actions(harness.events(), {RoleAction::JOIN}, "重复的增量不产出");

    // 未跟踪属性的变化同样不产出
    SystemdUnitDelta unrelated;
    unrelated.load_state = "loaded";
    harness.feed(sig_properties(kSvcPath, unrelated));
    expect_actions(harness.events(), {RoleAction::JOIN}, "未跟踪字段不产出");
}

// ============================================================
// 6. 过滤策略
// ============================================================

void test_filter()
{
    SystemdUnitFilter filter;
    CHECK(!filter.matches("systemd-journald.service"), "忽略 systemd- 前缀");
    CHECK(!filter.matches("user@1000.service"), "忽略 user@ 前缀");
    CHECK(!filter.matches("dbus.service"), "忽略内建列表中的 unit");
    CHECK(!filter.matches("nginx.scope"), "默认只取 .service");
    CHECK(!filter.matches("nginx.socket"), "非 service 后缀不取");
    CHECK(!filter.matches("nginx"), "无后缀不取");
    CHECK(filter.matches("nginx.service"), "普通服务单元纳入");
    CHECK(filter.matches("hng-probe-svc.service"), "普通服务单元纳入");

    SystemdUnitFilter opened;
    opened.unit_suffixes = {"service", "scope"};
    CHECK(opened.matches("nginx.scope"), "放开后缀后 scope 纳入");

    SystemdUnitFilter listed;
    listed.whitelist = {"nginx.service"};
    CHECK(listed.matches("nginx.service"), "白名单内的 unit 纳入");
    CHECK(!listed.matches("sshd.service"), "白名单外的 unit 不纳入");

    SystemdUnitFilter override_ignore;
    override_ignore.whitelist = {"dbus.service"};
    CHECK(override_ignore.matches("dbus.service"),
          "白名单是显式指定，优先于内建忽略列表");
}

// ============================================================
// 7. Type=oneshot 单独归类，照常发布
// ============================================================

void test_oneshot_is_carried_as_attribute()
{
    FakeSystem system;
    system.start_times[4760]  = 777ULL;
    system.members[kCgroup()] = {Process{4760, 777ULL}};

    Harness harness(SystemdUnitFilter(), system.probe());

    // 录制的 oneshot 序列：MainPID 出现时 ActiveState 仍是 activating/start
    harness.feed(sig_unit_new("hng-probe-once.service", kOncePath));
    harness.feed_snapshot(
        kOncePath, mk_snapshot("hng-probe-once.service", 4760, "activating",
                               "start", "oneshot", kCgroup()));
    expect_actions(harness.events(), {RoleAction::JOIN},
                   "oneshot 照常发布，不因短命被丢弃");
    CHECK(harness.events()[0].payload.identity.attributes.at("service_type") ==
              "oneshot",
          "oneshot 由 service_type 属性区分");

    harness.feed(sig_properties(kOncePath, delta_main_pid(0)));
    expect_actions(harness.events(), {RoleAction::JOIN, RoleAction::LEAVE},
                   "oneshot 结束后照常发布退出");
}

// ============================================================
// 8. 属性快照的维护
// ============================================================

void test_snapshot_maintenance()
{
    FakeSystem system;
    system.start_times[4751]  = 881234567ULL;
    system.members[kCgroup()] = {Process{4751, 881234567ULL}};

    Harness harness(SystemdUnitFilter(), system.probe());
    harness.feed_snapshot(kSvcPath, mk_snapshot("hng-probe-svc.service", 4751,
                                                "active", "running"));
    harness.clear_pending();

    // JobRemoved 只记日志，不重取属性：对已卸载的 unit 重取会把它的对象重新
    // 载入，读回尚未更新的 MainPID，凭空产出一对加入/退出
    harness.feed(sig_job_removed("hng-probe-svc.service", "done"));
    CHECK(harness.take_pending().empty(), "JobRemoved 不触发重取");

    // UnitRemoved 只丢弃属性快照，不产出事件，也不动状态表
    harness.feed(sig_unit_removed("hng-probe-svc.service", kSvcPath));
    CHECK(harness.events().size() == 1, "UnitRemoved 不产出事件");

    // 快照已丢弃：该路径的属性变化重新走「首次见到」→ 请求补快照
    harness.clear_pending();
    harness.feed(sig_properties(kSvcPath, delta_main_pid(4751)));
    const std::vector<std::string> pending = harness.take_pending();
    CHECK(pending.size() == 1 && pending[0] == kSvcPath,
          "UnitRemoved 后该 unit 的快照被丢弃");

    // NameOwnerChanged 不影响翻译层产出
    harness.feed(sig_name_owner_changed(":1.5"));
    CHECK(harness.events().size() == 1, "NameOwnerChanged 不产出事件");
}

// ============================================================
// 9. 滞后到达的 inactive 不得把存活实例读成离开
// ============================================================

void test_stale_inactive_keeps_instance_present()
{
    FakeSystem system;
    system.start_times[7765]  = 2737903ULL;
    system.members[kCgroup()] = {Process{7765, 2737903ULL}};

    Harness harness(SystemdUnitFilter(), system.probe());
    harness.feed_snapshot(kSvcPath, mk_snapshot("hng-probe-svc.service", 7765,
                                                "activating", "start"));
    expect_actions(harness.events(), {RoleAction::JOIN}, "前置：先加入");

    // 录制的真实序列：MainPID 之后 systemd 补发了一个值更旧的 ActiveState，
    // 随后才回到 activating。此刻实例仍在，锚点未变，不得产出任何动作。
    harness.feed(sig_properties(kSvcPath, delta_unit_state("inactive", "dead")));
    expect_actions(harness.events(), {RoleAction::JOIN},
                   "滞后的 inactive 不产出退出");

    harness.feed(
        sig_properties(kSvcPath, delta_unit_state("activating", "start")));
    expect_actions(harness.events(), {RoleAction::JOIN},
                   "回到 activating 不产出多余动作");

    // 真正的退出仍由主进程侧给出
    harness.feed(sig_properties(kSvcPath, delta_main_pid(0)));
    expect_actions(harness.events(), {RoleAction::JOIN, RoleAction::LEAVE},
                   "主进程归零仍照常产出退出");
}

// ============================================================
// 10. RemainAfterExit=yes 走到 active (exited)：退出由 MainPID 归零给出
// ============================================================

void test_remain_after_exit_leaves_on_main_pid_zero()
{
    FakeSystem system;
    system.start_times[9001]  = 555ULL;
    system.members[kCgroup()] = {Process{9001, 555ULL}};

    Harness harness(SystemdUnitFilter(), system.probe());
    harness.feed_snapshot(kSvcPath, mk_snapshot("hng-probe-svc.service", 9001,
                                                "active", "running", "oneshot"));
    expect_actions(harness.events(), {RoleAction::JOIN}, "前置：先加入");

    // 主进程退出，但 ActiveState 仍是 active——只看 ActiveState 会漏掉退出，
    // 留下一个「存活但锚点已死」的条目
    harness.feed(sig_properties(kSvcPath, delta_unit_state("active", "exited")));
    expect_actions(harness.events(), {RoleAction::JOIN},
                   "仅 SubState 变化不产出退出");

    harness.feed(sig_properties(kSvcPath, delta_main_pid(0)));
    expect_actions(harness.events(), {RoleAction::JOIN, RoleAction::LEAVE},
                   "MainPID 归零在 active(exited) 上照常产出退出");
}

// ============================================================
// 11. 已停止的 unit 不得被兜底重取复活
// ============================================================

void test_job_removed_does_not_revive_stopped_unit()
{
    FakeSystem system;
    system.start_times[4751]  = 881234567ULL;
    system.members[kCgroup()] = {Process{4751, 881234567ULL}};

    Harness harness(SystemdUnitFilter(), system.probe());
    harness.feed_snapshot(kSvcPath, mk_snapshot("hng-probe-svc.service", 4751,
                                                "active", "running"));
    expect_actions(harness.events(), {RoleAction::JOIN}, "前置：先加入");

    // 停止：MainPID 归零后产出退出
    harness.feed(sig_properties(kSvcPath, delta_main_pid(0)));
    expect_actions(harness.events(), {RoleAction::JOIN, RoleAction::LEAVE},
                   "停止产出退出");

    // 停止作业的 JobRemoved：若据此重取，会把 unit 对象重新载入并读回尚未
    // 更新的 MainPID，凭空产出一对加入/退出
    harness.clear_pending();
    harness.feed(sig_job_removed("hng-probe-svc.service", "done"));
    CHECK(harness.take_pending().empty(), "JobRemoved 不触发重取");
    expect_actions(harness.events(), {RoleAction::JOIN, RoleAction::LEAVE},
                   "已停止的 unit 不因 JobRemoved 复活");
}

// ============================================================
// 12. 对外形态：run() / stop()
// ============================================================

void test_run_stop_contract()
{
    int emitted = 0;
    SystemdRoleDiscoverer::Config config;
    config.on_event = [&emitted](const RoleEvent&) { ++emitted; };

    // stop() 先于 run()：run() 立即返回，不阻塞
    {
        SystemdRoleDiscoverer discoverer(config);
        discoverer.stop();
        discoverer.stop();  // 幂等
        discoverer.run();
        CHECK(true, "run() 之前调用 stop() 时 run() 立即返回");
        CHECK(emitted == 0, "run() 返回后不再产出事件");
    }

    // 反复 stop() 与析构不崩
    {
        SystemdRoleDiscoverer discoverer(config);
        for (int i = 0; i < 8; ++i) {
            discoverer.stop();
        }
        CHECK(emitted == 0, "未运行时不产出事件");
    }
}

}  // namespace

int main()
{
    test_join_on_first_main_pid();
    test_activating_without_main_pid_publishes_nothing();
    test_auto_restart_is_leave_then_join();
    test_main_pid_handover_without_leave();
    test_replay_produces_no_extra_actions();
    test_filter();
    test_oneshot_is_carried_as_attribute();
    test_snapshot_maintenance();
    test_stale_inactive_keeps_instance_present();
    test_remain_after_exit_leaves_on_main_pid_zero();
    test_job_removed_does_not_revive_stopped_unit();
    test_run_stop_contract();

    if (g_fail == 0) {
        std::printf("test_role_systemd_discoverer：全部通过\n");
        return 0;
    }
    std::fprintf(stderr, "test_role_systemd_discoverer：%d 处失败\n", g_fail);
    return 1;
}
