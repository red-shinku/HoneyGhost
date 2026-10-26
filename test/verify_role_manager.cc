/**
 * @file verify_role_manager.cc
 * @brief 角色管理器的端到端校验：装配形态 + 假发现器 + 真实 cgroup 读取
 * @details
 * 无需特权，注册为 ctest 用例。校验的是「装配起来能不能用」，不是单点语义：
 *  - 装配：发现器只拿 hng::role::RoleEventSink&，下游只拿 RoleLifecycleSink，
 *    查询方只拿 RoleLookupService&，ProcessManager 的位置由直接调
 *    RoleJoinService& / ProcessLifecycleSink& 代替（该组件尚未接线，见
 *    docs/role_manager/装配与遗留.md）；
 *  - 线程与顺序：先 add_lifecycle_sink、再起消费线程、再起发现器；
 *    停止时先停发现器并 join、再 stop()、最后 join 消费线程；
 *  - 多生产者：两个发现器线程各自推一批角色；
 *  - 真实 IO：其中一个角色的 cgroup 路径取本进程所在的那个，断言重读真的
 *    枚举到了本进程——这条不经注入替身，走的是 RoleCgroupReader。
 * @author red_shinku
 * @date 2026.9.18
 */

#include "agent/control_plane/src/role_manager.hpp"

#include <unistd.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <fstream>
#include <mutex>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "agent/role_discovery/src/role_cgroup_reader.hpp"

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

constexpr int kDiscoverers        = 2;   ///< 假发现器线程数
constexpr int kRolesPerSource     = 16;  ///< 每个发现器推的角色数
constexpr int kRoles              = kDiscoverers * kRolesPerSource;
/// 读不到的 cgroup 路径：除「真实 cgroup」那个角色外都用它
constexpr const char* kDeadCgroup = "/nonexistent-hng/cgroup";

/// 一个角色在本用例里的全部输入
struct RoleSpec {
    std::string instance_key;
    hng::Process anchor;
    std::string cgroup_path;
};

hng::Process proc(uint32_t pid, uint64_t start)
{
    return hng::Process{pid, start};
}

RoleEvent mk_event(RoleAction action, const RoleSpec& spec, hng::Process anchor)
{
    RoleEvent event;
    event.action                                = action;
    event.payload.identity.instance_key         = spec.instance_key;
    event.payload.identity.type_key             = "nginx";
    event.payload.identity.source               = RoleSource::SYSTEMD;
    event.payload.identity.attributes["source"] = "verify";
    event.payload.main_process                  = anchor;
    event.payload.cgroup_path                   = spec.cgroup_path;
    if (action == RoleAction::JOIN) {
        // 成员集故意留空：逼 RoleManager 走 cgroup 重读
        event.payload.member_processes.clear();
    }
    return event;
}

/// 读本进程的 (pid, start_time)
std::optional<hng::Process> read_self()
{
    std::ifstream stat("/proc/self/stat");
    if (!stat) {
        return std::nullopt;
    }
    std::stringstream buffer;
    buffer << stat.rdbuf();
    std::optional<uint64_t> start =
        hng::role::RoleCgroupReader::parse_start_time(buffer.str());
    if (!start) {
        return std::nullopt;
    }
    return proc(static_cast<uint32_t>(getpid()), *start);
}

/**
 * @brief 下游替身：按 roleID 维护基线集合，并在回调内反查查询接口
 * @note 四个回调都跑在消费线程上；跨线程读的计数在锁内或为原子量
 */
class BaselineSink : public RoleLifecycleSink {
   public:
    explicit BaselineSink(RoleLookupService& lookups) : lookups_(lookups) {}

    void on_role_joined(const hng::Role& role) override
    {
        // 加入：此刻起该 roleID 必须可查，否则下游的基线就是错的
        if (!lookups_.role(role.roleID).has_value()) {
            ++errors_;
        }
        std::lock_guard lock(mutex_);
        alive_.insert(role.roleID);
        ++joined_;
        cv_.notify_all();
    }

    void on_role_left(const hng::Role& role) override
    {
        if (lookups_.role(role.roleID).has_value()) {
            ++errors_;
        }
        std::lock_guard lock(mutex_);
        alive_.erase(role.roleID);
        ++left_;
        cv_.notify_all();
    }

    void on_role_main_process_changed(const hng::Role& role) override
    {
        if (!lookups_.role(role.roleID).has_value()) {
            ++errors_;
        }
        std::lock_guard lock(mutex_);
        ++changed_;
        cv_.notify_all();
    }

    void on_role_members_changed(const hng::Role& role,
                                 const std::vector<hng::Process>& added) override
    {
        // 成员通知到达时角色必须仍可查，否则下游增量维护的基线是错的
        if (!lookups_.role(role.roleID).has_value() || added.empty()) {
            ++errors_;
        }
        std::lock_guard lock(mutex_);
        added_members_ += added.size();
        cv_.notify_all();
    }

    bool wait_counts(uint64_t joined, uint64_t left, uint64_t changed)
    {
        std::unique_lock lock(mutex_);
        return cv_.wait_for(lock, std::chrono::seconds(10), [&] {
            return joined_ >= joined && left_ >= left && changed_ >= changed;
        });
    }

    std::size_t alive_count()
    {
        std::lock_guard lock(mutex_);
        return alive_.size();
    }

    uint64_t errors() const { return errors_.load(); }

    uint64_t added_members()
    {
        std::lock_guard lock(mutex_);
        return added_members_;
    }

   private:
    RoleLookupService& lookups_;

    std::mutex mutex_;
    std::condition_variable cv_;
    std::set<uint32_t> alive_;
    uint64_t joined_        = 0;
    uint64_t left_          = 0;
    uint64_t changed_       = 0;
    uint64_t added_members_ = 0;
    std::atomic<uint64_t> errors_{0};
};

}  // namespace

int main()
{
    // 本进程所在的 cgroup：让其中一个角色的重读走真实 IO
    std::optional<hng::Process> self = read_self();
    std::optional<std::string> own_cgroup =
        hng::role::RoleCgroupReader::read_process_cgroup(
            static_cast<uint32_t>(getpid()));
    std::string own_path;
    std::vector<hng::Process> own_members;
    if (own_cgroup) {
        own_path    = hng::role::RoleCgroupReader::absolute(*own_cgroup);
        own_members = hng::role::RoleCgroupReader::read(own_path);
    }

    std::vector<RoleSpec> specs;
    for (int i = 0; i < kRoles; ++i) {
        RoleSpec spec;
        spec.instance_key = "role-" + std::to_string(i);
        spec.anchor       = proc(10000 + static_cast<uint32_t>(i), 1000 + i);
        spec.cgroup_path  = kDeadCgroup;
        specs.push_back(spec);
    }
    if (!own_path.empty()) {
        specs[0].cgroup_path = own_path;  // 只有这个角色走真实读取
    }

    // ---- 装配：注册出口必须在起线程之前 ----
    RoleManager manager;
    BaselineSink sink(manager);
    manager.add_lifecycle_sink(&sink);

    hng::role::RoleEventSink& events = manager;  // 发现器只看见这一个接口
    RoleJoinService& joins           = manager;  // ProcessManager 的位置
    ProcessLifecycleSink& exits      = manager;
    RoleLookupService& lookups       = manager;

    // ---- 初始化期入口：先落地已入队事件（此刻为空），再以不完整空批对账 ----
    manager.drain();
    hng::ProcessSeedBatch batch;
    batch.complete = false;
    manager.reconcile(batch);

    // ---- 启动：先起消费线程，再起发现器 ----
    std::thread consumer([&manager] { manager.run(); });

    std::vector<std::thread> discoverers;
    for (int d = 0; d < kDiscoverers; ++d) {
        discoverers.emplace_back([&events, &specs, d] {
            for (int i = d * kRolesPerSource; i < (d + 1) * kRolesPerSource;
                 ++i) {
                events.on_role_event(
                    mk_event(RoleAction::JOIN, specs[i], specs[i].anchor));
            }
        });
    }
    for (std::thread& discoverer : discoverers) {
        discoverer.join();
    }

    // ---- 首次全量建表 ----
    CHECK(sink.wait_counts(kRoles, 0, 0), "全部加入通知应在时限内到齐");
    CHECK(sink.alive_count() == static_cast<std::size_t>(kRoles),
          "下游基线应含全部角色");
    CHECK(sink.added_members() >= static_cast<uint64_t>(kRoles),
          "首次建表应报告每个角色的新增成员");
    CHECK(sink.errors() == 0, "出口回调内反查角色记录应全部命中");

    for (const RoleSpec& spec : specs) {
        std::optional<uint32_t> role = lookups.lookup(spec.anchor);
        CHECK(role.has_value(), "每个角色的锚点都应有归属");
        std::optional<hng::Role> view = lookups.role(role.value_or(0));
        CHECK(view.has_value() && view->roleLabel == spec.instance_key,
              "角色视图应可查且 roleLabel 取 systemd 的 unit 名");
        std::optional<hng::role::RoleIdentity> identity =
            lookups.identity(role.value_or(0));
        CHECK(identity.has_value() && identity->instance_key == spec.instance_key,
              "身份应可查且实例键一致");
    }

    // ---- 真实 cgroup 重读：本进程应被归到那个角色 ----
    if (self && !own_members.empty()) {
        std::optional<uint32_t> real_role = lookups.lookup(specs[0].anchor);
        CHECK(real_role.has_value(), "走真实 cgroup 的角色应已加入");
        CHECK(lookups.lookup(*self).value_or(0) == real_role.value_or(0),
              "重读应把本进程归到该角色");
        std::printf("[verify] 真实 cgroup 重读枚举到 %zu 个进程（含本进程）\n",
                    own_members.size());
    }
    else {
        std::printf("[verify] 本进程 cgroup 不可读，跳过真实 IO 断言\n");
    }

    // ---- 经接口转交：fork 继承与进程退出 ----
    const hng::Process anchor0 = specs[0].anchor;
    const hng::Process moved = proc(anchor0.pid + 500000, anchor0.pid_start_time);
    const hng::Process child = proc(anchor0.pid + 500001, anchor0.pid_start_time);

    std::optional<uint32_t> role0 = lookups.lookup(anchor0);
    CHECK(role0.has_value(), "该角色应已加入");

    joins.bind_to_role(child, anchor0);  // 父已归属 → 子继承
    // 屏障：锚点更换排在 bind 之后，收到它的通知即说明 bind 已落地
    events.on_role_event(
        mk_event(RoleAction::MAIN_PROCESS_CHANGE, specs[0], moved));
    CHECK(sink.wait_counts(kRoles, 0, 1), "锚点更换通知应在时限内到齐");
    CHECK(lookups.lookup(child).value_or(0) == role0.value_or(0),
          "经接口转交的 fork 应继承父进程的角色");
    CHECK(lookups.lookup(moved).value_or(0) == role0.value_or(0),
          "锚点更换应保持 roleID");
    CHECK(lookups.lookup(anchor0).value_or(0) == role0.value_or(0),
          "旧锚点条目应仍在（清理由进程退出通知负责）");

    exits.on_process_exited(child);
    exits.on_process_exited(moved);
    // 屏障：换回原锚点
    events.on_role_event(
        mk_event(RoleAction::MAIN_PROCESS_CHANGE, specs[0], anchor0));
    CHECK(sink.wait_counts(kRoles, 0, 2), "第二次锚点更换通知应在时限内到齐");
    CHECK(!lookups.lookup(child).has_value(), "进程退出后不得有归属残留");
    CHECK(!lookups.lookup(moved).has_value(), "退出的锚点不得有归属残留");
    CHECK(lookups.lookup(anchor0).value_or(0) == role0.value_or(0),
          "换回原锚点后仍应是同一角色");
    CHECK(lookups.role(role0.value_or(0)).has_value(),
          "锚点退出不改变角色存在性");

    // ---- 停止：先停发现器（均已 join）、再 stop()、最后 join 消费线程 ----
    for (const RoleSpec& spec : specs) {
        events.on_role_event(mk_event(RoleAction::LEAVE, spec, spec.anchor));
    }
    CHECK(sink.wait_counts(kRoles, kRoles, 2), "全部退出通知应在时限内到齐");
    CHECK(sink.alive_count() == 0, "下游基线应已清空");
    CHECK(sink.errors() == 0, "出口回调内反查应始终成立");

    for (const RoleSpec& spec : specs) {
        CHECK(!lookups.lookup(spec.anchor).has_value(), "退出后锚点应失配");
    }

    manager.stop();
    consumer.join();

    // ---- 异常态观测 ----
    RoleManagerStats stats = manager.stats();
    CHECK(stats.store.rejected == 0, "不应出现入口拒收");
    CHECK(stats.store.unknown_instance == 0, "不应出现未知实例键");
    CHECK(stats.store.owner_conflict == 0, "成员集不应冲突");
    CHECK(stats.store.anchors_removed == 0, "全部退出后锚点 gauge 应归零");
    CHECK(stats.queue_rejected == 0, "运行期不应出现入队被拒");
    CHECK(stats.bind_deferred == 0 && stats.bind_resolved == 0 &&
              stats.bind_rejected == 0 && stats.bind_expired == 0 &&
              stats.bind_ignored == 0,
          "正常路径不应出现 bind 暂存或丢弃");
    CHECK(stats.late_adopt_rejected == 0, "正常路径不应出现迟到 adopt");
    CHECK(stats.dead_member_rejected == 0 && stats.dead_anchor_rejected == 0,
          "未接存活视图时不应出现死亡过滤");
    CHECK(stats.tombstone_depth >= 2, "已退出进程应留墓碑");

    const uint64_t expected_empty =
        (self && !own_members.empty()) ? kRoles - 1 : kRoles;
    CHECK(stats.cgroup_read_empty == expected_empty,
          "读不到的 cgroup 次数应为「除真实路径外的角色数」");

    std::printf("[verify] 角色=%d 空读=%llu 归属冲突=%llu 未知实例键=%llu\n",
                kRoles, static_cast<unsigned long long>(stats.cgroup_read_empty),
                static_cast<unsigned long long>(stats.store.owner_conflict),
                static_cast<unsigned long long>(stats.store.unknown_instance));

    if (g_fail) {
        std::fprintf(stderr, "TOTAL FAILURES: %d\n", g_fail);
        return 1;
    }
    std::printf("ALL PASS\n");
    return 0;
}
