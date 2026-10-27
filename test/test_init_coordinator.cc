/**
 * @file test_init_coordinator.cc
 * @brief 初始化协调器与报告的集成测试
 * @details
 * 覆盖阶段 5 的装配顺序（不含组件线程启动）：
 *  - 正常路径：源屏障就绪、初始角色落地、PM/CM/RM 写入一致、Child 继承角色、
 *    名单包含锚点与子进程；
 *  - /proc 不可用：以空且不完整的批继续，角色与名单照常推进；
 *  - 部分快照：已读进程照常 seed，角色对账跳过幽灵清理；
 *  - 角色源不可用与超时：降级继续，只有超时计数；
 *  - 初始化写入被拒：总状态 FAILED，后续步骤不再执行也不抛异常；
 *  - map 写入失败：降级但名单仍就绪，后续刷新重试；
 *  - 状态聚合优先级。
 * @note 全程使用手工快照与假 map/probe，不依赖 /proc、cgroup 与 eBPF，也不启动
 *       任何组件线程。
 * @author red_shinku
 * @date 2026.10.25
 */

#include "agent/assembly/include/initialization_coordinator.hpp"

#include "agent/context_maintainer/include/context_maintainer.hpp"
#include "agent/control_plane/include/context_component.hpp"
#include "agent/control_plane/include/control_plane_factory.hpp"
#include "agent/control_plane/include/process_component.hpp"
#include "agent/control_plane/include/role_component.hpp"
#include "agent/event_data/include/process_seed.hpp"
#include "agent/role_discovery/include/role_source_barrier.hpp"
#include "agent/role_filter/include/role_filter_component.hpp"
#include "agent/role_filter/include/role_filter_config.hpp"
#include "agent/role_filter/include/role_filter_factory.hpp"
#include "agent/role_filter/include/role_filter_policy.hpp"

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <system_error>
#include <unordered_set>
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

/// 记录写入结果的 map 后端；可让最初若干次 allow 失败
class FakeMap final : public hng::ProcessFilterMap {
   public:
    std::error_code allow(hng::Process process) noexcept override
    {
        if (allow_failures > 0) {
            --allow_failures;
            return std::make_error_code(std::errc::io_error);
        }
        values.insert(process);
        return {};
    }

    std::error_code erase(hng::Process process) noexcept override
    {
        values.erase(process);
        return {};
    }

    std::unordered_set<hng::Process> values;
    int allow_failures = 0;  ///< 剩余失败次数
};

hng::Process proc(uint32_t pid, uint64_t start)
{
    return hng::Process{pid, start};
}

hng::ProcessSeedEntry seed_entry(uint32_t pid, uint64_t start, uint32_t ppid,
                                 uint64_t ppid_start, std::string exe)
{
    hng::ProcessSeedEntry entry;
    entry.process         = proc(pid, start);
    entry.ppid            = ppid;
    entry.ppid_start_time = ppid_start;
    entry.exe             = std::move(exe);
    return entry;
}

/// 根 100 与子 101 的正常快照
hng::ProcessSnapshot make_snapshot()
{
    hng::ProcessSnapshot snapshot;
    snapshot.batch.entries.push_back(seed_entry(100, 1000, 0, 0, "/sbin/init"));
    snapshot.batch.entries.push_back(
        seed_entry(101, 1001, 100, 1000, "/usr/bin/grep"));
    return snapshot;
}

/**
 * @brief 测试装配：真实组件 + 假 map/probe，不启动线程
 * @details 完成阶段 0 的接线：注入 context 服务、把 RoleFilterComponent
 *          注册为角色生命周期出口；不做 seed/reconcile。
 */
struct Harness {
    std::unique_ptr<hng::ProcessComponent> process;
    std::unique_ptr<hng::ContextComponent> context;
    std::unique_ptr<hng::RoleComponent> role;
    ContextMaintainer maintainer;
    FakeMap* map_view = nullptr;
    std::unique_ptr<hng::RoleFilterComponent> filter;
    RoleSourceBarrier barrier;

    explicit Harness(hng::RoleComponentOptions role_options = {})
    {
        process = hng::ControlPlaneFactory::create_process();
        context = hng::ControlPlaneFactory::create_context();
        role    = hng::ControlPlaneFactory::create_role(std::move(role_options));
        maintainer.set_context_service(&context->lookup_service(),
                                       &context->join_service(),
                                       &context->update_service());
        auto map = std::make_unique<FakeMap>();
        map_view = map.get();
        std::istringstream input("[whitelist]\nexact: nginx.service\n");
        hng::RoleFilterComponentOptions options;
        options.lookup      = &role->lookup_service();
        options.supervision = &role->supervision_service();
        options.policy =
            hng::RoleFilterPolicy(hng::parse_role_filter_config(input));
        options.map                     = std::move(map);
        options.filter_options.liveness = [](hng::Process) {
            return hng::ProcessLiveness::ALIVE;
        };
        filter = hng::RoleFilterFactory::create(std::move(options));
        role->add_lifecycle_sink(&filter->lifecycle_sink());
    }
};

void deliver_join(Harness& harness, const std::string& instance_key,
                  hng::Process anchor, std::vector<hng::Process> members = {})
{
    hng::role::RoleEvent event;
    event.action                        = hng::role::RoleAction::JOIN;
    event.payload.identity.source       = hng::role::RoleSource::SYSTEMD;
    event.payload.identity.instance_key = instance_key;
    event.payload.identity.type_key     = "nginx";
    event.payload.main_process          = anchor;
    event.payload.cgroup_path           = "/test";
    event.payload.member_processes      = std::move(members);
    harness.role->event_sink().on_role_event(event);
}

hng::InitReport run_coordinator(Harness& harness,
                                const hng::ProcessSnapshot& snapshot,
                                hng::InitializationOptions options = {},
                                bool wait_sources                  = false)
{
    hng::InitializationCoordinator coordinator(
        *harness.process, *harness.context, *harness.role, harness.maintainer,
        harness.filter.get(), wait_sources ? &harness.barrier : nullptr, options);
    return coordinator.run(snapshot);
}

// ---- 正常路径 ----
void run_ready_path()
{
    Harness harness;
    const hng::Process root{100, 1000};
    const hng::Process child{101, 1001};
    hng::ProcessSnapshot snapshot = make_snapshot();

    deliver_join(harness, "nginx.service", root, {root});
    harness.barrier.expect(hng::role::RoleSource::SYSTEMD);
    harness.barrier.ready(hng::role::RoleSource::SYSTEMD, true);

    const hng::InitReport report = run_coordinator(harness, snapshot, {}, true);

    CHECK(report.state == hng::InitState::READY, "正常路径应为 READY");
    CHECK(report.role_source_timeout == 0, "源就绪不得计超时");
    CHECK(report.process.inserted == 2, "PM 应插入快照中的两个进程");

    CHECK(report.role.rejected_state == 0, "RM 对账不得被拒");
    CHECK(report.role.bind_adopted == 1, "子进程应被补绑定到父角色");
    const std::optional<uint32_t> anchor_role =
        harness.role->lookup_service().lookup(root);
    CHECK(anchor_role.has_value(), "锚点应有角色归属");
    CHECK(harness.role->lookup_service().lookup(child) == anchor_role,
          "子进程应继承父角色");

    CHECK(harness.process->lookup_service().lookup(root).has_value(),
          "PM 查询应可见根进程");
    CHECK(harness.process->lookup_service().lookup(child).has_value(),
          "PM 查询应可见子进程");

    CHECK(report.context.rejected_state == 0, "CM seed 不得被拒");
    CHECK(report.context.inserted == 2, "两个进程都应各自派生 context");
    CHECK(harness.context->lookup_service().lookup(root).has_value(),
          "CM 查询应可见根进程");
    CHECK(harness.context->lookup_service().lookup(child).has_value(),
          "CM 查询应可见子进程");

    CHECK(report.role_filter.roles == 1, "名单应记录一个角色");
    CHECK(report.role_filter.applied_processes == 2, "锚点与子进程都应进入名单");
    CHECK(harness.map_view->values.count(root) == 1, "map 应含锚点");
    CHECK(harness.map_view->values.count(child) == 1, "map 应含子进程");
    CHECK(harness.filter->state() == hng::ComponentState::READY,
          "名单播种后应为 READY");
    CHECK(report.dropped_events == 0, "丢事件计数当前固定为 0");
}

// ---- /proc 不可用：空状态继续 ----
void run_unavailable_path()
{
    Harness harness;
    const hng::Process root{100, 1000};
    hng::ProcessSnapshot snapshot;
    snapshot.anomalies.proc_available = false;
    deliver_join(harness, "nginx.service", root, {root});

    const hng::InitReport report = run_coordinator(harness, snapshot);

    CHECK(report.state == hng::InitState::UNAVAILABLE, "应降为 UNAVAILABLE");
    CHECK(!report.snapshot.proc_available, "报告应反映 /proc 不可用");
    CHECK(report.process.inserted == 0, "PM 应以空批 seed");
    CHECK(!harness.process->lookup_service().lookup(root).has_value(),
          "PM 不应有初始进程");
    CHECK(!harness.context->lookup_service().lookup(root).has_value(),
          "CM 不应有初始 context");
    CHECK(report.context.inserted == 0, "空批不应派生 context");
    CHECK(report.role.rejected_state == 0, "空的不完整批对账不得被拒");
    CHECK(!report.role.snapshot_complete, "对账应记录快照不完整");
    CHECK(harness.role->state() == hng::ComponentState::READY,
          "角色仍应完成初始化");
    CHECK(harness.context->state() == hng::ComponentState::READY,
          "context 仍应完成初始化");
    CHECK(harness.map_view->values.count(root) == 1, "角色过滤仍应照常播种");
}

// ---- 部分快照：照常 seed，跳过幽灵清理 ----
void run_partial_path()
{
    const hng::Process root{100, 1000};
    const hng::Process ghost{999, 9999};
    hng::RoleComponentOptions options;
    options.is_exited = [](hng::Process p) { return p.pid == 999; };
    Harness harness(std::move(options));

    deliver_join(harness, "nginx.service", root, {root});
    harness.role->join_service().bind_to_role(ghost, root);

    hng::ProcessSnapshot snapshot = make_snapshot();
    snapshot.batch.complete       = false;

    const hng::InitReport report  = run_coordinator(harness, snapshot);

    CHECK(report.state == hng::InitState::PARTIAL, "应降为 PARTIAL");
    CHECK(report.snapshot.proc_available, "报告快照应标为可用");
    CHECK(!report.role.snapshot_complete, "对账应记录快照不完整");
    CHECK(report.process.inserted == 2, "已读进程应照常 seed");
    CHECK(harness.process->lookup_service().lookup(root).has_value(),
          "PM 应含已读根进程");
    CHECK(report.role.pruned == 0, "不完整快照不得清理幽灵");
    CHECK(harness.role->lookup_service().lookup(ghost).has_value(),
          "幽灵成员应保留");
    CHECK(harness.role->lookup_service().lookup(proc(101, 1001)).has_value(),
          "快照内子进程仍应完成补绑定");
}

// ---- 角色源不可用 ----
void run_source_unavailable_path()
{
    Harness harness;
    harness.barrier.expect(hng::role::RoleSource::SYSTEMD);
    harness.barrier.ready(hng::role::RoleSource::SYSTEMD, false);

    const hng::InitReport report =
        run_coordinator(harness, make_snapshot(), {}, true);

    CHECK(report.state == hng::InitState::DEGRADED, "源不可用应降级");
    CHECK(report.role_source_timeout == 0, "源不可用不置超时计数");
    CHECK(report.process.inserted == 2, "降级后仍应 seed 已读进程");
}

// ---- 角色源超时 ----
void run_source_timeout_path()
{
    Harness harness;
    harness.barrier.expect(hng::role::RoleSource::SYSTEMD);

    hng::InitializationOptions options;
    options.role_source_timeout = std::chrono::milliseconds(1);
    const hng::InitReport report =
        run_coordinator(harness, make_snapshot(), options, true);

    CHECK(report.state == hng::InitState::DEGRADED, "源超时应降级");
    CHECK(report.role_source_timeout == 1, "源超时应置计数");
    CHECK(report.process.inserted == 2, "降级后仍应 seed 已读进程");
}

// ---- 初始化写入被拒：FAILED 且后续步骤不执行 ----
void run_failed_path()
{
    Harness harness;
    const ProcessSeedReport preseed =
        harness.process->seed_service().seed(hng::ProcessSeedBatch{});
    CHECK(preseed.rejected_state == 0, "预置 seed 不应被拒");

    const hng::InitReport report = run_coordinator(harness, make_snapshot());

    CHECK(report.state == hng::InitState::FAILED, "重复 seed 应为 FAILED");
    CHECK(report.process.rejected_state == 1, "报告应记录被拒的 seed");
    CHECK(report.process.inserted == 0, "被拒的 seed 不得插入");
    CHECK(harness.role->state() == hng::ComponentState::CONSTRUCTED,
          "FAILED 后不得再对账角色");
    CHECK(harness.context->state() == hng::ComponentState::CONSTRUCTED,
          "FAILED 后不得再 seed context");
}

// ---- map 写入失败：降级但名单仍就绪 ----
void run_map_error_path()
{
    Harness harness;
    const hng::Process root{100, 1000};
    harness.map_view->allow_failures = 1;
    deliver_join(harness, "nginx.service", root, {root});

    const hng::InitReport report = run_coordinator(harness, make_snapshot());

    CHECK(report.state == hng::InitState::DEGRADED, "map 写入失败应降级");
    CHECK(report.role_filter.map_errors > 0, "报告应记录 map 错误");
    CHECK(harness.filter->state() == hng::ComponentState::READY,
          "map 失败不应阻止名单就绪");
    CHECK(harness.map_view->values.count(root) == 1, "后续刷新应重试成功");
    CHECK(harness.map_view->values.count(proc(101, 1001)) == 1,
          "子进程仍应进入名单");
}

// ---- 状态聚合优先级 ----
void run_merge_priority()
{
    using hng::InitState;
    using hng::merge_init_state;
    CHECK(merge_init_state(InitState::READY, InitState::INITIALIZING) ==
              InitState::READY,
          "READY 高于 INITIALIZING");
    CHECK(merge_init_state(InitState::READY, InitState::DEGRADED) ==
              InitState::DEGRADED,
          "DEGRADED 高于 READY");
    CHECK(merge_init_state(InitState::DEGRADED, InitState::PARTIAL) ==
              InitState::PARTIAL,
          "PARTIAL 高于 DEGRADED");
    CHECK(merge_init_state(InitState::PARTIAL, InitState::UNAVAILABLE) ==
              InitState::UNAVAILABLE,
          "UNAVAILABLE 高于 PARTIAL");
    CHECK(merge_init_state(InitState::UNAVAILABLE, InitState::FAILED) ==
              InitState::FAILED,
          "FAILED 最高");
    CHECK(merge_init_state(InitState::FAILED, InitState::READY) ==
              InitState::FAILED,
          "合并与参数顺序无关");
    CHECK(merge_init_state(InitState::PARTIAL, InitState::DEGRADED) ==
              InitState::PARTIAL,
          "合并与参数顺序无关");
    CHECK(std::string(hng::to_string(InitState::DEGRADED)) == "DEGRADED",
          "状态名称应可读");
    CHECK(std::string(hng::to_string(InitState::UNAVAILABLE)) == "UNAVAILABLE",
          "状态名称应可读");
}

}  // namespace

int main()
{
    try {
        run_ready_path();
        run_unavailable_path();
        run_partial_path();
        run_source_unavailable_path();
        run_source_timeout_path();
        run_failed_path();
        run_map_error_path();
        run_merge_priority();
        if (g_fail != 0) {
            std::fprintf(stderr, "FAIL: %d checks failed\n", g_fail);
            return 1;
        }
        std::printf("PASS: initialization coordinator\n");
        return 0;
    }
    catch (const std::exception& error) {
        std::fprintf(stderr, "FAIL: %s\n", error.what());
        return 1;
    }
}
