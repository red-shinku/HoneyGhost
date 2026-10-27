/**
 * @file initialization_coordinator.cc
 * @brief 初始化协调器与四个初始化器的实现
 * @author red_shinku
 * @date 2026.10.25
 */

#include "agent/assembly/include/initialization_coordinator.hpp"

#include "agent/assembly/src/initializers.hpp"
#include "agent/control_plane/include/context_component.hpp"
#include "agent/control_plane/include/process_component.hpp"
#include "agent/control_plane/include/role_component.hpp"
#include "agent/context_maintainer/include/context_maintainer.hpp"
#include "agent/role_discovery/include/role_source_barrier.hpp"
#include "agent/role_filter/include/role_filter_component.hpp"
#include "agent/util/include/log.hpp"

#include <chrono>
#include <cstdint>

namespace hng {

namespace {

/// @brief 状态严重度：数值越大越优先
int severity(InitState state)
{
    switch (state) {
        case InitState::INITIALIZING:
            return 0;
        case InitState::READY:
            return 1;
        case InitState::DEGRADED:
            return 2;
        case InitState::PARTIAL:
            return 3;
        case InitState::UNAVAILABLE:
            return 4;
        case InitState::FAILED:
            return 5;
    }
    return 0;
}

/// @brief 两个时间点之间的毫秒数
int64_t elapsed_ms(std::chrono::steady_clock::time_point begin,
                   std::chrono::steady_clock::time_point end)
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(end - begin)
        .count();
}

}  // namespace

InitState merge_init_state(InitState lhs, InitState rhs)
{
    return severity(lhs) >= severity(rhs) ? lhs : rhs;
}

const char* to_string(InitState state)
{
    switch (state) {
        case InitState::INITIALIZING:
            return "INITIALIZING";
        case InitState::READY:
            return "READY";
        case InitState::DEGRADED:
            return "DEGRADED";
        case InitState::PARTIAL:
            return "PARTIAL";
        case InitState::UNAVAILABLE:
            return "UNAVAILABLE";
        case InitState::FAILED:
            return "FAILED";
    }
    return "UNKNOWN";
}

// ============================================================
// 初始化器
// ============================================================

ProcessInitializer::ProcessInitializer(ProcessComponent& component,
                                       const ProcessSeedBatch& batch)
    : component_(component), batch_(batch)
{
}

void ProcessInitializer::run()
{
    report_ = component_.seed_service().seed(batch_);
}

const ProcessSeedReport& ProcessInitializer::report() const noexcept
{
    return report_;
}

ContextInitializer::ContextInitializer(ContextComponent& component,
                                       ::ContextMaintainer& maintainer,
                                       const ProcessSeedBatch& batch)
    : component_(component), maintainer_(maintainer), batch_(batch)
{
}

void ContextInitializer::run()
{
    const ContextSeedPlan plan = maintainer_.build_seed_plan(batch_);
    HNG_LOG_DEBUG("context seed plan: {} entries", plan.entries.size());
    report_ = component_.seed_service().seed(plan);
}

const ContextSeedReport& ContextInitializer::report() const noexcept
{
    return report_;
}

RoleInitializer::RoleInitializer(RoleComponent& component,
                                 const ProcessSeedBatch& batch)
    : component_(component), batch_(batch)
{
}

void RoleInitializer::run()
{
    component_.drain();
    report_ = component_.seed_service().reconcile(batch_);
}

const RoleReconcileReport& RoleInitializer::report() const noexcept
{
    return report_;
}

RoleFilterInitializer::RoleFilterInitializer(RoleFilterComponent* filter)
    : filter_(filter)
{
}

void RoleFilterInitializer::run()
{
    if (filter_ == nullptr) {
        return;
    }
    filter_->seed_initial_roles();
    report_ = filter_->stats();
}

const RoleFilterStats& RoleFilterInitializer::report() const noexcept
{
    return report_;
}

// ============================================================
// 协调器
// ============================================================

InitializationCoordinator::InitializationCoordinator(
    ProcessComponent& process, ContextComponent& context, RoleComponent& role,
    ::ContextMaintainer& maintainer, RoleFilterComponent* role_filter,
    ::RoleSourceBarrier* role_barrier, InitializationOptions options)
    : process_(process),
      context_(context),
      role_(role),
      maintainer_(maintainer),
      role_filter_(role_filter),
      role_barrier_(role_barrier),
      options_(options)
{
}

InitReport InitializationCoordinator::run(const ProcessSnapshot& snapshot)
{
    InitReport report;
    InitState state        = InitState::READY;
    const auto total_start = std::chrono::steady_clock::now();

    HNG_LOG_INFO("initialization start");

    // 1. 角色源屏障：不可用与超时都降级继续，只有超时单独计数
    if (role_barrier_ != nullptr) {
        const auto barrier_start = std::chrono::steady_clock::now();
        const bool barrier_ready =
            role_barrier_->wait(options_.role_source_timeout);
        if (!barrier_ready) {
            state = merge_init_state(state, InitState::DEGRADED);
            if (role_barrier_->timed_out()) {
                report.role_source_timeout = 1;
            }
            if (report.role_source_timeout != 0) {
                HNG_LOG_WARN(
                    "role source barrier timed out after {} ms; continuing",
                    options_.role_source_timeout.count());
            }
            else {
                HNG_LOG_WARN("role source barrier unavailable; continuing");
            }
        }
        else {
            HNG_LOG_INFO(
                "role source barrier ready (waited {} ms)",
                elapsed_ms(barrier_start, std::chrono::steady_clock::now()));
        }
    }

    // 2. 发现器只入队，初始化写入前先同步落地初始角色事件
    const auto role_drain_start = std::chrono::steady_clock::now();
    role_.drain();
    HNG_LOG_DEBUG("phase drain initial role events: {} ms",
                  elapsed_ms(role_drain_start, std::chrono::steady_clock::now()));

    // 3. 初始名单须在探针挂载前写入过滤 map，此时只依赖已落地的角色
    if (role_filter_ != nullptr) {
        const uint64_t applied_before = role_filter_->stats().applied_processes;
        const auto seed_start         = std::chrono::steady_clock::now();
        RoleFilterInitializer filter_initializer(role_filter_);
        filter_initializer.run();
        const RoleFilterStats& filter_report = filter_initializer.report();
        HNG_LOG_DEBUG("phase role filter seed: {} ms",
                      elapsed_ms(seed_start, std::chrono::steady_clock::now()));
        HNG_LOG_DEBUG("role filter seed delta: processes {}",
                      static_cast<int64_t>(filter_report.applied_processes) -
                          static_cast<int64_t>(applied_before));
    }

    // 4. /proc 不可用时以空且不完整的批继续，角色与名单照常推进
    report.snapshot = snapshot.anomalies;
    ProcessSeedBatch empty_batch;
    empty_batch.complete = false;
    const ProcessSeedBatch& batch =
        snapshot.anomalies.proc_available ? snapshot.batch : empty_batch;
    if (!snapshot.anomalies.proc_available) {
        state = merge_init_state(state, InitState::UNAVAILABLE);
        HNG_LOG_WARN("/proc unavailable; continuing with an empty snapshot");
    }
    else if (!batch.complete) {
        state = merge_init_state(state, InitState::PARTIAL);
        HNG_LOG_WARN("snapshot incomplete (processes read: {}); continuing",
                     batch.entries.size());
    }
    HNG_LOG_INFO("snapshot processes: {}", batch.entries.size());
    HNG_LOG_DEBUG(
        "snapshot anomalies: seen {}, zombies {}, kthreads {}, "
        "stat failures {}, exe unreadable {}, parents missing {}",
        report.snapshot.proc_seen, report.snapshot.zombie_skipped,
        report.snapshot.kthread_skipped, report.snapshot.stat_parse_failed,
        report.snapshot.exe_unreadable, report.snapshot.parent_missing);
    // 对账被跳过（PM seed 失败）时报告仍应反映本批是否完整
    report.role.snapshot_complete = batch.complete;

    // 5. PM seed：被拒表示组件已不处于 CONSTRUCTED，初始化不能继续
    ProcessInitializer process_initializer(process_, batch);
    const auto process_seed_start = std::chrono::steady_clock::now();
    process_initializer.run();
    report.process = process_initializer.report();
    HNG_LOG_DEBUG(
        "phase process seed: {} ms",
        elapsed_ms(process_seed_start, std::chrono::steady_clock::now()));
    HNG_LOG_INFO(
        "process seed: inserted {}, duplicate {}, pid reused {}, "
        "parent missing {}, invalid {}",
        report.process.inserted, report.process.duplicate,
        report.process.pid_reused, report.process.parent_missing,
        report.process.invalid);
    bool failed = report.process.rejected_state != 0;
    if (failed) {
        HNG_LOG_ERROR(
            "process seed rejected: component is not CONSTRUCTED "
            "(rejected calls: {}); initialization failed",
            report.process.rejected_state);
    }

    // 6. 角色对账：drain 落地初始事件后再清理幽灵、补绑定与重读 cgroup
    if (!failed) {
        RoleInitializer role_initializer(role_, batch);
        const auto reconcile_start = std::chrono::steady_clock::now();
        role_initializer.run();
        report.role = role_initializer.report();
        HNG_LOG_DEBUG(
            "phase role reconcile: {} ms",
            elapsed_ms(reconcile_start, std::chrono::steady_clock::now()));
        HNG_LOG_INFO(
            "role reconcile: ownership entries {}, pruned {}, "
            "bind adopted {}, ignored {}, roles resynced {}",
            report.role.ownership_entries, report.role.pruned,
            report.role.bind_adopted, report.role.bind_ignored,
            report.role.roles_resynced);
        if (report.role.proc_unknown > 0) {
            HNG_LOG_WARN("ownership entries kept with unknown liveness: {}",
                         report.role.proc_unknown);
        }
        if (report.role.cgroup_read_empty > 0) {
            HNG_LOG_WARN("roles with empty members on cgroup re-read: {}",
                         report.role.cgroup_read_empty);
        }
        failed = report.role.rejected_state != 0;
        if (failed) {
            HNG_LOG_ERROR(
                "role reconcile rejected: component is not CONSTRUCTED "
                "(rejected calls: {}); initialization failed",
                report.role.rejected_state);
        }
    }

    // 7. 应用对账产生的角色与成员通知
    if (!failed && role_filter_ != nullptr) {
        const auto filter_drain_start = std::chrono::steady_clock::now();
        role_filter_->drain();
        HNG_LOG_DEBUG(
            "phase drain role filter notifications: {} ms",
            elapsed_ms(filter_drain_start, std::chrono::steady_clock::now()));
        const RoleFilterStats filter_stats = role_filter_->stats();
        HNG_LOG_INFO(
            "role filter: roles {}, processes applied {}, empty members {}",
            filter_stats.roles, filter_stats.applied_processes,
            filter_stats.empty_members);
    }

    // 8. context 计划与 seed：乱序、非法或状态被拒都视为启动失败
    if (!failed) {
        ContextInitializer context_initializer(context_, maintainer_, batch);
        const auto context_seed_start = std::chrono::steady_clock::now();
        context_initializer.run();
        report.context = context_initializer.report();
        HNG_LOG_DEBUG(
            "phase context seed: {} ms",
            elapsed_ms(context_seed_start, std::chrono::steady_clock::now()));
        HNG_LOG_INFO(
            "context seed: inserted {}, bound to parent {}, duplicate {}",
            report.context.inserted, report.context.bound,
            report.context.duplicate);
        const ContextSeedReport& context_report = report.context;
        failed = context_report.rejected_state != 0 ||
                 context_report.rejected_out_of_order != 0 ||
                 context_report.rejected_invalid != 0;
        if (failed) {
            HNG_LOG_ERROR(
                "context seed rejected: state {}, out of order {}, "
                "invalid {}; initialization failed",
                context_report.rejected_state,
                context_report.rejected_out_of_order,
                context_report.rejected_invalid);
        }
    }

    // 9. 名单统计：map 写入失败只降级，后续刷新会重试
    if (role_filter_ != nullptr) {
        report.role_filter = role_filter_->stats();
        if (report.role_filter.map_errors > 0) {
            state = merge_init_state(state, InitState::DEGRADED);
            HNG_LOG_WARN(
                "role filter map writes failed {} times (last errno {}); "
                "degraded",
                report.role_filter.map_errors, report.role_filter.last_map_error);
        }
    }

    // 10. 初始化期丢事件计数尚未接入，先固定为 0
    report.dropped_events = 0;

    if (failed) {
        state = merge_init_state(state, InitState::FAILED);
    }
    report.state = state;
    const int64_t total_ms =
        elapsed_ms(total_start, std::chrono::steady_clock::now());
    switch (state) {
        case InitState::FAILED:
            HNG_LOG_ERROR("initialization finished: state {}, {} ms",
                          to_string(state), total_ms);
            break;
        case InitState::READY:
            HNG_LOG_INFO("initialization finished: state {}, {} ms",
                         to_string(state), total_ms);
            break;
        case InitState::DEGRADED:
        case InitState::PARTIAL:
        case InitState::UNAVAILABLE:
            HNG_LOG_WARN("initialization finished: state {}, {} ms",
                         to_string(state), total_ms);
            break;
        case InitState::INITIALIZING:
            break;
    }
    return report;
}

}  // namespace hng
