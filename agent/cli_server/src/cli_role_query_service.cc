/**
 * @file cli_role_query_service.cc
 * @brief CLIRoleQueryService 各 handler 的实现
 * @author red-shinku
 * @date 2026.10.15
 */

#include "agent/cli_server/src/cli_role_query_service.hpp"

#include <algorithm>
#include <cstdint>
#include <optional>
#include <unordered_set>
#include <vector>

#include <userver/components/component_context.hpp>
#include <userver/engine/async.hpp>
#include <userver/engine/task/current_task.hpp>
#include <userver/ugrpc/server/exceptions.hpp>

#include "agent/cli_server/src/cli_server.hpp"
#include "agent/cli_server/src/query_handlers.hpp"
#include "agent/control_plane/include/context_service.hpp"
#include "agent/control_plane/include/process_service.hpp"
#include "agent/control_plane/include/role_service.hpp"

CLIRoleQueryService::CLIRoleQueryService(
    const userver::components::ComponentConfig& config,
    const userver::components::ComponentContext& context)
    : hng::clisv::RoleManagerServiceBase::Component(config, context),
      deps_(context.FindComponent<CLIServer>().server_deps())
{
}

CLIRoleQueryService::GetRolesResult CLIRoleQueryService::GetRoles(
    CallContext& context, hng::clisv::RM_GetRolesRequest&& request)
{
    return hng::cli::ToResult<hng::clisv::RM_GetRolesResponse>(
        context.GetCallName(), [&](hng::clisv::RM_GetRolesResponse& out) {
            if (deps_.role == nullptr) {
                throw userver::ugrpc::server::ErrorWithStatus(
                    grpc::StatusCode::FAILED_PRECONDITION,
                    "GetRoles: role lookup service is not installed");
            }

            std::vector<hng::Role> roles;
            switch (request.showoption()) {
                case hng::clisv::RM_SHOW_ALL:
                    roles = deps_.role->roles();
                    break;
                case hng::clisv::RM_SHOW_SUPERVISION:
                    roles = deps_.role->supervised_roles();
                    break;
                default:
                    throw userver::ugrpc::server::ErrorWithStatus(
                        grpc::StatusCode::INVALID_ARGUMENT,
                        "GetRoles: unknown show option");
            }

            for (const hng::Role& role : roles) {
                hng::clisv::role* item = out.add_r();
                item->set_roleid(role.roleID);
                item->set_rolelabel(role.roleLabel);
            }
        });
}

CLIRoleQueryService::GetProcessSetResult CLIRoleQueryService::GetProcessSet(
    CallContext& context, hng::clisv::RM_GetProcessSetRequest&& request)
{
    return hng::cli::ToResult<hng::clisv::RM_GetProcessSetResponse>(
        context.GetCallName(), [&](hng::clisv::RM_GetProcessSetResponse& out) {
            const uint32_t role_id = request.roleid();
            if (role_id == 0) {
                throw userver::ugrpc::server::ErrorWithStatus(
                    grpc::StatusCode::INVALID_ARGUMENT,
                    "GetProcessSet: roleID must be non-zero");
            }
            // 依赖为空说明装配方漏填，不是客户端错误
            if (deps_.role == nullptr) {
                throw userver::ugrpc::server::ErrorWithStatus(
                    grpc::StatusCode::FAILED_PRECONDITION,
                    "GetProcessSet: role lookup service is not installed");
            }
            // cgroup 实时重读是同步阻塞调用，故交给 blocking TP，避免占住主 TP
            // 的工作线程；调用方的取消与 deadline 不传给该子任务
            const std::vector<hng::Process> members =
                userver::engine::AsyncNoTracing(
                    userver::engine::current_task::GetBlockingTaskProcessor(),
                    [this, role_id] { return deps_.role->members(role_id); })
                    .Get();
            const std::optional<hng::Process> root =
                deps_.role->main_process(role_id);
            hng::cli::FillRoleProcessSet(root, members, out);
        });
}

CLIRoleQueryService::GetContextSetResult CLIRoleQueryService::GetContextSet(
    CallContext& context, hng::clisv::RM_GetContextSetRequest&& request)
{
    return hng::cli::ToResult<hng::clisv::RM_GetContextSetResponse>(
        context.GetCallName(), [&](hng::clisv::RM_GetContextSetResponse& out) {
            const uint32_t role_id = request.roleid();
            if (role_id == 0) {
                throw userver::ugrpc::server::ErrorWithStatus(
                    grpc::StatusCode::INVALID_ARGUMENT,
                    "GetContextSet: roleID must be non-zero");
            }
            if (deps_.role == nullptr || deps_.context == nullptr) {
                throw userver::ugrpc::server::ErrorWithStatus(
                    grpc::StatusCode::FAILED_PRECONDITION,
                    "GetContextSet: lookup services are not installed");
            }

            const std::vector<hng::Process> members =
                userver::engine::AsyncNoTracing(
                    userver::engine::current_task::GetBlockingTaskProcessor(),
                    [this, role_id] { return deps_.role->members(role_id); })
                    .Get();
            const std::optional<hng::Process> root =
                deps_.role->main_process(role_id);

            std::unordered_set<uint32_t> ids;
            const auto collect = [&](hng::Process p) {
                if (const auto id = deps_.context->lookup(p)) {
                    ids.insert(*id);
                }
                if (const auto id = deps_.context->lookup_extra(p)) {
                    ids.insert(*id);
                }
            };
            if (root) {
                collect(*root);
            }
            for (const hng::Process& p : members) {
                collect(p);
            }

            std::vector<uint32_t> sorted(ids.begin(), ids.end());
            std::sort(sorted.begin(), sorted.end());
            for (uint32_t id : sorted) {
                out.add_contextid(id);
            }
        });
}

CLIRoleQueryService::GetStatsResult CLIRoleQueryService::GetStats(
    CallContext& context, hng::clisv::RM_GetStatsRequest&&)
{
    return hng::cli::ToResult<hng::clisv::RM_GetStatsResponse>(
        context.GetCallName(), [&](hng::clisv::RM_GetStatsResponse& out) {
            if (deps_.role == nullptr) {
                throw userver::ugrpc::server::ErrorWithStatus(
                    grpc::StatusCode::FAILED_PRECONDITION,
                    "GetStats: role lookup service is not installed");
            }
            const RoleManagerStats stats = deps_.role->stats();
            out.set_rejected(stats.store.rejected);
            out.set_unknown_instance(stats.store.unknown_instance);
            out.set_owner_conflict(stats.store.owner_conflict);
            out.set_anchors_removed(stats.store.anchors_removed);
            out.set_cgroup_read_empty(stats.cgroup_read_empty);
            out.set_queue_rejected(stats.queue_rejected);
        });
}

CLIRoleQueryService::WhichRoleResult CLIRoleQueryService::WhichRole(
    CallContext& context, hng::clisv::RM_WhichRoleRequest&& request)
{
    return hng::cli::ToResult<hng::clisv::RM_WhichRoleResponse>(
        context.GetCallName(), [&](hng::clisv::RM_WhichRoleResponse& out) {
            const uint32_t pid = request.pid();
            if (pid == 0) {
                throw userver::ugrpc::server::ErrorWithStatus(
                    grpc::StatusCode::INVALID_ARGUMENT,
                    "WhichRole: pid must be non-zero");
            }
            if (deps_.process == nullptr || deps_.role == nullptr) {
                throw userver::ugrpc::server::ErrorWithStatus(
                    grpc::StatusCode::FAILED_PRECONDITION,
                    "WhichRole: lookup services are not installed");
            }

            const std::optional<hng::Process> process =
                deps_.process->resolve(pid);
            if (!process) {
                return;  // 查不到不是错误，roleID 保持未设置
            }
            if (const auto role_id = deps_.role->lookup(*process)) {
                out.set_roleid(*role_id);
            }
        });
}
