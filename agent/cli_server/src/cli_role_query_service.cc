/**
 * @file cli_role_query_service.cc
 * @brief CLIRoleQueryService 各 handler 的实现
 * @author red-shinku
 * @date 2026.10.15
 */

#include "agent/cli_server/src/cli_role_query_service.hpp"

#include <cstdint>
#include <string_view>
#include <vector>

#include <userver/components/component_context.hpp>
#include <userver/engine/async.hpp>
#include <userver/engine/task/current_task.hpp>
#include <userver/ugrpc/server/exceptions.hpp>

#include "agent/cli_server/src/cli_server.hpp"
#include "agent/cli_server/src/query_handlers.hpp"
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
    // 两个分支的数据源都未落地：角色表没有枚举入口，监管名单策略未定义
    const std::string_view gap =
        request.showoption() == hng::clisv::RM_SHOW_SUPERVISION ? "缺-2" : "缺-1";
    return hng::cli::Unimplemented(context.GetCallName(), gap);
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
            // cgroup 实时重读是同步阻塞调用，故交给 blocking TP，避免占住主 TP
            // 的工作线程；调用方的取消与 deadline 不传给该子任务
            const std::vector<hng::Process> members =
                userver::engine::AsyncNoTracing(
                    userver::engine::current_task::GetBlockingTaskProcessor(),
                    [this, role_id] { return deps_.role->members(role_id); })
                    .Get();
            hng::cli::FillRoleProcessSet(members, out);
        });
}

CLIRoleQueryService::GetContextSetResult CLIRoleQueryService::GetContextSet(
    CallContext& context, hng::clisv::RM_GetContextSetRequest&&)
{
    // context 与 role 的关联无人维护
    return hng::cli::Unimplemented(context.GetCallName(), "缺-3");
}

CLIRoleQueryService::GetStatsResult CLIRoleQueryService::GetStats(
    CallContext& context, hng::clisv::RM_GetStatsRequest&&)
{
    // RoleManagerStats 只在具体类的私有头里，查询面未暴露
    return hng::cli::Unimplemented(context.GetCallName(), "缺-6");
}

CLIRoleQueryService::WhichRoleResult CLIRoleQueryService::WhichRole(
    CallContext& context, hng::clisv::RM_WhichRoleRequest&&)
{
    // 请求只带 pid，而 RoleLookupService::lookup 以 hng::Process（pid +
    // start_time）为键，控制平面尚无按 pid 反查的入口
    return hng::cli::Unimplemented(context.GetCallName(), "缺-8");
}
