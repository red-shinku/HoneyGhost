/**
 * @file cli_process_query_service.cc
 * @brief CLIProcessQueryService 各 handler 的实现
 * @author red-shinku
 * @date 2026.10.29
 */

#include "agent/cli_server/src/cli_process_query_service.hpp"

#include <userver/components/component_context.hpp>
#include <userver/ugrpc/server/exceptions.hpp>

#include "agent/cli_server/src/cli_server.hpp"
#include "agent/cli_server/src/query_handlers.hpp"
#include "agent/control_plane/include/process_service.hpp"

CLIProcessQueryService::CLIProcessQueryService(
    const userver::components::ComponentConfig& config,
    const userver::components::ComponentContext& context)
    : hng::clisv::ProcessManagerServiceBase::Component(config, context),
      deps_(context.FindComponent<CLIServer>().server_deps())
{
}

CLIProcessQueryService::GetStatsResult CLIProcessQueryService::GetStats(
    CallContext& context, hng::clisv::PM_GetStatsRequest&&)
{
    return hng::cli::ToResult<hng::clisv::PM_GetStatsResponse>(
        context.GetCallName(), [&](hng::clisv::PM_GetStatsResponse& out) {
            if (deps_.process == nullptr) {
                throw userver::ugrpc::server::ErrorWithStatus(
                    grpc::StatusCode::FAILED_PRECONDITION,
                    "GetStats: process lookup service is not installed");
            }
            const ProcessManagerStats stats = deps_.process->stats();
            out.set_pid_reused(stats.pid_reused);
            out.set_stale_add(stats.stale_add);
            out.set_parent_missing(stats.parent_missing);
            out.set_tombstone_depth(stats.tombstone_depth);
        });
}
