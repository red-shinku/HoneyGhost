/**
 * @file cli_context_query_service.cc
 * @brief CLIContextQueryService 各 handler 的实现
 * @author red-shinku
 * @date 2026.10.15
 */

#include "agent/cli_server/src/cli_context_query_service.hpp"

#include <cstdint>
#include <optional>

#include <userver/components/component_context.hpp>
#include <userver/ugrpc/server/exceptions.hpp>

#include "agent/cli_server/src/cli_server.hpp"
#include "agent/cli_server/src/query_handlers.hpp"
#include "agent/control_plane/include/context_service.hpp"
#include "agent/control_plane/include/process_service.hpp"

CLIContextQueryService::CLIContextQueryService(
    const userver::components::ComponentConfig& config,
    const userver::components::ComponentContext& context)
    : hng::clisv::ContextManagerServiceBase::Component(config, context),
      deps_(context.FindComponent<CLIServer>().server_deps())
{
}

CLIContextQueryService::GetExcepCtxResult CLIContextQueryService::GetExcepCtx(
    CallContext& context, hng::clisv::CM_GetExcepCtxRequest&&)
{
    return hng::cli::ToResult<hng::clisv::CM_GetExcepCtxResponse>(
        context.GetCallName(), [&](hng::clisv::CM_GetExcepCtxResponse& out) {
            if (deps_.context == nullptr) {
                throw userver::ugrpc::server::ErrorWithStatus(
                    grpc::StatusCode::FAILED_PRECONDITION,
                    "GetExcepCtx: context lookup service is not installed");
            }
            for (uint32_t id :
                 deps_.context->contexts_by_attr(hng::contextattr::ATTACK)) {
                out.add_contextid(id);
            }
        });
}

CLIContextQueryService::GetExtraCtxResult CLIContextQueryService::GetExtraCtx(
    CallContext& context, hng::clisv::CM_GetExtraCtxRequest&&)
{
    return hng::cli::ToResult<hng::clisv::CM_GetExtraCtxResponse>(
        context.GetCallName(), [&](hng::clisv::CM_GetExtraCtxResponse& out) {
            if (deps_.context == nullptr) {
                throw userver::ugrpc::server::ErrorWithStatus(
                    grpc::StatusCode::FAILED_PRECONDITION,
                    "GetExtraCtx: context lookup service is not installed");
            }
            for (uint32_t id : deps_.context->contexts_by_attr(
                     hng::contextattr::EXTRA_ATTACK)) {
                out.add_contextid(id);
            }
        });
}

CLIContextQueryService::GetProcessSetResult CLIContextQueryService::GetProcessSet(
    CallContext& context, hng::clisv::CM_GetProcessSetRequest&& request)
{
    return hng::cli::ToResult<hng::clisv::CM_GetProcessSetResponse>(
        context.GetCallName(), [&](hng::clisv::CM_GetProcessSetResponse& out) {
            const uint32_t context_id = request.contextid();
            if (context_id == 0) {
                throw userver::ugrpc::server::ErrorWithStatus(
                    grpc::StatusCode::INVALID_ARGUMENT,
                    "GetProcessSet: contextID must be non-zero");
            }
            if (deps_.context == nullptr) {
                throw userver::ugrpc::server::ErrorWithStatus(
                    grpc::StatusCode::FAILED_PRECONDITION,
                    "GetProcessSet: context lookup service is not installed");
            }

            const std::optional<ContextProcessSet> set =
                deps_.context->members(context_id);
            if (!set) {
                return;  // 查不到不是错误，字段保持未设置
            }
            hng::cli::FillContextProcessSet(*set, out);
        });
}

CLIContextQueryService::GetStatsResult CLIContextQueryService::GetStats(
    CallContext& context, hng::clisv::CM_GetStatsRequest&&)
{
    return hng::cli::ToResult<hng::clisv::CM_GetStatsResponse>(
        context.GetCallName(), [&](hng::clisv::CM_GetStatsResponse& out) {
            if (deps_.context == nullptr) {
                throw userver::ugrpc::server::ErrorWithStatus(
                    grpc::StatusCode::FAILED_PRECONDITION,
                    "GetStats: context lookup service is not installed");
            }
            const ContextManagerStats stats = deps_.context->stats();
            out.set_ctxroot_parent_unsettled(stats.ctxroot_parent_unsettled);
            out.set_unknown_unregister(stats.unknown_unregister);
            out.set_pending_deferred(stats.pending_deferred);
            out.set_pending_resolved(stats.pending_resolved);
            out.set_pending_rejected(stats.pending_rejected);
            out.set_pending_expired(stats.pending_expired);
            out.set_pending_cancelled(stats.pending_cancelled);
            out.set_pending_depth(stats.pending_depth);
            out.set_bind_orphaned(stats.bind_orphaned);
            out.set_extra_orphaned(stats.extra_orphaned);
            out.set_parent_missing(stats.parent_missing);
            out.set_late_register(stats.late_register);
            out.set_late_bind(stats.late_bind);
            out.set_duplicate_context(stats.duplicate_context);
            out.set_ownership_conflict(stats.ownership_conflict);
            out.set_tombstone_hits(stats.tombstone_hits);
            out.set_tombstone_depth(stats.tombstone_depth);
        });
}

CLIContextQueryService::WhichContextResult CLIContextQueryService::WhichContext(
    CallContext& context, hng::clisv::CM_WhichContextRequest&& request)
{
    return hng::cli::ToResult<hng::clisv::CM_WhichContextResponse>(
        context.GetCallName(), [&](hng::clisv::CM_WhichContextResponse& out) {
            const uint32_t pid = request.pid();
            if (pid == 0) {
                throw userver::ugrpc::server::ErrorWithStatus(
                    grpc::StatusCode::INVALID_ARGUMENT,
                    "WhichContext: pid must be non-zero");
            }
            if (deps_.process == nullptr || deps_.context == nullptr) {
                throw userver::ugrpc::server::ErrorWithStatus(
                    grpc::StatusCode::FAILED_PRECONDITION,
                    "WhichContext: lookup services are not installed");
            }

            const std::optional<hng::Process> process =
                deps_.process->resolve(pid);
            if (!process) {
                return;  // 查不到不是错误，contextID 保持未设置
            }
            if (const auto context_id = deps_.context->lookup(*process)) {
                out.set_contextid(*context_id);
            }
        });
}
