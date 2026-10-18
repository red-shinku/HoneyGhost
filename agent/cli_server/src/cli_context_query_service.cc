/**
 * @file cli_context_query_service.cc
 * @brief CLIContextQueryService 各 handler 的实现
 * @author red-shinku
 * @date 2026.10.15
 */

#include "agent/cli_server/src/cli_context_query_service.hpp"

#include <userver/components/component_context.hpp>

#include "agent/cli_server/src/cli_server.hpp"
#include "agent/cli_server/src/query_handlers.hpp"

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
    // ContextManager 无按属性枚举的入口
    return hng::cli::Unimplemented(context.GetCallName(), "缺-4");
}

CLIContextQueryService::GetExtraCtxResult CLIContextQueryService::GetExtraCtx(
    CallContext& context, hng::clisv::CM_GetExtraCtxRequest&&)
{
    // ContextManager 无按属性枚举的入口
    return hng::cli::Unimplemented(context.GetCallName(), "缺-4");
}

CLIContextQueryService::GetProcessSetResult CLIContextQueryService::GetProcessSet(
    CallContext& context, hng::clisv::CM_GetProcessSetRequest&&)
{
    // 控制平面没有「某 context 的成员进程」入口，ToContextRootTable 是
    // Process→根 的索引，反查需另建索引
    return hng::cli::Unimplemented(context.GetCallName(), "缺-5");
}

CLIContextQueryService::GetStatsResult CLIContextQueryService::GetStats(
    CallContext& context, hng::clisv::CM_GetStatsRequest&&)
{
    // ContextManagerStats 只在具体类的私有头里，查询面未暴露
    return hng::cli::Unimplemented(context.GetCallName(), "缺-6");
}

CLIContextQueryService::WhichContextResult CLIContextQueryService::WhichContext(
    CallContext& context, hng::clisv::CM_WhichContextRequest&&)
{
    // 请求只带 pid，而 ContextLookupService::lookup 以 hng::Process（pid +
    // start_time）为键，控制平面尚无按 pid 反查的入口
    return hng::cli::Unimplemented(context.GetCallName(), "缺-8");
}
