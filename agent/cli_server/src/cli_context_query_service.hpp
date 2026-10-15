/**
 * @file cli_context_query_service.hpp
 * @brief 定义 CLIContextQueryService，cli_service.proto 中
 * ContextManagerService 的 handler
 * @author red-shinku
 * @date 2026.10.15
 */

#ifndef HNG_CLICONTEXTQUERYSERVICE_HPP
#define HNG_CLICONTEXTQUERYSERVICE_HPP

#include <proto/cli_service_service.usrv.pb.hpp>

#include "agent/cli_server/include/cli_server.hpp"

/**
 * @brief ContextManagerService 的服务组件
 * @details 自身无状态，只把请求转给控制平面的只读查询接口。依赖取自 CLIServer
 * 组件，不与其他服务组件互相引用。
 * @note 须登记在 CLIServer 之后：服务组件在构造期经 FindComponent 取用后者
 */
class CLIContextQueryService final
    : public hng::clisv::ContextManagerServiceBase::Component {
   public:
    static constexpr std::string_view kName = "cli-context-service";

    CLIContextQueryService(const userver::components::ComponentConfig& config,
                           const userver::components::ComponentContext& context);

    GetExcepCtxResult GetExcepCtx(
        CallContext& context,
        hng::clisv::CM_GetExcepCtxRequest&& request) override;

    GetExtraCtxResult GetExtraCtx(
        CallContext& context,
        hng::clisv::CM_GetExtraCtxRequest&& request) override;

    GetProcessSetResult GetProcessSet(
        CallContext& context,
        hng::clisv::CM_GetProcessSetRequest&& request) override;

    GetStatsResult GetStats(CallContext& context,
                            hng::clisv::CM_GetStatsRequest&& request) override;

    WhichContextResult WhichContext(
        CallContext& context,
        hng::clisv::CM_WhichContextRequest&& request) override;

   private:
    /// 指向 CLIServer 持有的依赖集合，存活期覆盖本组件
    /// @note 本服务的各 RPC 均因控制平面缺口未实现，故暂未取用
    const CLIServerDeps& deps_;
};

#endif  // HNG_CLICONTEXTQUERYSERVICE_HPP
