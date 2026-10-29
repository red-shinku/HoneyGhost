/**
 * @file cli_process_query_service.hpp
 * @brief 定义 CLIProcessQueryService，cli_service.proto 中
 * ProcessManagerService 的 handler
 * @author red-shinku
 * @date 2026.10.29
 */

#ifndef HNG_CLIPROCESSQUERYSERVICEHPP
#define HNG_CLIPROCESSQUERYSERVICEHPP

#include <proto/cli_service_service.usrv.pb.hpp>

#include "agent/cli_server/include/cli_server.hpp"

/**
 * @brief ProcessManagerService 的服务组件
 * @details 自身无状态，只把请求转给控制平面的只读查询接口。依赖取自 CLIServer
 * 组件，不与其他服务组件互相引用。
 * @note 须登记在 CLIServer 之后：服务组件在构造期经 FindComponent 取用后者
 */
class CLIProcessQueryService final
    : public hng::clisv::ProcessManagerServiceBase::Component {
   public:
    static constexpr std::string_view kName = "cli-process-service";

    CLIProcessQueryService(const userver::components::ComponentConfig& config,
                           const userver::components::ComponentContext& context);

    GetStatsResult GetStats(CallContext& context,
                            hng::clisv::PM_GetStatsRequest&& request) override;

   private:
    /// 指向 CLIServer 持有的依赖集合，存活期覆盖本组件
    const CLIServerDeps& deps_;
};

#endif  // HNG_CLIPROCESSQUERYSERVICEHPP
