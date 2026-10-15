/**
 * @file cli_role_query_service.hpp
 * @brief 定义 CLIRoleQueryService，cli_service.proto 中 RoleManagerService 的
 * handler
 * @author red-shinku
 * @date 2026.10.15
 */

#ifndef HNG_CLIROLEQUERYSERVICE_HPP
#define HNG_CLIROLEQUERYSERVICE_HPP

#include <proto/cli_service_service.usrv.pb.hpp>

#include "agent/cli_server/include/cli_server.hpp"

/**
 * @brief RoleManagerService 的服务组件
 * @details 自身无状态，只把请求转给控制平面的只读查询接口。依赖取自 CLIServer
 * 组件，不与其他服务组件互相引用。
 * @note 须登记在 CLIServer 之后：服务组件在构造期经 FindComponent 取用后者
 */
class CLIRoleQueryService final
    : public hng::clisv::RoleManagerServiceBase::Component {
   public:
    static constexpr std::string_view kName = "cli-role-service";

    CLIRoleQueryService(const userver::components::ComponentConfig& config,
                        const userver::components::ComponentContext& context);

    GetRolesResult GetRoles(CallContext& context,
                            hng::clisv::RM_GetRolesRequest&& request) override;

    GetProcessSetResult GetProcessSet(
        CallContext& context,
        hng::clisv::RM_GetProcessSetRequest&& request) override;

    GetContextSetResult GetContextSet(
        CallContext& context,
        hng::clisv::RM_GetContextSetRequest&& request) override;

    GetStatsResult GetStats(CallContext& context,
                            hng::clisv::RM_GetStatsRequest&& request) override;

    WhichRoleResult WhichRole(CallContext& context,
                              hng::clisv::RM_WhichRoleRequest&& request) override;

   private:
    /// 指向 CLIServer 持有的依赖集合，存活期覆盖本组件
    const CLIServerDeps& deps_;
};

#endif  // HNG_CLIROLEQUERYSERVICE_HPP
