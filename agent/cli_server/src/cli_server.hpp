/**
 * @file cli_server.hpp
 * @brief 定义 CLIServer，CLI 服务端模块的入口组件
 * @author red-shinku
 * @date 2026.10.15
 */
#ifndef HNG_CLISERVER_HPP_
#define HNG_CLISERVER_HPP_

#include <string_view>
#include <userver/components/component_base.hpp>

#include "agent/cli_server/include/cli_server.hpp"
#include "agent/cli_server/src/cli_stream_manager.hpp"

/**
 * @brief 模块入口组件：持有装配方注入的依赖与流管理器，供各服务组件取用
 * @details socket 与 TaskProcessor 由框架组件按静态配置创建，本组件不持。
 * 依赖由 InstallCliServerDeps 写入，本组件在构造期取出。
 */
class CLIServer final : public userver::components::ComponentBase {
   public:
    static constexpr std::string_view kName = "cli-server";

    CLIServer(const userver::components::ComponentConfig&,
              const userver::components::ComponentContext&);

    /// @return 流管理器
    /// @note 服务组件在构造期取用；本组件的存活期覆盖全部服务组件
    CLIStreamManager& stream_manager();

    /// @return 装配方注入的依赖集合
    const CLIServerDeps& server_deps() const;

   private:
    /// 装配方注入的依赖；本组件不拥有所指对象
    CLIServerDeps deps_;
    CLIStreamManager stream_manager_;
};

#endif  // HNG_CLISERVER_HPP_
