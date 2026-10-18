/**
 * @file cli_server.hpp
 * @brief 定义 CLIServer，CLI 服务端模块的入口组件
 * @author red-shinku
 * @date 2026.10.15
 */
#ifndef HNG_CLISERVER_HPP_
#define HNG_CLISERVER_HPP_

#include <chrono>
#include <cstddef>
#include <string_view>

#include <userver/components/component_base.hpp>
#include <userver/yaml_config/schema.hpp>

#include "agent/cli_server/include/cli_server.hpp"
#include "agent/cli_server/src/cli_stream_manager.hpp"

/**
 * @brief 模块入口组件：持有装配方注入的依赖与流管理器，供各服务组件取用
 * @details socket 与 TaskProcessor 由框架组件按静态配置创建，本组件不持。
 * 依赖由 InstallCliServerDeps 写入，本组件在构造期取出。
 * @see CLIStreamManager
 * @see InstallCliServerDeps
 */
class CLIServer final : public userver::components::ComponentBase {
   public:
    static constexpr std::string_view kName = "cli-server";

    CLIServer(const userver::components::ComponentConfig& config,
              const userver::components::ComponentContext& context);

    /// @brief 本组件的静态配置项
    /// @details max-concurrent-streams、queue-capacity、drain-timeout
    static userver::yaml_config::Schema GetStaticConfigSchema();

    /// @return 流管理器
    /// @note 服务组件在构造期取用；本组件的存活期覆盖全部服务组件
    CLIStreamManager& stream_manager();

    /// @return 每流事件队列的目标容量
    /// @note 实际容量会向上取整为 2 的幂
    std::size_t queue_capacity() const { return queue_capacity_; }

    /// @return 装配方注入的依赖集合
    const CLIServerDeps& server_deps() const;

    /// @brief 停机：广播关闭，并在 drain-timeout 内等待各流结束
    /// @note 超时只记 LOG_ERROR 后继续停机，不会阻塞退出
    void OnAllComponentsAreStopping() override;

   private:
    /// 装配方注入的依赖；本组件不拥有所指对象
    CLIServerDeps deps_;
    CLIStreamManager stream_manager_;
    /// 每流事件队列的目标容量
    const std::size_t queue_capacity_;
    /// 等待各流结束的上界
    const std::chrono::milliseconds drain_timeout_;
};

#endif  // HNG_CLISERVER_HPP_
