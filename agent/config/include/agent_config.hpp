/**
 * @file
 * @brief 主配置的节结构与内建默认值。
 * @author inless427
 */
#ifndef HNG_AGENT_CONFIG_HPP_
#define HNG_AGENT_CONFIG_HPP_
#include <optional>
#include <string>

namespace hng {

/** @brief 采集器开关。 */
struct CollectorConfig {
    bool enabled = true;  ///< 是否启动采集器。
};

/** @brief 角色发现源开关。 */
struct RoleDiscoveryConfig {
    bool systemd    = true;  ///< 是否启用 systemd 角色发现源。
    bool containerd = true;  ///< 是否启用 containerd 角色发现源。
    std::string containerd_socket_path =
        "/run/honeyghost/containerd-bridge.sock";  ///< 桥接 socket。
};

/** @brief CLI 服务端选项。 */
struct CliConfig {
    std::optional<bool> enabled;  ///< 未设置：按构建结果决定。
    std::string socket_path;      ///< 空：不覆盖 CLI 配置文件与内建值。
    std::string config_path;      ///< 空：CLI 服务端只用内建默认值。
};

/**
 * @brief 节点代理的完整配置。
 * @details 由文件与环境变量填充后，相对路径已在
 * `load_agent_config` 中解析为绝对路径。
 * @see CliConfig
 * @see RoleDiscoveryConfig
 */
struct AgentConfig {
    CollectorConfig collector;            ///< 采集器开关。
    RoleDiscoveryConfig role_discovery;   ///< 角色发现源配置。
    std::string role_filter_config_path;  ///< 空：空策略。
    CliConfig cli;                        ///< CLI 服务端配置。
};

}  // namespace hng
#endif
