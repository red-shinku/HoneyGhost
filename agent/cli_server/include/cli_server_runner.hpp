/**
 * @file cli_server_runner.hpp
 * @brief CLI 服务端的进程级运行入口
 * @author red-shinku
 * @date 2026.10.28
 */

#ifndef HNG_CLI_SERVER_RUNNER_HPP_
#define HNG_CLI_SERVER_RUNNER_HPP_

#include "agent/cli_server/include/cli_server_deps.hpp"

#include <string>

/**
 * @brief CLI 服务端的进程级运行参数
 */
struct CLIServerOptions final {
    /// Unix socket 路径；空表示不覆盖 CLI 配置文件与内建值
    std::string unix_socket_path;
    /// CLI 配置文件路径；空表示只用内建默认值
    std::string config_path;
};

/**
 * @brief 已准备好的 CLI 服务端配置
 */
struct PreparedCliServerConfig final {
    /// 已填充的 userver 静态配置文本
    std::string text;
    /// 最终生效的 Unix socket 路径
    std::string unix_socket_path;
};

/**
 * @brief 解析 CLI 配置文件、确定 socket 并填充内建 userver 静态配置模板
 * @details 配置文件缺失或键省略时取内建默认值；socket 的最终优先级为内建默认
 * < 配置文件 < @p options.unix_socket_path。
 * @param options 运行参数；空字段表示不覆盖
 * @return 已填充的配置文本与最终生效的 socket 路径
 * @throws std::runtime_error 文件不可读、语法错误、未知键、取值越界或 socket
 * 非法；消息格式为 `<来源>:<行号>: <键>: <原因>`，来自运行参数的错误不带行号
 * @see RunCliServer
 */
PreparedCliServerConfig prepare_cli_server_config(
    const CLIServerOptions& options);

/**
 * @brief 运行 CLI 服务端，阻塞到收到停机信号
 * @param deps 依赖集合；所指对象须活到本函数返回，本函数不接管其生命周期
 * @param config 已准备好的静态配置文本与最终 socket
 * @note 须在主线程调用：内部登记组件并运行组件系统，阻塞到 SIGTERM /
 * SIGINT / SIGQUIT
 * @note 返回前组件系统已停，含 gRPC 停止接收新流与订阅流 drain
 * @note 启动失败以 std::exception 传播
 * @see prepare_cli_server_config
 * @see AppendCliServerComponents
 */
void RunCliServer(const CLIServerDeps& deps,
                  const PreparedCliServerConfig& config);

#endif  // HNG_CLI_SERVER_RUNNER_HPP_
