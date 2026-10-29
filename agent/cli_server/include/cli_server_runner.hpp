/**
 * @file cli_server_runner.hpp
 * @brief CLI 服务端的进程级运行入口
 * @author red-shinku
 * @date 2026.10.28
 */

#ifndef HNG_CLI_SERVER_RUNNER_HPP_
#define HNG_CLI_SERVER_RUNNER_HPP_

#include "agent/cli_server/include/cli_server_deps.hpp"

#include <chrono>
#include <cstddef>
#include <string>

/**
 * @brief CLI 服务端的进程级运行参数
 */
struct CLIServerOptions final {
    /// Unix socket 路径，gRPC 在该路径上监听
    std::string unix_socket_path       = "/run/honeyghost/cli.sock";
    /// 同时活跃的订阅流条数上限
    std::size_t max_concurrent_streams = 64;
    /// 每流事件队列的目标容量，实际取不小于它的 2 的幂
    std::size_t queue_capacity         = 1024;
    /// 停机时等待各订阅流结束的上界
    std::chrono::milliseconds drain_timeout{10000};
};

/**
 * @brief 运行 CLI 服务端，阻塞到收到停机信号
 * @param deps 依赖集合；所指对象须活到本函数返回，本函数不接管其生命周期
 * @param options 运行参数
 * @note 须在主线程调用：内部登记组件并运行组件系统，阻塞到 SIGTERM /
 * SIGINT / SIGQUIT
 * @note 返回前组件系统已停，含 gRPC 停止接收新流与订阅流 drain
 * @note 启动失败以 std::exception 传播
 * @see AppendCliServerComponents
 */
void RunCliServer(const CLIServerDeps& deps, const CLIServerOptions& options);

#endif  // HNG_CLI_SERVER_RUNNER_HPP_
