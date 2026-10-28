/**
 * @file cli_server_runner.cc
 * @brief CLI 服务端进程级运行入口的实现
 * @author red-shinku
 * @date 2026.10.28
 */

#include "agent/cli_server/include/cli_server_runner.hpp"

#include "agent/cli_server/src/cli_server.hpp"

#include <cstddef>
#include <string>
#include <string_view>

#include <userver/components/minimal_component_list.hpp>
#include <userver/components/run.hpp>
#include <userver/ugrpc/server/component_list.hpp>

namespace {

/// 内建静态配置模板；容量项以下列占位符保留，由 BuildConfig 填入
constexpr char kConfigTemplate[] = R"(
components_manager:
    coro_pool:
        stack_usage_monitor_enabled: false
    task_processors:
        main-task-processor:
            worker_threads: 1
        cli-tp:
            worker_threads: 2
            # 框架只为 *-task-processor 形式的名字自动派生线程名
            thread_name: cli-tp
        fs-task-processor:
            worker_threads: 1
    default_task_processor: main-task-processor
    components:
        logging:
            fs-task-processor: fs-task-processor
            loggers:
                default:
                    file_path: '@stderr'
                    level: warning
                    overflow_behavior: discard
        grpc-server:
            unix-socket-path: "@SOCKET@"
            service-defaults:
                task-processor: cli-tp
        cli-server:
            max-concurrent-streams: @MAX_STREAMS@
            queue-capacity: @QUEUE_CAPACITY@
            drain-timeout: @DRAIN_TIMEOUT@
        cli-role-service: {}
        cli-context-service: {}
        cli-runtime-service: {}
)";

/// @brief 把 text 中出现的所有 from 就地替换成 to
void ReplaceAll(std::string& text, std::string_view from, std::string_view to)
{
    for (auto pos = text.find(from); pos != std::string::npos;
         pos      = text.find(from, pos + to.size())) {
        text.replace(pos, from.size(), to);
    }
}

/// @brief 用运行参数填充内建配置模板
std::string BuildConfig(const CLIServerOptions& options)
{
    // TODO: 外部 YAML 与动态配置尚未接入，第一版只用内建模板
    std::string config = kConfigTemplate;

    ReplaceAll(config, "@SOCKET@", options.unix_socket_path);
    ReplaceAll(config, "@MAX_STREAMS@",
               std::to_string(options.max_concurrent_streams));
    ReplaceAll(config, "@QUEUE_CAPACITY@",
               std::to_string(options.queue_capacity));
    ReplaceAll(config, "@DRAIN_TIMEOUT@",
               std::to_string(options.drain_timeout.count()) + "ms");

    return config;
}

}  // namespace

void RunCliServer(const CLIServerDeps& deps, const CLIServerOptions& options)
{
    InstallCliServerDeps(deps);

    userver::components::ComponentList list =
        userver::components::MinimalComponentList();
    list.AppendComponentList(userver::ugrpc::server::MinimalComponentList());
    AppendCliServerComponents(list);

    userver::components::Run(
        userver::components::InMemoryConfig{BuildConfig(options)}, list);
}
