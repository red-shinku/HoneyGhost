/**
 * @file cli_server_runner.cc
 * @brief CLI 服务端进程级运行入口的实现
 * @author red-shinku
 * @date 2026.10.28
 */

#include "agent/cli_server/include/cli_server_runner.hpp"

#include "agent/cli_server/src/cli_server.hpp"
#include "agent/config/include/config_document.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

#include <userver/components/minimal_component_list.hpp>
#include <userver/components/run.hpp>
#include <userver/ugrpc/server/component_list.hpp>

namespace {

constexpr char kDefaultSocketPath[]                  = "/run/honeyghost/cli.sock";
constexpr std::uint32_t kDefaultMaxConcurrentStreams = 64;
constexpr std::uint32_t kDefaultQueueCapacity        = 1024;
constexpr std::chrono::milliseconds kDefaultDrainTimeout{10000};

constexpr std::uint32_t kMinMaxConcurrentStreams = 1;
constexpr std::uint32_t kMaxMaxConcurrentStreams = 65535;
constexpr std::uint32_t kMinQueueCapacity        = 1;
constexpr std::uint32_t kMaxQueueCapacity        = 1048576;
constexpr std::chrono::milliseconds kMinDrainTimeout{1};
constexpr std::chrono::milliseconds kMaxDrainTimeout{300000};
constexpr std::size_t kMaxSocketPath = 107;

/// 内建静态配置模板；容量项与 socket 以占位符保留，由
/// prepare_cli_server_config 填入
constexpr char kConfigTemplate[]     = R"(
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
        cli-process-service: {}
        cli-runtime-service: {}
)";

/// @brief CLI 配置文件的取值；缺失的键保留内建默认值
struct CliServerFileConfig final {
    std::uint32_t max_concurrent_streams = kDefaultMaxConcurrentStreams;
    std::uint32_t queue_capacity         = kDefaultQueueCapacity;
    std::chrono::milliseconds drain_timeout{kDefaultDrainTimeout};
    std::string socket_path = kDefaultSocketPath;
};

/// @brief 把 text 中出现的所有 from 就地替换成 to
void ReplaceAll(std::string& text, std::string_view from, std::string_view to)
{
    for (auto pos = text.find(from); pos != std::string::npos;
         pos      = text.find(from, pos + to.size())) {
        text.replace(pos, from.size(), to);
    }
}

/// @brief 校验 socket 路径：非空、绝对且不超过 107 字节
/// @throws std::runtime_error 不符合时抛出，消息以 label 开头
void ValidateSocketPath(const std::string& value, const std::string& label)
{
    if (value.empty()) {
        throw std::runtime_error(label + ": 值不能为空");
    }
    if (value.front() != '/') {
        throw std::runtime_error(label + ": 值必须为绝对路径");
    }
    if (value.size() > kMaxSocketPath) {
        throw std::runtime_error(label + ": 路径超过 107 字节");
    }
}

/// @brief 打开并检查 CLI 配置文件
/// @return 已打开的二进制输入流
/// @throws std::runtime_error 路径不可访问、不存在、不是普通文件或无法打开
std::ifstream OpenConfigFile(const std::string& path)
{
    std::error_code error;
    const auto status = std::filesystem::status(path, error);
    if (error && error != std::errc::no_such_file_or_directory) {
        throw std::runtime_error("无法访问 CLI 配置文件: " + path + ": " +
                                 error.message());
    }
    if (!std::filesystem::exists(status)) {
        throw std::runtime_error("CLI 配置文件不存在: " + path);
    }
    if (!std::filesystem::is_regular_file(status)) {
        throw std::runtime_error("CLI 配置文件不是普通文件: " + path);
    }
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("无法打开 CLI 配置文件: " + path);
    }
    return input;
}

/// @brief 读取并校验 CLI 配置文件
/// @throws std::runtime_error 语法错误、未知键、类型错误或取值越界
CliServerFileConfig ParseConfigFile(const std::string& path)
{
    std::ifstream input = OpenConfigFile(path);
    const auto document = hng::ConfigDocument::parse(input, path);
    document.reject_unknown_keys({
        {"cli_server", "max_concurrent_streams"},
        {"cli_server", "queue_capacity"},
        {"cli_server", "drain_timeout"},
        {"cli_server", "socket_path"},
    });

    CliServerFileConfig config;
    auto label = [&path, &document](std::string_view key) {
        const std::string name = "cli_server." + std::string(key);
        const std::size_t line = document.line_of("cli_server", key);
        if (line == 0) return path + ": " + name;
        return path + ":" + std::to_string(line) + ": " + name;
    };

    config.max_concurrent_streams = document.get_uint(
        "cli_server", "max_concurrent_streams", config.max_concurrent_streams);
    if (config.max_concurrent_streams < kMinMaxConcurrentStreams ||
        config.max_concurrent_streams > kMaxMaxConcurrentStreams) {
        throw std::runtime_error(label("max_concurrent_streams") +
                                 ": 取值范围为 1 到 65535");
    }

    config.queue_capacity =
        document.get_uint("cli_server", "queue_capacity", config.queue_capacity);
    if (config.queue_capacity < kMinQueueCapacity ||
        config.queue_capacity > kMaxQueueCapacity) {
        throw std::runtime_error(label("queue_capacity") +
                                 ": 取值范围为 1 到 1048576");
    }

    config.drain_timeout = document.get_duration("cli_server", "drain_timeout",
                                                 config.drain_timeout);
    if (config.drain_timeout < kMinDrainTimeout ||
        config.drain_timeout > kMaxDrainTimeout) {
        throw std::runtime_error(label("drain_timeout") +
                                 ": 取值范围为 1ms 到 300s");
    }

    config.socket_path =
        document.get_string("cli_server", "socket_path", config.socket_path);
    ValidateSocketPath(config.socket_path, label("socket_path"));

    return config;
}

}  // namespace

PreparedCliServerConfig prepare_cli_server_config(const CLIServerOptions& options)
{
    CliServerFileConfig file_config;
    if (!options.config_path.empty()) {
        file_config = ParseConfigFile(options.config_path);
    }

    std::string socket_path = file_config.socket_path;
    if (!options.unix_socket_path.empty()) {
        ValidateSocketPath(options.unix_socket_path, "cli.socket_path");
        socket_path = options.unix_socket_path;
    }

    PreparedCliServerConfig prepared;
    prepared.text = kConfigTemplate;
    ReplaceAll(prepared.text, "@SOCKET@", socket_path);
    ReplaceAll(prepared.text, "@MAX_STREAMS@",
               std::to_string(file_config.max_concurrent_streams));
    ReplaceAll(prepared.text, "@QUEUE_CAPACITY@",
               std::to_string(file_config.queue_capacity));
    ReplaceAll(prepared.text, "@DRAIN_TIMEOUT@",
               std::to_string(file_config.drain_timeout.count()) + "ms");
    prepared.unix_socket_path = std::move(socket_path);
    return prepared;
}

void RunCliServer(const CLIServerDeps& deps,
                  const PreparedCliServerConfig& config)
{
    InstallCliServerDeps(deps);

    userver::components::ComponentList list =
        userver::components::MinimalComponentList();
    list.AppendComponentList(userver::ugrpc::server::MinimalComponentList());
    AppendCliServerComponents(list);

    userver::components::Run(userver::components::InMemoryConfig{config.text},
                             list);
}
