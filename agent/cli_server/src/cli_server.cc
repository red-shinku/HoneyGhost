/**
 * @file cli_server.cc
 * @brief CLIServer 组件的实现，以及本模块的两个装配入口
 * @author red-shinku
 * @date 2026.10.15
 */

#include "agent/cli_server/src/cli_server.hpp"

#include <chrono>
#include <cstddef>
#include <thread>

#include <userver/components/component_list.hpp>
#include <userver/logging/log.hpp>
#include <userver/yaml_config/schema.hpp>

#include "agent/cli_server/src/cli_context_query_service.hpp"
#include "agent/cli_server/src/cli_role_query_service.hpp"
#include "agent/cli_server/src/cli_runtime_service.hpp"

namespace {

/// @brief 装配方经 InstallCliServerDeps 写入的依赖槽
/// @note 启动期单线程写、之后只读，故不加同步
CLIServerDeps& InstalledDeps()
{
    static CLIServerDeps deps;
    return deps;
}

/// 停机时复查配额槽的周期
constexpr std::chrono::milliseconds kDrainPollPeriod{10};

constexpr std::size_t kDefaultMaxConcurrentStreams = 64;
constexpr std::size_t kDefaultQueueCapacity        = 1024;
constexpr std::chrono::milliseconds kDefaultDrainTimeout{10000};

}  // namespace

userver::yaml_config::Schema CLIServer::GetStaticConfigSchema()
{
    return userver::yaml_config::impl::SchemaFromString(R"(
        type: object
        description: CLI 服务端模块的入口组件
        additionalProperties: false
        properties:
            max-concurrent-streams:
                type: integer
                description: 同时活跃的订阅流条数上限
                defaultDescription: 64
            queue-capacity:
                type: integer
                description: 每流事件队列的目标容量，实际取不小于它的 2 的幂
                defaultDescription: 1024
            drain-timeout:
                type: string
                description: 停机时等待各订阅流结束的上界
                defaultDescription: 10s
        )");
}

void InstallCliServerDeps(const CLIServerDeps& deps) { InstalledDeps() = deps; }

void AppendCliServerComponents(userver::components::ComponentList& list)
{
    list.Append<CLIServer>()
        .Append<CLIRoleQueryService>()
        .Append<CLIContextQueryService>()
        .Append<CLIRuntimeService>();
}

CLIServer::CLIServer(const userver::components::ComponentConfig& config,
                     const userver::components::ComponentContext& context)
    : userver::components::ComponentBase(config, context),
      deps_(InstalledDeps()),
      stream_manager_(config["max-concurrent-streams"].As<std::size_t>(
          kDefaultMaxConcurrentStreams)),
      queue_capacity_(
          config["queue-capacity"].As<std::size_t>(kDefaultQueueCapacity)),
      drain_timeout_(config["drain-timeout"].As<std::chrono::milliseconds>(
          kDefaultDrainTimeout))
{
}

CLIStreamManager& CLIServer::stream_manager() { return stream_manager_; }

const CLIServerDeps& CLIServer::server_deps() const { return deps_; }

void CLIServer::OnAllComponentsAreStopping()
{
    stream_manager_.shutdown();

    // 各流的收敛由自己的消费循环完成，这里只等配额槽全部归还
    const auto deadline = std::chrono::steady_clock::now() + drain_timeout_;
    while (stream_manager_.active_streams() != 0) {
        if (std::chrono::steady_clock::now() >= deadline) {
            LOG_ERROR() << "cli-server: " << stream_manager_.active_streams()
                        << " subscription stream(s) still active after "
                        << drain_timeout_.count() << " ms; continuing shutdown";
            return;
        }
        std::this_thread::sleep_for(kDrainPollPeriod);
    }
}
