/**
 * @file cli_server.cc
 * @brief CLIServer 组件的实现，以及本模块的两个装配入口
 * @author red-shinku
 * @date 2026.10.15
 */

#include "agent/cli_server/src/cli_server.hpp"

#include <cstddef>

#include <userver/components/component_list.hpp>

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

/// 同时活跃的订阅流条数上限
/// TODO: 阶段三抽成 cli-server 组件的静态配置项
constexpr std::size_t kMaxConcurrentStreams = 64;

}  // namespace

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
      stream_manager_(kMaxConcurrentStreams)
{
}

CLIStreamManager& CLIServer::stream_manager() { return stream_manager_; }

const CLIServerDeps& CLIServer::server_deps() const { return deps_; }
