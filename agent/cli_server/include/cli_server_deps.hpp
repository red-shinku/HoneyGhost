/**
 * @file cli_server_deps.hpp
 * @brief CLIServer 模块的外部依赖集合
 * @author red-shinku
 * @date 2026.10.28
 */

#ifndef HNG_CLI_SERVER_DEPS_HPP_
#define HNG_CLI_SERVER_DEPS_HPP_

class RoleLookupService;
class ContextLookupService;
class ProcessLookupService;
class SubscriberRegService;

/**
 * @brief CLIServer模块的全部外部依赖
 * @details 全部为裸指针；所指对象由装配方拥有，其存活期须覆盖整个服务
 * 运行期。启动期单线程写、之后只读。
 */
struct CLIServerDeps final {
    /// 角色归属查询
    const RoleLookupService* role       = nullptr;
    /// 上下文归属查询
    const ContextLookupService* context = nullptr;
    /// 进程结构查询
    const ProcessLookupService* process = nullptr;
    /// 引擎订阅入口（写侧）
    SubscriberRegService* subs          = nullptr;
};

#endif  // HNG_CLI_SERVER_DEPS_HPP_
