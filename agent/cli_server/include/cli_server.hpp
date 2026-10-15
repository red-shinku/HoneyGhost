/**
 * @file cli_server.hpp
 * @brief CLI 服务端模块的装配契约：依赖集合与组件登记入口
 * @author red-shinku
 * @date 2026.10.15
 */

#ifndef HNG_CLI_SERVER_HPP_
#define HNG_CLI_SERVER_HPP_

#include <userver/components/component_list.hpp>

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
    // TODO: 查询面还需要 RoleManagerStats / ContextManagerStats，
    //             待两个 *ManagerStats 从各自的 src/ 私有头移到
    //             control_plane/include/ (缺-6)
    /// 引擎订阅入口（写侧）
    SubscriberRegService* subs          = nullptr;
};

/**
 * @brief 注入CLIServer模块的依赖
 * @param deps 依赖集合，CLIServer模块只读，不接管所指对象的生命周期
 * @note 须早于 components::RunApplication 调用：组件在那个调用期间按静态配置
 * 构造，构造期即取用依赖
 */
void InstallCliServerDeps(const CLIServerDeps& deps);

/**
 * @brief 把本模块的组件类型登记进应用的组件表
 * @param list 装配方传给 components::RunApplication 的组件表
 * @note
 * 登记之后静态配置里的 cli-server / cli-role-service / cli-context-service
 * 才有组件可 实例化（未登记的键会以「no component with such name is
 * registered」报错）
 * @note 服务组件在构造期向 grpc-server 注册自己，且构造期经 FindComponent 取用
 * cli-server，故装配方须先把 ugrpc::server::ServerComponent 登记进 list
 */
void AppendCliServerComponents(userver::components::ComponentList& list);

#endif  // HNG_CLI_SERVER_HPP_
