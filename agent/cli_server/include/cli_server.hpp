/**
 * @file cli_server.hpp
 * @brief CLI 服务端模块的装配契约：依赖集合与组件登记入口
 * @author red-shinku
 * @date 2026.10.15
 */

#ifndef HNG_CLI_SERVER_HPP_
#define HNG_CLI_SERVER_HPP_

#include <userver/components/component_list.hpp>

#include "agent/cli_server/include/cli_server_deps.hpp"

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
 * 登记之后静态配置里的 cli-server / cli-role-service / cli-context-service /
 * cli-process-service / cli-runtime-service 才有组件可实例化（未登记的键会以
 * 「no component with such
 * name is registered」报错）
 * @note 服务组件在构造期向 grpc-server 注册自己，且构造期经 FindComponent 取用
 * cli-server。服务组件还依赖 gRPC 的中间件管线，故装配方须先把
 * ugrpc::server::MinimalComponentList() 合并进 list，只登记 ServerComponent 不够
 */
void AppendCliServerComponents(userver::components::ComponentList& list);

#endif  // HNG_CLI_SERVER_HPP_
