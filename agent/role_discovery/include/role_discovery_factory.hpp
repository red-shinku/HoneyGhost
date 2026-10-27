/**
 * @file role_discovery_factory.hpp
 * @brief 角色发现组件的唯一构造入口。
 */

#ifndef HNG_ROLE_DISCOVERY_FACTORY_HPP_
#define HNG_ROLE_DISCOVERY_FACTORY_HPP_

#include <memory>

#include "agent/role_discovery/include/role_discovery_component.hpp"

class RoleSourceBarrier;

namespace hng {

namespace role {
class RoleEventSink;
}  // namespace role

/**
 * @brief 角色发现组件工厂。
 * @details create_systemd() 与 create_containerd() 各持一个存活实例名额，互不
 *          影响；组件析构后名额归还。
 * @note 对应发现源未编入构建时，该方法返回空指针。
 */
class RoleDiscoveryFactory {
   public:
    /**
     * @brief 构造 systemd 发现源组件。
     * @param sink 事件出口，须比组件活得久
     * @param barrier 初始快照结论的上报点，须比组件活得久
     * @param options 周期快照间隔
     * @return 状态为 READY 的组件；systemd 源未编入构建时为空指针
     * @throws std::logic_error 已有经本方法创建的实例存活
     */
    static std::unique_ptr<RoleDiscoveryComponent> create_systemd(
        role::RoleEventSink& sink, ::RoleSourceBarrier& barrier,
        SystemdSourceOptions options = {});

    /**
     * @brief 构造 containerd 发现源组件。
     * @param sink 事件出口，须比组件活得久
     * @param barrier 初始快照结论的上报点，须比组件活得久
     * @param options 翻译进程的 socket 路径
     * @return 状态为 READY 的组件；containerd 源未编入构建时为空指针
     * @throws std::logic_error 已有经本方法创建的实例存活
     */
    static std::unique_ptr<RoleDiscoveryComponent> create_containerd(
        role::RoleEventSink& sink, ::RoleSourceBarrier& barrier,
        ContainerdSourceOptions options = {});

    RoleDiscoveryFactory() = delete;
};

}  // namespace hng

#endif  // HNG_ROLE_DISCOVERY_FACTORY_HPP_
