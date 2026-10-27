/**
 * @file control_plane_factory.hpp
 * @brief 控制面三个组件的唯一构造入口。
 */

#ifndef HNG_CONTROL_PLANE_FACTORY_HPP_
#define HNG_CONTROL_PLANE_FACTORY_HPP_

#include <memory>

#include "agent/control_plane/include/context_component.hpp"
#include "agent/control_plane/include/process_component.hpp"
#include "agent/control_plane/include/role_component.hpp"

namespace hng {

/**
 * @brief 控制面组件工厂。
 * @details 三个创建方法各持一个存活实例名额，互不影响；组件析构后名额归还。
 */
class ControlPlaneFactory {
   public:
    /**
     * @brief 构造进程管理组件。
     * @return 状态为 CONSTRUCTED 的组件；服务接口可直接取用
     * @throws std::logic_error 已有经本方法创建的实例存活
     */
    static std::unique_ptr<ProcessComponent> create_process();

    /**
     * @brief 构造上下文管理组件。
     * @return 状态为 CONSTRUCTED 的组件；服务接口可直接取用
     * @throws std::logic_error 已有经本方法创建的实例存活
     */
    static std::unique_ptr<ContextComponent> create_context();

    /**
     * @brief 构造角色管理组件。
     * @param options cgroup 读取与存活核对的外部 IO 注入点
     * @return 状态为 CONSTRUCTED 的组件；服务接口可直接取用
     * @throws std::logic_error 已有经本方法创建的实例存活
     */
    static std::unique_ptr<RoleComponent> create_role(
        RoleComponentOptions options = {});

    ControlPlaneFactory() = delete;
};

}  // namespace hng

#endif  // HNG_CONTROL_PLANE_FACTORY_HPP_
