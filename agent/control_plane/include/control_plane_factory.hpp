/**
 * @file control_plane_factory.hpp
 * @brief 控制面三个组件的唯一构造入口。
 */

#ifndef HNG_CONTROL_PLANE_FACTORY_HPP_
#define HNG_CONTROL_PLANE_FACTORY_HPP_

#include <memory>

#include "agent/control_plane/include/context_component.hpp"
#include "agent/control_plane/include/control_plane.hpp"
#include "agent/control_plane/include/process_component.hpp"
#include "agent/control_plane/include/role_component.hpp"

namespace hng {

/**
 * @brief 控制面组件工厂。
 * @details 三个单组件创建方法各持一个存活实例名额，互不影响；组件析构后名额
 *          归还。create() 经这三个方法装配聚合句柄，同时占用三个名额。
 */
class ControlPlaneFactory {
   public:
    /**
     * @brief 构造控制面聚合句柄。
     * @details 依次经 create_role()、create_process()、create_context() 构造
     *          三个组件，并在聚合句柄构造期完成控制面内部接线。
     * @param options cgroup 读取与存活核对的外部 IO 注入点
     * @return 三个组件状态均为 CONSTRUCTED 的聚合句柄
     * @throws std::logic_error 任一组件已有经对应单组件方法创建的实例存活
     * @note 聚合入口同样占用三个名额；聚合句柄析构后名额归还
     */
    static std::unique_ptr<ControlPlane> create(
        RoleComponentOptions options = {});

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
