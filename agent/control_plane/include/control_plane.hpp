/**
 * @file control_plane.hpp
 * @brief 控制面三个组件的聚合句柄
 * @details 聚合句柄由装配层持有，组件对象仍经 ControlPlaneFactory 构造。
 * @author red_shinku
 * @date 2026.10.28
 */

#ifndef HNG_CONTROL_PLANE_HPP_
#define HNG_CONTROL_PLANE_HPP_

#include <memory>

namespace hng {

class ContextComponent;
class ProcessComponent;
class RoleComponent;

/**
 * @brief 控制面三个组件的聚合句柄
 * @details 持有角色、进程与上下文组件，并在构造期完成三者之间的接线：进程组件
 *          取角色组件的 @ref RoleJoinService，进程退出通知投向上下文组件与角色
 *          组件的 @ref ProcessLifecycleSink。
 *
 *          析构按进程、角色、上下文的顺序释放三个组件。
 *
 *          组件引用仅供装配层驱动组件线程与取服务；聚合句柄不转发组件生命周期。
 * @see ControlPlaneFactory
 */
class ControlPlane final {
   public:
    /// @brief 按 process → role → context 的顺序释放组件
    ~ControlPlane();

    ControlPlane(const ControlPlane&)            = delete;
    ControlPlane& operator=(const ControlPlane&) = delete;

    /// @brief 角色管理组件
    RoleComponent& role() noexcept;

    /// @brief 进程管理组件
    ProcessComponent& process() noexcept;

    /// @brief 上下文管理组件
    ContextComponent& context() noexcept;

   private:
    /**
     * @brief 接管三个组件并完成控制面内部接线
     * @param role 角色组件
     * @param process 进程组件
     * @param context 上下文组件
     * @note 三个参数都不得为空
     */
    ControlPlane(std::unique_ptr<RoleComponent> role,
                 std::unique_ptr<ProcessComponent> process,
                 std::unique_ptr<ContextComponent> context);

    friend class ControlPlaneFactory;

    // 声明顺序即析构的逆序：process → role → context。
    std::unique_ptr<ContextComponent> context_;
    std::unique_ptr<RoleComponent> role_;
    std::unique_ptr<ProcessComponent> process_;
};

}  // namespace hng

#endif  // HNG_CONTROL_PLANE_HPP_
