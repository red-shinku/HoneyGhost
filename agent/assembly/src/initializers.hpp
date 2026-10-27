/**
 * @file initializers.hpp
 * @brief 装配层内部的一次性初始化器
 * @details 每个初始化器借用组件与输入，只执行一次对应的初始化写入，并保存
 *          该次写入的统计。不进入组件公共头，不持有组件所有权，不负责状态机，
 *          也不捕获组件异常。
 * @author red_shinku
 * @date 2026.10.25
 */

#ifndef HNG_ASSEMBLY_INITIALIZERS_HPP_
#define HNG_ASSEMBLY_INITIALIZERS_HPP_

#include "agent/context_maintainer/include/context_maintainer.hpp"
#include "agent/control_plane/include/context_component.hpp"
#include "agent/control_plane/include/process_component.hpp"
#include "agent/control_plane/include/role_component.hpp"
#include "agent/role_filter/include/role_filter_component.hpp"

namespace hng {

/**
 * @brief 进程树的初始化器
 * @see ProcessSeedService::seed
 */
class ProcessInitializer {
   public:
    /**
     * @brief 绑定组件与批次
     * @param component 状态为 CONSTRUCTED 的进程管理组件
     * @param batch 本次快照的进程批次
     */
    ProcessInitializer(ProcessComponent& component,
                       const ProcessSeedBatch& batch);

    /// @brief 执行一次 seed；只调用一次
    void run();

    /// @brief 本次 seed 的统计
    const ProcessSeedReport& report() const noexcept;

   private:
    ProcessComponent& component_;
    const ProcessSeedBatch& batch_;
    ProcessSeedReport report_;
};

/**
 * @brief context 树的初始化器
 * @details 先用 ContextMaintainer 由批次生成计划，再交给 ContextSeedService
 *          落地。
 */
class ContextInitializer {
   public:
    /**
     * @brief 绑定组件、维护器与批次
     * @param component 状态为 CONSTRUCTED 的上下文管理组件
     * @param maintainer 负责生成计划的维护器
     * @param batch 本次快照的进程批次
     */
    ContextInitializer(ContextComponent& component,
                       ::ContextMaintainer& maintainer,
                       const ProcessSeedBatch& batch);

    /// @brief 生成计划并执行一次 seed；只调用一次
    void run();

    /// @brief 本次 seed 的统计
    const ContextSeedReport& report() const noexcept;

   private:
    ContextComponent& component_;
    ::ContextMaintainer& maintainer_;
    const ProcessSeedBatch& batch_;
    ContextSeedReport report_;
};

/**
 * @brief 角色归属的初始化器
 * @details 先同步落地已入队的角色事件，再按批次对账。
 * @see RoleManager::drain
 * @see RoleSeedService::reconcile
 */
class RoleInitializer {
   public:
    /**
     * @brief 绑定组件与批次
     * @param component 状态为 CONSTRUCTED 的角色管理组件
     * @param batch 本次快照的进程批次
     */
    RoleInitializer(RoleComponent& component, const ProcessSeedBatch& batch);

    /// @brief 先 drain() 再执行一次 reconcile；只调用一次
    void run();

    /// @brief 本次对账的统计
    const RoleReconcileReport& report() const noexcept;

   private:
    RoleComponent& component_;
    const ProcessSeedBatch& batch_;
    RoleReconcileReport report_;
};

/**
 * @brief 采集名单的初始化器
 * @see RoleFilterComponent::seed_initial_roles
 */
class RoleFilterInitializer {
   public:
    /// @param filter 名单维护器；空指针表示本次不播种，统计全零
    explicit RoleFilterInitializer(RoleFilterComponent* filter);

    /// @brief 非空时播种初始名单并读取统计；只调用一次
    void run();

    /// @brief 本次播种后的统计
    const RoleFilterStats& report() const noexcept;

   private:
    RoleFilterComponent* filter_;
    RoleFilterStats report_;
};

}  // namespace hng

#endif  // HNG_ASSEMBLY_INITIALIZERS_HPP_
