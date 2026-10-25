/**
 * @file initialization_coordinator.hpp
 * @brief 一次性初始化的执行顺序
 * @details 装配层在启动发现器线程之后、启动控制面消费线程之前调用一次
 *          run()；协调器只借用组件，不持有所有权、不启动线程、不注册 sink。
 * @author red_shinku
 * @date 2026.10.25
 */

#ifndef HNG_ASSEMBLY_INITIALIZATION_COORDINATOR_HPP_
#define HNG_ASSEMBLY_INITIALIZATION_COORDINATOR_HPP_

#include <chrono>

#include "agent/assembly/include/init_report.hpp"

class ContextMaintainer;
class RoleSourceBarrier;

namespace hng {

class ContextComponent;
class ProcessComponent;
class RoleComponent;
class RoleFilter;

/**
 * @brief 初始化协调的可调参数
 */
struct InitializationOptions {
    /// @brief 等待全部角色源上报的最长时间
    /// @note 超时后降级继续；源不可用同样降级，但不计为超时
    std::chrono::milliseconds role_source_timeout{5000};
};

/**
 * @brief 按固定顺序执行一次初始化写入并聚合报告
 * @details 顺序：角色源屏障 → RM drain → RoleFilter 初始名单 → 读快照 →
 *          PM seed → RM drain 与对账 → RoleFilter 应用成员通知 → CM seed →
 *          名单统计。任何初始化写入被拒即停止后续写入并把总状态置为 FAILED。
 * @note PM/CM/RM 的 seed 与 reconcile 各只调用一次，故只能在组件仍为
 *       CONSTRUCTED 时调用；RoleFilter 不在 CONSTRUCTED 时播种，不会因此失败。
 *       协调器不启动组件线程，也不注册 sink；接线由装配方在调用前完成。
 * @see hng::InitReport
 */
class InitializationCoordinator {
   public:
    /**
     * @brief 绑定参与初始化的组件
     * @param process 进程管理组件
     * @param context 上下文管理组件
     * @param role 角色管理组件
     * @param maintainer 已注入 context 服务的 context 维护器
     * @param role_filter 名单维护器；空指针表示本次不播种名单
     * @param role_barrier 角色源屏障；空指针表示不等待任何源
     * @param options 等待时长等参数
     * @note 所有引用与指针须活到 run() 返回
     */
    InitializationCoordinator(ProcessComponent& process,
                              ContextComponent& context, RoleComponent& role,
                              ::ContextMaintainer& maintainer,
                              RoleFilter* role_filter,
                              ::RoleSourceBarrier* role_barrier,
                              InitializationOptions options = {});

    /**
     * @brief 执行一次初始化
     * @param snapshot 本次 /proc 快照；proc_available 为 false 时忽略其内容
     * @return 各步骤的落地统计与聚合状态
     * @pre 三个控制面组件均为 CONSTRUCTED；各只调用一次
     * @pre 角色发现器已上报角色源结论或已超时，且没有组件消费线程在运行
     * @note 组件写入被拒只体现在报告与 FAILED 状态上；组件或查询抛出的异常
     *       按原样传播，由装配方按启动失败处理
     */
    InitReport run(const ProcessSnapshot& snapshot);

   private:
    ProcessComponent& process_;
    ContextComponent& context_;
    RoleComponent& role_;
    ::ContextMaintainer& maintainer_;
    RoleFilter* role_filter_;
    ::RoleSourceBarrier* role_barrier_;
    InitializationOptions options_;
};

}  // namespace hng

#endif  // HNG_ASSEMBLY_INITIALIZATION_COORDINATOR_HPP_
