/**
 * @file role_seed_service.hpp
 * @brief 角色初始落地后的对账接口
 * @details 初始化期同步入口，不经通知队列；role_manager.hpp 中 RoleManager
 *          实现该接口。
 * @author red_shinku
 * @date 2026.10.25
 */

#ifndef HNG_ROLE_SEED_SERVICE_HPP_
#define HNG_ROLE_SEED_SERVICE_HPP_

#include <cstdint>

#include "agent/event_data/include/process_seed.hpp"

/// @brief 一次角色对账的统计
struct RoleReconcileReport {
    uint64_t ownership_entries = 0;  ///< 对账开始时归属表的条目数
    uint64_t pruned            = 0;  ///< 幽灵清理删除的归属条目数
    /// @brief /proc 存活核对没有结论而保留的条目数
    uint64_t proc_unknown      = 0;
    /// @brief 初始化期补绑定新增成员的子进程数
    uint64_t bind_adopted      = 0;
    uint64_t bind_ignored      = 0;     ///< 父不在任何角色，无需暂存
    uint64_t roles_resynced    = 0;     ///< 实际重读成员的角色数
    uint64_t cgroup_read_empty = 0;     ///< 重读未返回任何进程的角色数
    uint64_t rejected_state    = 0;     ///< 非 CONSTRUCTED 时的 reconcile 调用
    bool snapshot_complete     = true;  ///< 快照是否完整
};

/// @brief 角色初始落地后的对账接口
/// @details 同步、直接写入；调用方在 run() 之前使用。
class RoleSeedService {
   protected:
    virtual ~RoleSeedService() = default;

   public:
    /// @brief 清理幽灵成员、补绑定并重读角色成员
    /// @param batch 初始进程批次
    /// @return 本次对账的统计；正常返回后组件状态为 READY
    /// @pre 组件为 CONSTRUCTED；只调用一次
    virtual RoleReconcileReport reconcile(const hng::ProcessSeedBatch& batch) = 0;
};

#endif  // HNG_ROLE_SEED_SERVICE_HPP_
