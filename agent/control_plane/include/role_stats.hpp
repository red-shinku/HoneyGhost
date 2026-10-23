/**
 * @file role_stats.hpp
 * @brief 角色管理器的异常态观测快照
 * @details 供查询面接口 RoleLookupService::stats() 使用。
 * @author red_shinku
 * @date 2026.10.18
 */

#ifndef HNG_ROLE_STATS_HPP_
#define HNG_ROLE_STATS_HPP_

#include <cstdint>

/// @brief 角色关系表的异常态观测快照
/// @details 前三项为累计计数：单次读数说明不了问题，只在看增量时才有意义；
///          末项是当前值，两者读法不同，见各自说明。
struct RoleStoreStats {
    uint64_t rejected         = 0;  ///< 累计：入口拒收，缺实例键或锚点
    uint64_t unknown_instance = 0;  ///< 累计：LEAVE 或锚点更换遇未知实例键
    uint64_t owner_conflict   = 0;  ///< 累计：成员写入时已归属另一个角色
    /// 当前值非累计：锚点已退出而角色未退出的角色数
    /// @note 锚点退出到 LEAVE 到达之间必然经过该状态，故它不为零不是错态；
    ///       持续为正、或增量长期不收敛才是。只按 on_process_exited 的到达
    ///       记账，锚点在角色建立前就已退出的情形无从得知
    uint64_t anchors_removed  = 0;
};

/// @brief 角色管理器的异常态观测快照
struct RoleManagerStats {
    RoleStoreStats store;  ///< 关系表侧的异常态
    /// 累计：重读未返回任何进程
    /// @note 不等于读失败：RoleCgroupReader::read 的契约不区分失败与空
    uint64_t cgroup_read_empty = 0;
    /// 累计：stop() 之后的入队被拒绝
    uint64_t queue_rejected    = 0;
};

#endif  // HNG_ROLE_STATS_HPP_
