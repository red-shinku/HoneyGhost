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
/// @details 除 anchors_removed 与 tombstone_depth 为当前值外，其余为累计计数：
///          单次读数说明不了问题，只在看增量时才有意义。
struct RoleStoreStats {
    uint64_t rejected            = 0;  ///< 累计：入口拒收，缺实例键或锚点
    uint64_t unknown_instance    = 0;  ///< 累计：LEAVE 或锚点更换遇未知实例键
    uint64_t owner_conflict      = 0;  ///< 累计：成员写入时已归属另一个角色
    /// 累计：fork 继承的 bind 因父进程尚未归属而暂存
    uint64_t bind_deferred       = 0;
    /// 累计：暂存的 bind 在锚点落地后被应用，含子进程已有归属而保留的情形
    uint64_t bind_resolved       = 0;
    /// 累计：暂存的 bind 被丢弃，因相关进程已退出、角色已释放或表已满/重复
    uint64_t bind_rejected       = 0;
    /// 累计：暂存的 bind 超过寿命被丢弃
    uint64_t bind_expired        = 0;
    /// 累计：bind 到达时子进程已有归属，本次不改写
    uint64_t bind_ignored        = 0;
    /// 累计：成员写入因该身份已有墓碑被跳过
    uint64_t late_adopt_rejected = 0;
    /// 当前值非累计：未过期的已退出进程墓碑数
    uint64_t tombstone_depth     = 0;
    /// 当前值非累计：锚点已退出而角色未退出的角色数
    /// @note 锚点退出到 LEAVE 到达之间必然经过该状态，故它不为零不是错态；
    ///       持续为正、或增量长期不收敛才是。只按 on_process_exited 的到达
    ///       记账，锚点在角色建立前就已退出的情形无从得知
    uint64_t anchors_removed     = 0;
};

/// @brief 角色管理器的异常态观测快照
struct RoleManagerStats {
    RoleStoreStats store;  ///< 关系表侧的异常态
    /// 以下 bind_* 与 tombstone_depth 是 store 中同名字段的镜像，供查询面
    /// 按角色管理器快照直接读取；两处同源，不得单独写入。
    uint64_t bind_deferred        = 0;
    uint64_t bind_resolved        = 0;
    uint64_t bind_rejected        = 0;
    uint64_t bind_expired         = 0;
    uint64_t bind_ignored         = 0;
    uint64_t late_adopt_rejected  = 0;
    uint64_t tombstone_depth      = 0;
    /// 累计：重读未返回任何进程
    /// @note 不等于读失败：RoleCgroupReader::read 的契约不区分失败与空
    uint64_t cgroup_read_empty    = 0;
    /// 累计：stop() 之后的入队被拒绝
    uint64_t queue_rejected       = 0;
    /// 累计：成员因已知退出未进入关系表
    uint64_t dead_member_rejected = 0;
    /// 累计：JOIN / MAIN_PROCESS_CHANGE 因锚点已知退出而整条拒绝
    uint64_t dead_anchor_rejected = 0;
};

#endif  // HNG_ROLE_STATS_HPP_
