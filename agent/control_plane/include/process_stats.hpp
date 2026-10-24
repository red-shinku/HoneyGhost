/**
 * @file process_stats.hpp
 * @brief 进程管理器的异常态观测快照
 * @details 供进程管理器的装配者与运维端读取。
 * @author red_shinku
 * @date 2026.10.24
 */

#ifndef HNG_PROCESS_STATS_HPP_
#define HNG_PROCESS_STATS_HPP_

#include <cstdint>

/// @brief 进程管理器的异常态观测快照
/// @details 除 tombstone_depth 为当前值外，其余字段为累计计数。
struct ProcessManagerStats {
    /// 累计：注册时发现该 pid 的旧实例仍在实进程树中
    /// @details 即 pid 已被复用，而旧实例的退出事件缺失或晚于本条到达。
    /// 出现即说明采集侧丢过事件或跨通道乱序；旧实例已按退役路径处理
    uint64_t pid_reused      = 0;

    /// 累计：注册的进程已有墓碑，ADD 被当作迟到事件丢弃的次数
    uint64_t stale_add       = 0;

    /// 累计：注册时父进程身份既不在实进程树也不在虚拟根中的次数
    /// @details 这类 ADD 照常插入，但不更新任何父进程的孩子计数
    uint64_t parent_missing  = 0;

    /// 当前：墓碑表中的条目数
    uint64_t tombstone_depth = 0;
};

#endif  // HNG_PROCESS_STATS_HPP_
