/**
 * @file context_stats.hpp
 * @brief 上下文管理器的异常态观测快照
 * @details 供查询面接口 ContextLookupService::stats() 使用。
 * @author red_shinku
 * @date 2026.10.18
 */

#ifndef HNG_CONTEXT_STATS_HPP_
#define HNG_CONTEXT_STATS_HPP_

#include <cstdint>

/// @brief 上下文管理器的异常态观测快照
struct ContextManagerStats {
    /// 累计：成功进入延迟关系表的父链接与挂靠条数
    uint64_t pending_deferred         = 0;
    /// 累计：从延迟关系表取出并成功应用的条数
    uint64_t pending_resolved         = 0;
    /// 累计：延迟关系表已满或同一等待方重复入表而拒绝的条数
    uint64_t pending_rejected         = 0;
    /// 累计：延迟关系超过寿命而被取出的条数
    uint64_t pending_expired          = 0;
    /// 累计：主动取消的延迟关系条数
    uint64_t pending_cancelled        = 0;
    /// 当前：延迟关系表中的条数
    uint64_t pending_depth            = 0;
    /// 累计：因父目标消失而无归属的挂靠条数
    uint64_t bind_orphaned            = 0;
    /// 累计：无主 context 的附属登记被丢弃的条数
    uint64_t extra_orphaned           = 0;
    /// 累计：父 contextID 无法解析、父链接按森林根处理的条数
    uint64_t parent_missing           = 0;
    /// 累计：注册命中墓碑而被拒绝的条数
    uint64_t late_register            = 0;
    /// 累计：挂靠命中墓碑而被拒绝的条数
    uint64_t late_bind                = 0;
    /// 累计：同一根进程重复注册主 context 的条数；保留首条
    uint64_t duplicate_context        = 0;
    /// 累计：进程已有不同 context 归属时的改绑尝试条数；保留首条
    uint64_t ownership_conflict       = 0;
    /// 累计：墓碑查询命中次数
    uint64_t tombstone_hits           = 0;
    /// 当前：墓碑表中的条数
    uint64_t tombstone_depth          = 0;
    /// 累计：因父未落定进入延迟表的条数
    uint64_t ctxroot_parent_unsettled = 0;
    /// 累计：注销了未注册的 context 根
    /// @details 注销先于注册到达，该次注销被丢弃，随后的注册会留下一个
    /// 永不删除的 context
    uint64_t unknown_unregister       = 0;
};

#endif  // HNG_CONTEXT_STATS_HPP_
