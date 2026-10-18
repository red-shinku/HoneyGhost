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
    /// 累计：挂靠时父进程的归属尚未落定
    /// @details 登记竞态（见 docs/red_shinku_logs/控制平面context归属重构.md
    /// §4）， 该次挂靠为空操作、由工作平面补调。持续增长说明补调未生效，
    /// 这些进程会一直无归属
    uint64_t ctxroot_parent_unsettled = 0;
    /// 累计：注销了未注册的 context 根
    /// @details 注销先于注册到达，该次注销被丢弃，随后的注册会留下一个
    /// 永不删除的 context
    uint64_t unknown_unregister       = 0;
};

#endif  // HNG_CONTEXT_STATS_HPP_
