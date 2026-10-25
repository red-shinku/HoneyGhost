/**
 * @file context_seed_service.hpp
 * @brief context 树的初始化写入接口
 * @details 初始化期同步批量写入，不经通知队列；context_manager.hpp 中
 *          ContextManager 实现该接口。
 * @author red_shinku
 * @date 2026.10.25
 */

#ifndef HNG_CONTEXT_SEED_SERVICE_HPP_
#define HNG_CONTEXT_SEED_SERVICE_HPP_

#include <cstdint>

#include "agent/context_maintainer/include/context_seed.hpp"

/// @brief 一次 context 树初始化的落地统计
struct ContextSeedReport {
    uint64_t inserted              = 0;  ///< 实际插入的主 context 条数
    uint64_t bound                 = 0;  ///< 实际并入父 context 的进程条数
    uint64_t duplicate             = 0;  ///< 计划内重复的条目；首条落地
    uint64_t rejected_out_of_order = 0;  ///< 父进程尚未落地而拒绝的条数
    uint64_t rejected_invalid      = 0;  ///< 字段非法或 contextID 已被占用
    uint64_t rejected_state        = 0;  ///< 非 CONSTRUCTED 时的 seed 调用
};

/// @brief context 树初始化写入接口
/// @details 同步、直接写入，不调用其它服务、不发通知；调用方在 run() 之前使用。
class ContextSeedService {
   protected:
    virtual ~ContextSeedService() = default;

   public:
    /// @brief 批量落地初始 context 树
    /// @param plan 初始计划，entries 须父先子后
    /// @return 落地统计；正常返回时写入对查询方可见
    /// @pre 组件为 CONSTRUCTED；只调用一次
    virtual ContextSeedReport seed(const ContextSeedPlan& plan) = 0;
};

#endif  // HNG_CONTEXT_SEED_SERVICE_HPP_
