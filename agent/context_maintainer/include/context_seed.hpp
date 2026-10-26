/**
 * @file context_seed.hpp
 * @brief context 树初始化 seed 的计划类型
 * @details 由工作平面的 ContextMaintainer 生成、控制平面的 ContextSeedService
 *          落地；只描述一次性的初始归属，不依赖控制平面实现。
 * @author red_shinku
 * @date 2026.10.25
 */

#ifndef HNG_CONTEXT_SEED_HPP_
#define HNG_CONTEXT_SEED_HPP_

#include <cstdint>
#include <vector>

#include "agent/event_data/include/context.hpp"
#include "agent/event_data/include/process.hpp"

/**
 * @brief 一条初始计划的落地方式
 * @details DERIVE 表示该进程是其 context 的根，携带 contextID；BIND 表示该进程
 *          留在父进程所属的 context 中，不携带 contextID。
 */
enum class ContextSeedKind : uint8_t { DERIVE, BIND };

/**
 * @brief 一个进程的初始 context 归属
 * @details 身份由 process 的 (pid, pid_start_time) 决定；parent 的 pid 为 0
 *          表示森林根。BIND 以父进程所属 context 的根为归属，故不携带
 *          contextID 与 attr。
 */
struct ContextSeedEntry {
    ContextSeedKind kind = ContextSeedKind::DERIVE;
    hng::Process process{};                             ///< 本条目描述的进程
    hng::Process parent{};                              ///< 父进程；根为 {0, 0}
    uint32_t contextID    = 0;                          ///< DERIVE 时有效
    hng::contextattr attr = hng::contextattr::UNKNOWN;  ///< DERIVE 时有效
};

/**
 * @brief 一次初始 context 树的落地计划
 * @details entries 已按父先子后排序，可直接逐条落地；同一进程只出现一次。
 */
struct ContextSeedPlan {
    std::vector<ContextSeedEntry> entries;  ///< 父先子后
};

#endif  // HNG_CONTEXT_SEED_HPP_
