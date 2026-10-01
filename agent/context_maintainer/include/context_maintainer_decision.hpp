/**
 * @file context_maintainer_desicion.hpp
 * @brief context 维护模块的决策。
 * 决策结构会包含上层关心的信息。
 * 与 context/rule/ 下定义的内部决策消息划清界限
 * @author red_shinku
 * @date 2026.9.3
 */

#ifndef CONTEXT_MAINTAINER_DECISION_HPP_
#define CONTEXT_MAINTAINER_DECISION_HPP_

#include <cstdint>

#include "agent/event_data/include/context.hpp"

/**
 * @brief 最终的派生 context 的决策
 */
struct ContextDeriveDecision {
    bool should_derive;
    uint32_t contextID;
    hng::contextattr attr;
};

/**
 * @brief 事件进入附属 context 的决策
 */
struct ContextExtraDecision {
    bool should_extra;
    uint32_t extraContextID;
};

#endif  // CONTEXT_MAINTAINER_DECISION_HPP_