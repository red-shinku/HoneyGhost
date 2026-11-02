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
 * @brief context 决策的种类
 * @details NONE 表示本次没有决策；KEEP 表示留在父 context；DERIVE 表示派生新
 *          context。三类决策都以值形式返回，不用空 optional 表达无决策
 */
enum class ContextDecisionKind : uint8_t { NONE, KEEP, DERIVE };

/**
 * @brief 一次 context 决策
 * @details KEEP 时 contextID 与 attr 无效；DERIVE 时有效
 */
struct ContextDeriveDecision {
    ContextDecisionKind kind = ContextDecisionKind::NONE;
    uint32_t contextID      = 0;
    hng::contextattr attr   = hng::contextattr::UNKNOWN;
};

/**
 * @brief 事件进入附属 context 的决策
 */
struct ContextExtraDecision {
    bool should_extra;
    uint32_t extraContextID;
};

#endif  // CONTEXT_MAINTAINER_DECISION_HPP_