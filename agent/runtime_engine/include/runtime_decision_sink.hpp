/**
 * @file runtime_decision_sink.hpp
 * @brief 系统组件的事件接受接口，带contextmaintainer模块的决策消息
 * @author red-shinku
 * @date 2026.10.10
 */
#ifndef HNG_RUNTIME_DECISION_SINK_HPP_
#define HNG_RUNTIME_DECISION_SINK_HPP_

#include "agent/event_data/include/runtime_event.hpp"
#include "agent/context_maintainer/include/context_maintainer_decision.hpp"

class RuntimeDecisionSink {
   protected:
    ~RuntimeDecisionSink() = default;

   public:
    virtual void on_event(const hng::RuntimeEvent& runtime_ev,
                          const ContextDeriveDecision& ctx_derive_decision) = 0;

    // virtual void on_event(const hng::RuntimeEvent& runtime_ev,
    //                       const ContextExtraDecision& ctx_extra_decision)   =
    //                       0;
};

#endif  // HNG_RUNTIME_DECISION_SINK_HPP_