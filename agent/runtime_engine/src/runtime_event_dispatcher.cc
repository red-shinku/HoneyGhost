/**
 * @file runtime_event_dispatcher.cc
 * @brief 事件分发的实现
 * @author red-shinku
 * @date 2026.10.11
 */

#include "agent/runtime_engine/src/runtime_event_dispatcher.hpp"

void RuntimeEventDispatcher::add_system_sink(RuntimeDecisionSink* sink)
{
    system_sinks_.push_back(sink);
}

void RuntimeEventDispatcher::add_cli_sink(RuntimeEventSink* sink,
                                          RuntimeInfoFilter filter)
{
    for (auto& entry : cli_sinks_) {
        if (entry.first == sink) {
            entry.second = std::move(filter);
            return;
        }
    }
    cli_sinks_.emplace_back(sink, std::move(filter));
}

bool RuntimeEventDispatcher::remove_cli_sink(RuntimeEventSink* sink)
{
    for (auto it = cli_sinks_.begin(); it != cli_sinks_.end(); ++it) {
        if (it->first == sink) {
            cli_sinks_.erase(it);
            return true;
        }
    }
    return false;
}

void RuntimeEventDispatcher::dispatch(const hng::RuntimeEvent& event,
                                      const ContextDeriveDecision& decision)
{
    for (RuntimeDecisionSink* sink : system_sinks_) {
        sink->on_event(event, decision);
    }

    for (const auto& entry : cli_sinks_) {
        if (entry.second.should_take(event.runtimeInfo)) {
            entry.first->on_event(event);
        }
    }
}

void RuntimeEventDispatcher::clear()
{
    system_sinks_.clear();
    cli_sinks_.clear();
}
