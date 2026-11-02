/**
 * @file runtime_event_dispatcher.cc
 * @brief 事件分发的实现
 * @author red-shinku
 * @date 2026.10.11
 */

#include "agent/runtime_engine/src/runtime_event_dispatcher.hpp"

#include <utility>

void RuntimeEventDispatcher::add_system_sink(RuntimeDecisionSink* sink)
{
    system_sinks_.push_back(sink);
}

void RuntimeEventDispatcher::add_cli_sink(RuntimeEventSink* sink,
                                          RuntimeInfoFilter filter,
                                          UnsubscribeAck* ack)
{
    for (CliSink& entry : cli_sinks_) {
        if (entry.sink == sink) {
            entry.filter = std::move(filter);
            entry.ack    = ack;
            return;
        }
    }
    cli_sinks_.push_back(CliSink{sink, std::move(filter), ack});
}

bool RuntimeEventDispatcher::remove_cli_sink(RuntimeEventSink* sink)
{
    for (auto it = cli_sinks_.begin(); it != cli_sinks_.end(); ++it) {
        if (it->sink != sink) {
            continue;
        }
        UnsubscribeAck* ack = it->ack;
        cli_sinks_.erase(it);
        if (ack != nullptr) {
            ack->on_unsubscribed();
        }
        return true;
    }
    return false;
}

void RuntimeEventDispatcher::dispatch(const hng::RuntimeEvent& event,
                                      const ContextDeriveDecision& decision)
{
    for (RuntimeDecisionSink* sink : system_sinks_) {
        sink->on_event(event, decision);
    }

    for (const CliSink& entry : cli_sinks_) {
        if (entry.filter.should_take(event.runtimeInfo)) {
            entry.sink->on_event(event);
        }
    }
}

void RuntimeEventDispatcher::clear()
{
    system_sinks_.clear();

    // 先摘表再回调：回执里若重入本分发器，表已是干净的
    std::vector<CliSink> sinks;
    sinks.swap(cli_sinks_);
    for (const CliSink& entry : sinks) {
        if (entry.ack != nullptr) {
            entry.ack->on_unsubscribed();
        }
    }
}
