/**
 * @file runtime_engine.cc
 * @brief 运行时引擎的实现
 * @author red-shinku
 * @date 2026.10.11
 */

#include "agent/runtime_engine/src/runtime_engine.hpp"

#include <utility>

RuntimeEngine::RuntimeEngine(
    hng::SPSC_Queue<hng::syscall_semantic_data>* syscall_queue,
    hng::SPSC_Queue<hng::file_semantic_data>* file_queue,
    ContextMaintainer* ctx_maintainer, ProcessJoinService* process_join,
    RoleJoinService* role_join, RoleLookupService* role_lookup)
    : pipeline_(syscall_queue, file_queue, ctx_maintainer, process_join,
                role_join, role_lookup)
{
}

void RuntimeEngine::add_system_sink(RuntimeDecisionSink* sink)
{
    if (sink == nullptr) {
        return;
    }
    dispatcher_.add_system_sink(sink);
}

void RuntimeEngine::run()
{
    RuntimeDraft drafts[kMaxDraftsPerRound]{};

    while (!stopped_.load(std::memory_order_acquire)) {
        land_commands();

        const std::size_t taken =
            pipeline_.take_round(drafts, kMaxDraftsPerRound);
        for (std::size_t i = 0; i < taken; ++i) {
            const hng::RuntimeInformation& info = drafts[i].event.runtimeInfo;
            if (info.roleID == 0 || info.contextID == 0) {
                unsettled_events_.fetch_add(1, std::memory_order_relaxed);
            }
            dispatcher_.dispatch(drafts[i].event, drafts[i].decision);
        }
    }

    // 停机：已入队的命令仍会落地（含注销回执），此后不再投递事件
    land_commands();
    dispatcher_.clear();
}

void RuntimeEngine::stop()
{
    // 先关门：此后入队一律被拒，下面的排空不会再遇到新命令
    commands_.stop();
    stopped_.store(true, std::memory_order_release);
}

bool RuntimeEngine::subscribe(RuntimeEventSink* sink, RuntimeInfoFilter filter)
{
    Command cmd;
    cmd.kind   = Command::Kind::SUBSCRIBE;
    cmd.sink   = sink;
    cmd.filter = std::move(filter);

    if (!commands_.push(std::move(cmd))) {
        queue_rejected_.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    return true;
}

bool RuntimeEngine::unsubscribe(RuntimeEventSink* sink, UnsubscribeAck* ack)
{
    Command cmd;
    cmd.kind = Command::Kind::UNSUBSCRIBE;
    cmd.sink = sink;
    cmd.ack  = ack;

    if (!commands_.push(std::move(cmd))) {
        queue_rejected_.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    return true;
}

RuntimeEngineStats RuntimeEngine::stats() const
{
    RuntimeEngineStats snapshot;
    snapshot.unsettled_events = unsettled_events_.load(std::memory_order_relaxed);
    snapshot.peak_cli_streams = peak_cli_streams_.load(std::memory_order_relaxed);
    snapshot.queue_rejected   = queue_rejected_.load(std::memory_order_relaxed);
    return snapshot;
}

void RuntimeEngine::land_commands()
{
    Command cmd;
    while (commands_.try_pop(cmd)) {
        land(cmd);
    }
}

void RuntimeEngine::land(Command& cmd)
{
    switch (cmd.kind) {
        case Command::Kind::SUBSCRIBE: {
            dispatcher_.add_cli_sink(cmd.sink, std::move(cmd.filter));

            const std::size_t current = dispatcher_.cli_sink_count();
            if (current > peak_cli_streams_.load(std::memory_order_relaxed)) {
                peak_cli_streams_.store(current, std::memory_order_relaxed);
            }
            break;
        }
        case Command::Kind::UNSUBSCRIBE:
            dispatcher_.remove_cli_sink(cmd.sink);
            cmd.ack->on_unsubscribed();
            break;
    }
}
