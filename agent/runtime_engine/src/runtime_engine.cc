/**
 * @file runtime_engine.cc
 * @brief 运行时引擎的实现
 * @author red-shinku
 * @date 2026.10.11
 */

#include "agent/runtime_engine/src/runtime_engine.hpp"

#include <system_error>
#include <utility>

#include "agent/util/include/log.hpp"

RuntimeEngine::RuntimeEngine(
    hng::EventChannelReader<hng::syscall_semantic_data>* syscall_input,
    hng::EventChannelReader<hng::file_semantic_data>* file_input,
    ContextMaintainer* ctx_maintainer, ProcessJoinService* process_join,
    ProcessUpdateService* process_update, RoleJoinService* role_join,
    RoleLookupService* role_lookup)
    : pipeline_(syscall_input, file_input, ctx_maintainer, process_join,
                process_update, role_join, role_lookup)
{
}

void RuntimeEngine::add_system_sink(RuntimeDecisionSink* sink)
{
    if (sink == nullptr) {
        return;
    }
    dispatcher_.add_system_sink(sink);
}

void RuntimeEngine::register_sources()
{
    loop_.add(commands_wakeup_.fd(), kCommandTag);
    if (pipeline_.syscall_fd() >= 0) {
        loop_.add(pipeline_.syscall_fd(), kSyscallTag);
    }
    if (pipeline_.file_fd() >= 0) {
        loop_.add(pipeline_.file_fd(), kFileTag);
    }
}

void RuntimeEngine::run()
{
    RuntimeDraft drafts[kMaxDraftsPerRound]{};
    hng::EventLoop::Ready ready[hng::EventLoop::capacity()];

    try {
        if (!stopped_.load(std::memory_order_acquire)) {
            register_sources();
            while (!stopped_.load(std::memory_order_acquire)) {
                land_commands();
                if (drain_events(drafts) != 0) {
                    continue;
                }
                // 命令与两条输入都已取空：它们各自在取空时交还了通知权，
                // 此处的阻塞不会丢唤醒。就绪源由下一轮的排空取走。
                idle_waits_.fetch_add(1, std::memory_order_relaxed);
                (void)loop_.wait(ready, hng::EventLoop::capacity());
            }
        }
    }
    catch (const std::system_error& error) {
        HNG_LOG_ERROR("engine event loop failed: {}; stopping", error.what());
    }

    // 停机：已入队的命令仍会落地，随后排空已入队事件。装配层先停语义再停
    // 引擎，故此时输入不再增长，取空即结束。
    land_commands();
    while (drain_events(drafts) != 0) {
    }
    dispatcher_.clear();

    HNG_LOG_INFO(
        "engine stopped: {} idle wait(s), {} unsettled event(s), {} rejected "
        "command(s), {} syscall drop(s), {} file drop(s)",
        idle_waits_.load(std::memory_order_relaxed),
        unsettled_events_.load(std::memory_order_relaxed),
        queue_rejected_.load(std::memory_order_relaxed),
        pipeline_.syscall_dropped(), pipeline_.file_dropped());
}

void RuntimeEngine::stop()
{
    // 先关门：此后入队一律被拒，下面的排空不会再遇到新命令
    commands_.stop();
    stopped_.store(true, std::memory_order_release);
    // 唤醒可能阻塞在事件循环上的引擎线程
    loop_.request_stop();
}

bool RuntimeEngine::subscribe(RuntimeEventSink* sink, RuntimeInfoFilter filter,
                              UnsubscribeAck* ack)
{
    Command cmd;
    cmd.kind   = Command::Kind::SUBSCRIBE;
    cmd.sink   = sink;
    cmd.filter = std::move(filter);
    cmd.ack    = ack;

    if (!commands_.push(std::move(cmd))) {
        queue_rejected_.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    commands_wakeup_.notify();
    return true;
}

void RuntimeEngine::unsubscribe(RuntimeEventSink* sink)
{
    Command cmd;
    cmd.kind = Command::Kind::UNSUBSCRIBE;
    cmd.sink = sink;

    if (!commands_.push(std::move(cmd))) {
        queue_rejected_.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    commands_wakeup_.notify();
}

hng::RuntimeEngineStats RuntimeEngine::stats() const
{
    hng::RuntimeEngineStats snapshot;
    snapshot.unsettled_events = unsettled_events_.load(std::memory_order_relaxed);
    snapshot.peak_cli_streams = peak_cli_streams_.load(std::memory_order_relaxed);
    snapshot.queue_rejected   = queue_rejected_.load(std::memory_order_relaxed);
    snapshot.idle_waits       = idle_waits_.load(std::memory_order_relaxed);
    snapshot.syscall_dropped  = pipeline_.syscall_dropped();
    snapshot.file_dropped     = pipeline_.file_dropped();
    return snapshot;
}

bool RuntimeEngine::next_command(Command& cmd)
{
    if (commands_.try_pop(cmd)) {
        return true;
    }
    // 取空：交还通知权，并复查一次以捕获交还之前的入队
    commands_wakeup_.consume();
    return commands_.try_pop(cmd);
}

void RuntimeEngine::land_commands()
{
    Command cmd;
    while (next_command(cmd)) {
        land(cmd);
    }
}

std::size_t RuntimeEngine::drain_events(RuntimeDraft* drafts)
{
    std::size_t total = 0;
    while (total < kMaxEventsPerWake) {
        const std::size_t taken =
            pipeline_.take_round(drafts, kMaxDraftsPerRound);
        if (taken == 0) {
            break;
        }
        for (std::size_t i = 0; i < taken; ++i) {
            const hng::RuntimeInformation& info = drafts[i].event.runtimeInfo;
            if (info.roleID == 0 || info.contextID == 0) {
                unsettled_events_.fetch_add(1, std::memory_order_relaxed);
            }
            dispatcher_.dispatch(drafts[i].event, drafts[i].decision);
        }
        total += taken;
    }
    return total;
}

void RuntimeEngine::land(Command& cmd)
{
    switch (cmd.kind) {
        case Command::Kind::SUBSCRIBE: {
            dispatcher_.add_cli_sink(cmd.sink, std::move(cmd.filter), cmd.ack);

            const std::size_t current = dispatcher_.cli_sink_count();
            if (current > peak_cli_streams_.load(std::memory_order_relaxed)) {
                peak_cli_streams_.store(current, std::memory_order_relaxed);
            }
            break;
        }
        case Command::Kind::UNSUBSCRIBE:
            // 销号回执由分发器在实际摘表时回调
            dispatcher_.remove_cli_sink(cmd.sink);
            break;
    }
}
