/**
 * @file chain_core.cc
 * @brief chain 段整链运行期的装配、快照与收尾
 * @details
 * 原始通道与语义通道各一条；真实语义组件、真实运行时引擎、真实 context
 * 维护器，控制面替身与语料全量种子来自 L1 头文件。ChainRuntime 启动 feeder、
 * 语义、引擎三条命名线程，并在调用方指定的时刻读取累计计数与线程 CPU；
 * 通道占用峰值由随快照启停的采样线程记录，一次快照取走并重置它。
 */

#include "test/bench/chain_core.hpp"

#include "test/bench/l1_control_plane.hpp"

#include "agent/context_maintainer/include/context_maintainer.hpp"
#include "agent/control_plane/include/context_service.hpp"
#include "agent/control_plane/include/process_service.hpp"
#include "agent/control_plane/include/role_service.hpp"
#include "agent/event_data/include/syscall_event.hpp"
#include "agent/runtime_engine/include/runtime_decision_sink.hpp"
#include "agent/runtime_engine/include/runtime_engine_component.hpp"
#include "agent/runtime_engine/include/runtime_engine_factory.hpp"
#include "agent/runtime_engine/include/subscriber_reg_service.hpp"
#include "agent/semantic/include/semantic_component.hpp"
#include "agent/semantic/include/semantic_factory.hpp"
#include "agent/semantic/src/semantic.hpp"
#include "agent/util/include/event_channel.hpp"
#include "agent/util/include/pipeline_stats.hpp"

#include <sys/prctl.h>
#include <sys/types.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace {

/// @brief 退出码：工作线程收尾超时，仅用于兜底退出
constexpr int kExitRuntimeFailure = 1;

/// @brief 等待工作线程退出的上限；超过后告警并再等一次
constexpr std::chrono::seconds kThreadJoinLimit(2);
/// @brief 等待工作线程发布 tid 的上限
constexpr std::chrono::milliseconds kTidWaitLimit(1000);
/// @brief 通道占用采样的间隔
constexpr std::chrono::milliseconds kOccupancyInterval(10);

/// @brief 回放线程名；PR_SET_NAME 只保留前 15 字节
constexpr char kFeederThreadName[]   = "hng-chain-feed";
/// @brief 语义线程名
constexpr char kSemanticThreadName[] = "hng-chain-sem";
/// @brief 引擎线程名
constexpr char kEngineThreadName[]   = "hng-chain-eng";
/// @brief 通道占用采样线程名
constexpr char kSamplerThreadName[]  = "hng-chain-occ";

/// @brief 系统订阅计数端，兼作引擎分发计数器
class CountSystemSink final : public RuntimeDecisionSink {
   public:
    void on_event(const hng::RuntimeEvent&, const ContextDeriveDecision&) override
    {
        count_.fetch_add(1, std::memory_order_relaxed);
    }

    std::uint64_t count() const { return count_.load(std::memory_order_relaxed); }

   private:
    std::atomic<std::uint64_t> count_{0};
};

/// @brief 通道容量向上取整为 2 的幂，与 SPSC_Queue 的容量语义一致
std::size_t channel_capacity(int queue)
{
    std::size_t capacity = 1;
    while (capacity < static_cast<std::size_t>(queue)) {
        capacity <<= 1;
    }
    return capacity;
}

/// @brief 把峰值更新为 value 与现值的较大者
void update_peak(std::atomic<std::size_t>& peak, std::size_t value)
{
    std::size_t current = peak.load(std::memory_order_relaxed);
    while (value > current && !peak.compare_exchange_weak(
                                  current, value, std::memory_order_relaxed)) {
    }
}

/// @brief 等待线程退出并 join；超时返回 false 且不 join
bool wait_for_thread(std::thread& thread, const std::atomic<bool>& done,
                     std::chrono::milliseconds limit)
{
    const bench::Clock::time_point deadline = bench::Clock::now() + limit;
    while (!done.load(std::memory_order_acquire)) {
        if (bench::Clock::now() >= deadline) {
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    if (thread.joinable()) {
        thread.join();
    }
    return true;
}

/**
 * @brief 等待一条工作线程发布 tid
 * @param[in] tid 线程 tid
 * @param[in] name 线程名，用于报错
 * @param[out] error 失败原因
 * @return 在 kTidWaitLimit 内发布时为 true
 */
bool wait_for_tid(const std::atomic<pid_t>& tid, const char* name,
                  std::string& error)
{
    const bench::Clock::time_point deadline = bench::Clock::now() + kTidWaitLimit;
    while (tid.load(std::memory_order_acquire) == 0) {
        if (bench::Clock::now() >= deadline) {
            error =
                std::string(
                    "timed out after 1s waiting for threads to publish tid: ") +
                name;
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return true;
}

}  // namespace

namespace bench::chain {

/**
 * @brief ChainRuntime 的装配、线程与快照状态
 * @details 声明顺序即析构顺序的逆序：组件在通道之前析构，维护器在引擎之后
 *          析构，线程由 stop() 在析构前 join。
 */
struct ChainRuntime::Impl final : hng::PipelineStatsService {
    ChainOptions options;  ///< 本轮的语料与通道参数
    ChainFeeder feeder;    ///< 回放生产者
    /// 两条通道由本对象持有；组件与线程只借用
    std::unique_ptr<hng::EventChannel<struct syscall_event>> raw_channel;
    std::unique_ptr<hng::EventChannel<hng::syscall_semantic_data>> sem_channel;

    bench::l1::FakeProcessJoin process_join;
    bench::l1::FakeProcessUpdate process_update;
    bench::l1::FakeProcessLookup process_lookup;
    bench::l1::FakeRoleJoin role_join;
    bench::l1::FakeRoleLookup role_lookup;
    bench::l1::FakeContextService context_service;
    /// L2 的真实 Process/Context 组件与组件线程；声明在维护器之前
    bench::l2::ControlPlane control;
    ContextMaintainer maintainer;

    std::vector<std::unique_ptr<CountSystemSink>> system_sinks;
    std::unique_ptr<hng::SemanticComponent> semantic;
    std::unique_ptr<hng::RuntimeEngineComponent> engine;

    std::atomic<bool> feeder_stop{false};
    std::atomic<pid_t> feeder_tid{0};
    std::atomic<pid_t> semantic_tid{0};
    std::atomic<pid_t> engine_tid{0};
    std::atomic<bool> semantic_done{false};
    std::atomic<bool> engine_done{false};
    std::atomic<bool> semantic_failed{false};
    std::atomic<bool> engine_failed{false};

    std::thread semantic_thread;
    std::thread engine_thread;
    std::thread feeder_thread;

    std::atomic<bool> sampler_stop{false};
    std::atomic<std::size_t> raw_peak{0};
    std::atomic<std::size_t> sem_peak{0};
    std::thread sampler_thread;

    std::size_t capacity = 1;
    bool started         = false;
    bool feeder_started  = false;
    bool stopped         = false;

    ~Impl() override { stop(); }

    bool start(const ChainOptions& settings, std::string& error,
               bool defer_feeder);
    bool start_feeder(std::string& error);
    bool snapshot(ChainSnapshot& snapshot, std::string& error);
    void stop();
    bool failed() const
    {
        return semantic_failed.load(std::memory_order_acquire) ||
               engine_failed.load(std::memory_order_acquire) || control.failed();
    }

    /// @brief PipelineStatsService 入口：collector/semantic/engine 三段累计计数
    hng::PipelineStats snapshot() const override;

    void start_sampler();
    void stop_sampler();
    void sample_occupancy();
};

bool ChainRuntime::Impl::start(const ChainOptions& settings, std::string& error,
                               bool defer_feeder)
{
    if (started) {
        error = "ChainRuntime already started";
        return false;
    }
    options = settings;

    if (!feeder.load(options.trace_path, options.events, error)) {
        return false;
    }

    // 种子始终用全量语料，不受 --events 回放类别影响：先离线语义化一次，
    // 再按出现过的进程身份播种 L1 替身
    std::vector<hng::syscall_semantic_data> seed_events;
    seed_events.reserve(feeder.records().size());
    {
        Semantic_syscall semantic_tool;
        for (const std::vector<char>& record : feeder.records()) {
            struct syscall_event raw{};
            rebuild_event(record, raw);
            hng::syscall_semantic_data event;
            semantic_tool.transform_one(raw, event);
            seed_events.push_back(std::move(event));
        }
    }

    capacity    = channel_capacity(options.queue);
    raw_channel = std::make_unique<hng::EventChannel<struct syscall_event>>(
        static_cast<std::size_t>(options.queue));
    sem_channel = std::make_unique<hng::EventChannel<hng::syscall_semantic_data>>(
        static_cast<std::size_t>(options.queue));

    // 引擎注入点：L1 全部指向内存替身，L2 的进程与 context 维度指向真实组件
    ProcessJoinService* process_join_target     = &process_join;
    ProcessUpdateService* process_update_target = &process_update;
    ProcessLookupService* process_lookup_target = &process_lookup;

    if (options.fidelity == bench::Fidelity::L2) {
        if (!control.start(seed_events, options.settled, maintainer, role_join,
                           role_lookup, error)) {
            return false;
        }
        process_join_target   = &control.process_join();
        process_update_target = &control.process_update();
        process_lookup_target = &control.process_lookup();
    }
    else {
        maintainer.set_context_service(&context_service, &context_service,
                                       &context_service);
        bench::l1::SeedCounts seeds;
        bench::l1::seed_services(seed_events, options.settled, process_lookup,
                                 role_lookup, context_service, seeds);
    }
    seed_events.clear();
    seed_events.shrink_to_fit();

    system_sinks.reserve(static_cast<std::size_t>(options.system_sinks));
    for (int index = 0; index < options.system_sinks; ++index) {
        system_sinks.push_back(std::make_unique<CountSystemSink>());
    }

    try {
        hng::SemanticOptions semantic_settings;
        semantic_settings.raw_syscall = &raw_channel->reader();
        semantic_settings.out_syscall = &sem_channel->writer();
        semantic = hng::SemanticFactory::create(semantic_settings);
        if (!semantic) {
            error =
                "failed to construct the semantic component: factory returned no "
                "instance";
            return false;
        }

        hng::RuntimeEngineOptions engine_settings;
        engine_settings.syscall_input  = &sem_channel->reader();
        engine_settings.ctx_maintainer = &maintainer;
        engine_settings.process_join   = process_join_target;
        engine_settings.process_update = process_update_target;
        engine_settings.process_lookup = process_lookup_target;
        engine_settings.role_join      = &role_join;
        engine_settings.role_lookup    = &role_lookup;
        engine = hng::RuntimeEngineFactory::create(engine_settings);
        if (!engine) {
            error =
                "failed to construct the engine: factory returned no instance";
            return false;
        }
        for (const std::unique_ptr<CountSystemSink>& sink : system_sinks) {
            engine->add_system_sink(sink.get());
        }
    }
    catch (const std::exception& failure) {
        error = std::string("failed to construct the pipeline component: ") +
                failure.what();
        return false;
    }

    try {
        // 消费线程先进入等待；回放线程由 start() 末尾或 start_feeder() 启动
        semantic_thread = std::thread([this] {
            semantic_tid.store(::gettid(), std::memory_order_release);
            (void)::prctl(PR_SET_NAME, kSemanticThreadName);
            try {
                semantic->run();
            }
            catch (const std::exception& failure) {
                std::fprintf(stderr, "semantic thread failed: %s\n",
                             failure.what());
                semantic_failed.store(true, std::memory_order_release);
            }
            catch (...) {
                std::fprintf(stderr,
                             "semantic thread failed: unknown exception\n");
                semantic_failed.store(true, std::memory_order_release);
            }
            semantic_done.store(true, std::memory_order_release);
        });

        engine_thread   = std::thread([this] {
            engine_tid.store(::gettid(), std::memory_order_release);
            (void)::prctl(PR_SET_NAME, kEngineThreadName);
            try {
                engine->run();
            }
            catch (const std::exception& failure) {
                std::fprintf(stderr, "engine thread failed: %s\n",
                               failure.what());
                engine_failed.store(true, std::memory_order_release);
            }
            catch (...) {
                std::fprintf(stderr, "engine thread failed: unknown exception\n");
                engine_failed.store(true, std::memory_order_release);
            }
            engine_done.store(true, std::memory_order_release);
        });
    }
    catch (const std::exception& failure) {
        error = std::string("failed to start the consumer threads: ") +
                failure.what();
        stop();
        return false;
    }

    if (!wait_for_tid(semantic_tid, "semantic", error) ||
        !wait_for_tid(engine_tid, "engine", error)) {
        std::fprintf(stderr, "%s\n", error.c_str());
        stop();
        return false;
    }

    started = true;
    if (!defer_feeder && !start_feeder(error)) {
        stop();
        return false;
    }
    return true;
}

bool ChainRuntime::Impl::start_feeder(std::string& error)
{
    if (!started) {
        error = "ChainRuntime not started";
        return false;
    }
    if (feeder_started) {
        error = "replay thread already started";
        return false;
    }
    try {
        feeder_stop.store(false, std::memory_order_release);
        feeder_thread = std::thread([this] {
            feeder_tid.store(::gettid(), std::memory_order_release);
            (void)::prctl(PR_SET_NAME, kFeederThreadName);
            feeder.run(raw_channel->writer(), feeder_stop, options.rate);
        });
    }
    catch (const std::exception& failure) {
        error =
            std::string("failed to start the replay thread: ") + failure.what();
        return false;
    }
    if (!wait_for_tid(feeder_tid, "feeder", error)) {
        return false;
    }
    feeder_started = true;
    return true;
}

bool ChainRuntime::Impl::snapshot(ChainSnapshot& sample, std::string& error)
{
    sample = ChainSnapshot{};
    if (!started) {
        error = "ChainRuntime not started";
        return false;
    }
    stop_sampler();

    if (feeder_started) {
        const std::uint64_t feeder_id = static_cast<std::uint64_t>(
            feeder_tid.load(std::memory_order_acquire));
        if (!bench::read_thread_cpu(feeder_id, sample.feeder_cpu, error)) {
            error = "failed to read replay thread CPU: " + error;
            return false;
        }
    }
    const std::uint64_t semantic_id =
        static_cast<std::uint64_t>(semantic_tid.load(std::memory_order_acquire));
    if (!bench::read_thread_cpu(semantic_id, sample.semantic_cpu, error)) {
        error = "failed to read semantic thread CPU: " + error;
        return false;
    }
    const std::uint64_t engine_id =
        static_cast<std::uint64_t>(engine_tid.load(std::memory_order_acquire));
    if (!bench::read_thread_cpu(engine_id, sample.engine_cpu, error)) {
        error = "failed to read engine thread CPU: " + error;
        return false;
    }
    double process_cpu = 0.0;
    if (!bench::read_process_cpu(::getpid(), process_cpu, error)) {
        error = "failed to read process total CPU: " + error;
        return false;
    }

    const FeederCounters feeder_counters = feeder.counters();
    sample.consumed                      = feeder_counters.consumed;
    sample.consumed_lifecycle            = feeder_counters.consumed_lifecycle;
    sample.push_ok                       = feeder_counters.push_ok;
    sample.push_fail                     = feeder_counters.push_fail;
    sample.malformed                     = feeder.malformed();
    sample.records                       = feeder.records().size();
    sample.playback                      = feeder.playback().size();

    if (semantic) {
        sample.processed = semantic->stats().processed_syscall;
    }

    std::uint64_t dispatched_total = 0;
    for (const std::unique_ptr<CountSystemSink>& sink : system_sinks) {
        dispatched_total += sink->count();
    }
    sample.dispatched =
        system_sinks.empty() ? 0 : dispatched_total / system_sinks.size();

    sample.raw_drops =
        raw_channel->reader().dropped() + raw_channel->reader().rejected();
    sample.sem_drops =
        sem_channel->reader().dropped() + sem_channel->reader().rejected();
    if (engine) {
        const hng::RuntimeEngineStats stats = engine->stats();
        sample.unsettled                    = stats.unsettled_events;
        sample.engine_syscall_dropped       = stats.syscall_dropped;
        sample.engine_idle_waits            = stats.idle_waits;
    }

    // 控制面 CPU：进程总量减去三条按 tid 归属的工作线程；占用采样线程与
    // L2 的 process/context 组件线程都只能落在这一差值里
    const double thread_cpu =
        sample.feeder_cpu + sample.semantic_cpu + sample.engine_cpu;
    sample.cp_cpu = process_cpu > thread_cpu ? process_cpu - thread_cpu : 0.0;
    if (options.fidelity == bench::Fidelity::L2) {
        sample.control = control.snapshot();
    }

    // 采样已停：此刻取走的是上一次快照以来的真实峰值，随后重新开始采样
    sample.raw_peak = raw_peak.exchange(0, std::memory_order_relaxed);
    sample.sem_peak = sem_peak.exchange(0, std::memory_order_relaxed);

    try {
        start_sampler();
    }
    catch (const std::exception& failure) {
        error = std::string("failed to restart the occupancy sampling thread: ") +
                failure.what();
        return false;
    }

    error.clear();
    return true;
}

void ChainRuntime::Impl::start_sampler()
{
    sampler_stop.store(false, std::memory_order_release);
    sampler_thread = std::thread([this] { sample_occupancy(); });
}

void ChainRuntime::Impl::stop_sampler()
{
    sampler_stop.store(true, std::memory_order_release);
    if (sampler_thread.joinable()) {
        sampler_thread.join();
    }
}

void ChainRuntime::Impl::sample_occupancy()
{
    (void)::prctl(PR_SET_NAME, kSamplerThreadName);
    // EventChannel::size() 只保证单线程观察；第三方线程采样可能读到瞬时
    // 不一致的 head/tail 而下溢，超出容量的样本视为无效并丢弃
    while (!sampler_stop.load(std::memory_order_acquire)) {
        if (raw_channel) {
            const std::size_t value = raw_channel->size();
            if (value <= capacity) {
                update_peak(raw_peak, value);
            }
        }
        if (sem_channel) {
            const std::size_t value = sem_channel->size();
            if (value <= capacity) {
                update_peak(sem_peak, value);
            }
        }
        std::this_thread::sleep_for(kOccupancyInterval);
    }
}

void ChainRuntime::Impl::stop()
{
    if (stopped) {
        return;
    }
    stopped = true;

    stop_sampler();
    feeder_stop.store(true, std::memory_order_release);
    if (feeder_thread.joinable()) {
        feeder_thread.join();
    }
    if (semantic && semantic_thread.joinable()) {
        semantic->stop();
        if (!wait_for_thread(semantic_thread, semantic_done, kThreadJoinLimit)) {
            std::fprintf(stderr,
                         "warning: semantic thread did not exit within %lld "
                         "seconds; waiting once more\n",
                         static_cast<long long>(kThreadJoinLimit.count()));
            if (!wait_for_thread(semantic_thread, semantic_done,
                                 kThreadJoinLimit)) {
                std::fprintf(stderr,
                             "semantic thread still has not exited; exiting the "
                             "process\n");
                std::_Exit(kExitRuntimeFailure);
            }
        }
    }
    if (engine && engine_thread.joinable()) {
        engine->stop();
        if (!wait_for_thread(engine_thread, engine_done, kThreadJoinLimit)) {
            std::fprintf(stderr,
                         "warning: engine thread did not exit within %lld "
                         "seconds; waiting once more\n",
                         static_cast<long long>(kThreadJoinLimit.count()));
            if (!wait_for_thread(engine_thread, engine_done, kThreadJoinLimit)) {
                std::fprintf(
                    stderr,
                    "engine thread still has not exited; exiting the process\n");
                std::_Exit(kExitRuntimeFailure);
            }
        }
    }
    if (raw_channel) {
        raw_channel->writer().close();
    }
    if (sem_channel) {
        sem_channel->writer().close();
    }
    control.stop();
}

hng::PipelineStats ChainRuntime::Impl::snapshot() const
{
    hng::PipelineStats stats;
    if (!raw_channel) {
        return stats;
    }

    hng::CollectorLineStats line;
    line.line                     = "replay";
    const FeederCounters counters = feeder.counters();
    line.consumed                 = counters.consumed;
    line.malformed                = counters.malformed;
    line.channel_dropped          = counters.push_fail;
    stats.collector.push_back(std::move(line));

    if (semantic) {
        stats.semantic = semantic->stats();
    }
    if (engine) {
        const hng::RuntimeEngineStats raw = engine->stats();
        hng::PipelineEngineStats published;
        published.unsettled_events = raw.unsettled_events;
        published.peak_cli_streams = raw.peak_cli_streams;
        published.queue_rejected   = raw.queue_rejected;
        published.idle_waits       = raw.idle_waits;
        published.syscall_dropped  = raw.syscall_dropped;
        stats.engine               = published;
    }
    return stats;
}

ChainRuntime::ChainRuntime() : impl_(std::make_unique<Impl>()) {}

ChainRuntime::~ChainRuntime() = default;

bool ChainRuntime::start(const ChainOptions& options, std::string& error,
                         bool defer_feeder)
{
    return impl_->start(options, error, defer_feeder);
}

bool ChainRuntime::start_feeder(std::string& error)
{
    return impl_->start_feeder(error);
}

bool ChainRuntime::snapshot(ChainSnapshot& snapshot, std::string& error)
{
    return impl_->snapshot(snapshot, error);
}

void ChainRuntime::stop() { impl_->stop(); }

SubscriberRegService& ChainRuntime::subscriber_service()
{
    return impl_->engine->subscriber_service();
}

hng::PipelineStatsService& ChainRuntime::stats_service() { return *impl_; }

RoleLookupService& ChainRuntime::role_lookup_service()
{
    return impl_->role_lookup;
}

ContextLookupService& ChainRuntime::context_lookup_service()
{
    if (impl_->options.fidelity == bench::Fidelity::L2) {
        return impl_->control.context_lookup();
    }
    return impl_->context_service;
}

ProcessLookupService& ChainRuntime::process_lookup_service()
{
    if (impl_->options.fidelity == bench::Fidelity::L2) {
        return impl_->control.process_lookup();
    }
    return impl_->process_lookup;
}

bool ChainRuntime::failed() const { return impl_->failed(); }

ChainSnapshot window_delta(const ChainSnapshot& begin, const ChainSnapshot& end)
{
    const auto delta = [](std::uint64_t later, std::uint64_t earlier) {
        return later >= earlier ? later - earlier : 0;
    };
    const auto cpu_delta = [](double later, double earlier) {
        return later >= earlier ? later - earlier : 0.0;
    };

    ChainSnapshot window = end;
    window.seconds       = 0.0;
    window.consumed      = delta(end.consumed, begin.consumed);
    window.consumed_lifecycle =
        delta(end.consumed_lifecycle, begin.consumed_lifecycle);
    window.push_ok    = delta(end.push_ok, begin.push_ok);
    window.push_fail  = delta(end.push_fail, begin.push_fail);
    window.processed  = delta(end.processed, begin.processed);
    window.dispatched = delta(end.dispatched, begin.dispatched);
    window.raw_drops  = delta(end.raw_drops, begin.raw_drops);
    window.sem_drops  = delta(end.sem_drops, begin.sem_drops);
    window.unsettled  = delta(end.unsettled, begin.unsettled);
    window.engine_syscall_dropped =
        delta(end.engine_syscall_dropped, begin.engine_syscall_dropped);
    window.engine_idle_waits =
        delta(end.engine_idle_waits, begin.engine_idle_waits);
    window.feeder_cpu       = cpu_delta(end.feeder_cpu, begin.feeder_cpu);
    window.semantic_cpu     = cpu_delta(end.semantic_cpu, begin.semantic_cpu);
    window.engine_cpu       = cpu_delta(end.engine_cpu, begin.engine_cpu);
    window.cp_cpu           = cpu_delta(end.cp_cpu, begin.cp_cpu);

    // 控制面统计：累计字段取窗口增量，深度字段保留窗口终点的当前值
    ProcessManagerStats& pm = window.control.process;
    pm.pid_reused =
        delta(end.control.process.pid_reused, begin.control.process.pid_reused);
    pm.stale_add =
        delta(end.control.process.stale_add, begin.control.process.stale_add);
    pm.parent_missing                 = delta(end.control.process.parent_missing,
                                              begin.control.process.parent_missing);

    ContextManagerStats& cm           = window.control.context;
    const ContextManagerStats& cm_end = end.control.context;
    const ContextManagerStats& cm_begin = begin.control.context;
    cm.pending_deferred =
        delta(cm_end.pending_deferred, cm_begin.pending_deferred);
    cm.pending_resolved =
        delta(cm_end.pending_resolved, cm_begin.pending_resolved);
    cm.pending_rejected =
        delta(cm_end.pending_rejected, cm_begin.pending_rejected);
    cm.pending_expired = delta(cm_end.pending_expired, cm_begin.pending_expired);
    cm.pending_cancelled =
        delta(cm_end.pending_cancelled, cm_begin.pending_cancelled);
    cm.bind_orphaned  = delta(cm_end.bind_orphaned, cm_begin.bind_orphaned);
    cm.extra_orphaned = delta(cm_end.extra_orphaned, cm_begin.extra_orphaned);
    cm.parent_missing = delta(cm_end.parent_missing, cm_begin.parent_missing);
    cm.late_register  = delta(cm_end.late_register, cm_begin.late_register);
    cm.late_bind      = delta(cm_end.late_bind, cm_begin.late_bind);
    cm.duplicate_context =
        delta(cm_end.duplicate_context, cm_begin.duplicate_context);
    cm.ownership_conflict =
        delta(cm_end.ownership_conflict, cm_begin.ownership_conflict);
    cm.tombstone_hits = delta(cm_end.tombstone_hits, cm_begin.tombstone_hits);
    cm.ctxroot_parent_unsettled =
        delta(cm_end.ctxroot_parent_unsettled, cm_begin.ctxroot_parent_unsettled);
    cm.unknown_unregister =
        delta(cm_end.unknown_unregister, cm_begin.unknown_unregister);
    return window;
}

bool run_chain_sink(const ChainOptions& options, ChainSnapshot& snapshot,
                    std::string& error)
{
    ChainRuntime runtime;
    if (!runtime.start(options, error)) {
        return false;
    }

    const bench::Clock::time_point measure_start =
        bench::Clock::now() + std::chrono::seconds(options.warmup_seconds);
    std::this_thread::sleep_until(measure_start);

    ChainSnapshot counter_start;
    if (!runtime.snapshot(counter_start, error)) {
        std::fprintf(stderr, "%s\n", error.c_str());
        runtime.stop();
        return false;
    }

    std::this_thread::sleep_until(measure_start +
                                  std::chrono::seconds(options.seconds));
    ChainSnapshot counter_end;
    if (!runtime.snapshot(counter_end, error)) {
        std::fprintf(stderr, "%s\n", error.c_str());
        runtime.stop();
        return false;
    }

    runtime.stop();

    if (runtime.failed()) {
        error = "a worker thread failed; no result generated";
        return false;
    }

    snapshot         = window_delta(counter_start, counter_end);
    snapshot.seconds = static_cast<double>(options.seconds);
    return true;
}

}  // namespace bench::chain
