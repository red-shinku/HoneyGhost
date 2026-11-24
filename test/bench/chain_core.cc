/**
 * @file chain_core.cc
 * @brief chain 段 sink 后端的装配与窗口测量
 * @details
 * 原始通道与语义通道各一条；真实语义组件、真实运行时引擎、真实 context
 * 维护器，控制面替身与语料全量种子来自 L1 头文件。feeder、语义、引擎三条
 * 线程分别命名后按 semantic → engine → feeder 启动，预热结束与窗口结束两个
 * 绝对时刻各采一次计数与线程 CPU，占用峰值由后台采样线程记录。
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

/// @brief 退出码：运行期失败，仅用于收尾超时后的兜底退出
constexpr int kExitRuntimeFailure = 1;

/// @brief 等待工作线程退出的上限；超过后告警并再等一次
constexpr std::chrono::seconds kThreadJoinLimit(2);
/// @brief 等待工作线程发布 tid 的上限
constexpr std::chrono::milliseconds kTidWaitLimit(1000);

/// @brief 回放线程名；PR_SET_NAME 只保留前 15 字节
constexpr char kFeederThreadName[]   = "hng-chain-feed";
/// @brief 语义线程名
constexpr char kSemanticThreadName[] = "hng-chain-sem";
/// @brief 引擎线程名
constexpr char kEngineThreadName[]   = "hng-chain-eng";

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
 * @brief 等待三条工作线程发布 tid
 * @param[in] feeder_tid 回放线程 tid
 * @param[in] semantic_tid 语义线程 tid
 * @param[in] engine_tid 引擎线程 tid
 * @param[out] error 失败原因
 * @return 三个 tid 都发布时为 true
 * @note 最多等待 1 秒；超时后列出尚未发布的线程。
 */
bool wait_for_tids(const std::atomic<pid_t>& feeder_tid,
                   const std::atomic<pid_t>& semantic_tid,
                   const std::atomic<pid_t>& engine_tid, std::string& error)
{
    const bench::Clock::time_point deadline = bench::Clock::now() + kTidWaitLimit;
    while (true) {
        const bool feeder_ready = feeder_tid.load(std::memory_order_acquire) != 0;
        const bool semantic_ready =
            semantic_tid.load(std::memory_order_acquire) != 0;
        const bool engine_ready = engine_tid.load(std::memory_order_acquire) != 0;
        if (feeder_ready && semantic_ready && engine_ready) {
            return true;
        }
        if (bench::Clock::now() >= deadline) {
            error = "等待线程 tid 发布超时（1s）：";
            if (!feeder_ready) {
                error += " feeder";
            }
            if (!semantic_ready) {
                error += " semantic";
            }
            if (!engine_ready) {
                error += " engine";
            }
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

/// @brief 三条工作线程的窗口 CPU 快照
struct CpuSample {
    double feeder   = 0.0;  ///< 回放线程
    double semantic = 0.0;  ///< 语义线程
    double engine   = 0.0;  ///< 引擎线程
};

/// @brief 窗口计数快照
struct CounterSample {
    std::uint64_t consumed           = 0;  ///< feeder 已回放记录数
    std::uint64_t consumed_lifecycle = 0;  ///< 其中 lifecycle 类的记录数
    std::uint64_t push_ok            = 0;  ///< feeder 成功入队次数
    std::uint64_t push_fail          = 0;  ///< feeder 被拒收次数
    std::uint64_t processed          = 0;  ///< 语义已处理数
    std::uint64_t dispatched         = 0;  ///< 引擎分发数
    std::uint64_t raw_drops          = 0;  ///< 原始通道拒收
    std::uint64_t sem_drops          = 0;  ///< 语义通道拒收
    std::uint64_t unsettled          = 0;  ///< 引擎未落定事件数
};

}  // namespace

namespace bench::chain {

bool run_chain_sink(const ChainOptions& options, ChainSnapshot& snapshot,
                    std::string& error)
{
    ChainFeeder feeder;
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

    // 通道由本函数持有；组件与线程只借用，声明顺序保证收尾后先析构线程与
    // 组件、再析构通道
    hng::EventChannel<struct syscall_event> raw_channel(
        static_cast<std::size_t>(options.queue));
    hng::EventChannel<hng::syscall_semantic_data> sem_channel(
        static_cast<std::size_t>(options.queue));

    bench::l1::FakeProcessJoin process_join;
    bench::l1::FakeProcessUpdate process_update;
    bench::l1::FakeProcessLookup process_lookup;
    bench::l1::FakeRoleJoin role_join;
    bench::l1::FakeRoleLookup role_lookup;
    bench::l1::FakeContextService context_service;
    ContextMaintainer maintainer;
    maintainer.set_context_service(&context_service, &context_service,
                                   &context_service);
    bench::l1::SeedCounts seeds;
    bench::l1::seed_services(seed_events, options.settled, process_lookup,
                             role_lookup, context_service, seeds);

    std::vector<std::unique_ptr<CountSystemSink>> system_sinks;
    system_sinks.reserve(static_cast<std::size_t>(options.system_sinks));
    for (int index = 0; index < options.system_sinks; ++index) {
        system_sinks.push_back(std::make_unique<CountSystemSink>());
    }

    std::unique_ptr<hng::SemanticComponent> semantic;
    std::unique_ptr<hng::RuntimeEngineComponent> engine;
    try {
        hng::SemanticOptions semantic_settings;
        semantic_settings.raw_syscall = &raw_channel.reader();
        semantic_settings.out_syscall = &sem_channel.writer();
        semantic = hng::SemanticFactory::create(semantic_settings);
        if (!semantic) {
            error = "语义组件构造失败：工厂未返回实例";
            return false;
        }

        hng::RuntimeEngineOptions engine_settings;
        engine_settings.syscall_input  = &sem_channel.reader();
        engine_settings.ctx_maintainer = &maintainer;
        engine_settings.process_join   = &process_join;
        engine_settings.process_update = &process_update;
        engine_settings.process_lookup = &process_lookup;
        engine_settings.role_join      = &role_join;
        engine_settings.role_lookup    = &role_lookup;
        engine = hng::RuntimeEngineFactory::create(engine_settings);
        if (!engine) {
            error = "引擎构造失败：工厂未返回实例";
            return false;
        }
        for (const std::unique_ptr<CountSystemSink>& sink : system_sinks) {
            engine->add_system_sink(sink.get());
        }
    }
    catch (const std::exception& failure) {
        error = std::string("流水线组件构造失败：") + failure.what();
        return false;
    }

    std::atomic<bool> feeder_stop{false};
    std::atomic<pid_t> feeder_tid{0};
    std::atomic<pid_t> semantic_tid{0};
    std::atomic<pid_t> engine_tid{0};
    std::atomic<bool> semantic_done{false};
    std::atomic<bool> engine_done{false};
    std::atomic<bool> semantic_failed{false};
    std::atomic<bool> engine_failed{false};

    const bench::Clock::time_point run_start = bench::Clock::now();
    const bench::Clock::time_point measure_start =
        run_start + std::chrono::seconds(options.warmup_seconds);
    const bench::Clock::time_point measure_end =
        measure_start + std::chrono::seconds(options.seconds);

    // 上游最后启动：语义与引擎的消费线程先进入等待，回放随即开始
    std::thread semantic_thread([&] {
        semantic_tid.store(::gettid(), std::memory_order_release);
        (void)::prctl(PR_SET_NAME, kSemanticThreadName);
        try {
            semantic->run();
        }
        catch (const std::exception& failure) {
            std::fprintf(stderr, "语义线程失败：%s\n", failure.what());
            semantic_failed.store(true, std::memory_order_release);
        }
        catch (...) {
            std::fprintf(stderr, "语义线程失败：未知异常\n");
            semantic_failed.store(true, std::memory_order_release);
        }
        semantic_done.store(true, std::memory_order_release);
    });

    std::thread engine_thread([&] {
        engine_tid.store(::gettid(), std::memory_order_release);
        (void)::prctl(PR_SET_NAME, kEngineThreadName);
        try {
            engine->run();
        }
        catch (const std::exception& failure) {
            std::fprintf(stderr, "引擎线程失败：%s\n", failure.what());
            engine_failed.store(true, std::memory_order_release);
        }
        catch (...) {
            std::fprintf(stderr, "引擎线程失败：未知异常\n");
            engine_failed.store(true, std::memory_order_release);
        }
        engine_done.store(true, std::memory_order_release);
    });

    std::thread feeder_thread([&] {
        feeder_tid.store(::gettid(), std::memory_order_release);
        (void)::prctl(PR_SET_NAME, kFeederThreadName);
        feeder.run(raw_channel.writer(), feeder_stop, options.rate);
    });

    // 收尾顺序：先停回放，再停语义并等它排空，最后停引擎；任何提前返回
    // 都调用本闭包，不留下可 join 的线程
    bool threads_stopped    = false;
    const auto stop_threads = [&]() {
        if (threads_stopped) {
            return;
        }
        threads_stopped = true;
        feeder_stop.store(true, std::memory_order_release);
        if (feeder_thread.joinable()) {
            feeder_thread.join();
        }
        semantic->stop();
        if (semantic_thread.joinable() &&
            !wait_for_thread(semantic_thread, semantic_done, kThreadJoinLimit)) {
            std::fprintf(stderr, "告警：语义线程在 %lld 秒内未退出，再等一次\n",
                         static_cast<long long>(kThreadJoinLimit.count()));
            if (!wait_for_thread(semantic_thread, semantic_done,
                                 kThreadJoinLimit)) {
                std::fprintf(stderr, "语义线程仍未退出，退出进程\n");
                std::_Exit(kExitRuntimeFailure);
            }
        }
        engine->stop();
        if (engine_thread.joinable() &&
            !wait_for_thread(engine_thread, engine_done, kThreadJoinLimit)) {
            std::fprintf(stderr, "告警：引擎线程在 %lld 秒内未退出，再等一次\n",
                         static_cast<long long>(kThreadJoinLimit.count()));
            if (!wait_for_thread(engine_thread, engine_done, kThreadJoinLimit)) {
                std::fprintf(stderr, "引擎线程仍未退出，退出进程\n");
                std::_Exit(kExitRuntimeFailure);
            }
        }
        raw_channel.writer().close();
        sem_channel.writer().close();
    };

    if (!wait_for_tids(feeder_tid, semantic_tid, engine_tid, error)) {
        std::fprintf(stderr, "%s\n", error.c_str());
        stop_threads();
        return false;
    }

    const auto sample_cpu = [&](CpuSample& sample) -> bool {
        const std::uint64_t feeder_id = static_cast<std::uint64_t>(
            feeder_tid.load(std::memory_order_acquire));
        if (!bench::read_thread_cpu(feeder_id, sample.feeder, error)) {
            error = "读取回放线程 CPU 失败：" + error;
            return false;
        }
        const std::uint64_t semantic_id = static_cast<std::uint64_t>(
            semantic_tid.load(std::memory_order_acquire));
        if (!bench::read_thread_cpu(semantic_id, sample.semantic, error)) {
            error = "读取语义线程 CPU 失败：" + error;
            return false;
        }
        const std::uint64_t engine_id = static_cast<std::uint64_t>(
            engine_tid.load(std::memory_order_acquire));
        if (!bench::read_thread_cpu(engine_id, sample.engine, error)) {
            error = "读取引擎线程 CPU 失败：" + error;
            return false;
        }
        return true;
    };

    const auto sample_counters = [&](CounterSample& sample) {
        const FeederCounters feeder_counters = feeder.counters();
        sample.consumed                      = feeder_counters.consumed;
        sample.consumed_lifecycle            = feeder_counters.consumed_lifecycle;
        sample.push_ok                       = feeder_counters.push_ok;
        sample.push_fail                     = feeder_counters.push_fail;

        const hng::SemanticStats semantic_stats = semantic->stats();
        sample.processed               = semantic_stats.processed_syscall;

        std::uint64_t dispatched_total = 0;
        for (const std::unique_ptr<CountSystemSink>& sink : system_sinks) {
            dispatched_total += sink->count();
        }
        const std::uint64_t sink_count =
            static_cast<std::uint64_t>(system_sinks.size());
        sample.dispatched = sink_count == 0 ? 0 : dispatched_total / sink_count;

        sample.raw_drops =
            raw_channel.reader().dropped() + raw_channel.reader().rejected();
        sample.sem_drops =
            sem_channel.reader().dropped() + sem_channel.reader().rejected();
        sample.unsettled = engine->stats().unsettled_events;
    };

    std::this_thread::sleep_until(measure_start);
    CpuSample cpu_start;
    if (!sample_cpu(cpu_start)) {
        std::fprintf(stderr, "%s\n", error.c_str());
        stop_threads();
        return false;
    }
    CounterSample counter_start;
    sample_counters(counter_start);

    // EventChannel::size() 只保证单线程观察；第三方线程采样可能读到瞬时
    // 不一致的 head/tail 而下溢，超出容量的样本视为无效并丢弃
    const std::size_t capacity = channel_capacity(options.queue);
    bench::OccupancySampler raw_occupancy([&raw_channel, capacity] {
        const std::size_t value = raw_channel.size();
        return value <= capacity ? value : 0;
    });
    raw_occupancy.start();
    bench::OccupancySampler sem_occupancy([&sem_channel, capacity] {
        const std::size_t value = sem_channel.size();
        return value <= capacity ? value : 0;
    });
    sem_occupancy.start();

    std::this_thread::sleep_until(measure_end);
    CpuSample cpu_end;
    if (!sample_cpu(cpu_end)) {
        raw_occupancy.stop();
        sem_occupancy.stop();
        std::fprintf(stderr, "%s\n", error.c_str());
        stop_threads();
        return false;
    }
    CounterSample counter_end;
    sample_counters(counter_end);
    raw_occupancy.stop();
    sem_occupancy.stop();

    stop_threads();

    if (semantic_failed.load(std::memory_order_acquire) ||
        engine_failed.load(std::memory_order_acquire)) {
        error = "语义或引擎线程失败，未生成结果";
        return false;
    }

    const auto delta = [](std::uint64_t end, std::uint64_t start) {
        return end >= start ? end - start : 0;
    };
    const auto cpu_delta = [](double end, double start) {
        return end >= start ? end - start : 0.0;
    };

    snapshot           = ChainSnapshot{};
    snapshot.seconds   = static_cast<double>(options.seconds);
    snapshot.records   = feeder.records().size();
    snapshot.playback  = feeder.playback().size();
    snapshot.malformed = feeder.malformed();
    snapshot.consumed  = delta(counter_end.consumed, counter_start.consumed);
    snapshot.consumed_lifecycle =
        delta(counter_end.consumed_lifecycle, counter_start.consumed_lifecycle);
    snapshot.push_ok    = delta(counter_end.push_ok, counter_start.push_ok);
    snapshot.push_fail  = delta(counter_end.push_fail, counter_start.push_fail);
    snapshot.processed  = delta(counter_end.processed, counter_start.processed);
    snapshot.dispatched = delta(counter_end.dispatched, counter_start.dispatched);
    snapshot.raw_drops  = delta(counter_end.raw_drops, counter_start.raw_drops);
    snapshot.sem_drops  = delta(counter_end.sem_drops, counter_start.sem_drops);
    snapshot.unsettled  = delta(counter_end.unsettled, counter_start.unsettled);
    snapshot.raw_peak   = raw_occupancy.peak();
    snapshot.sem_peak   = sem_occupancy.peak();
    snapshot.feeder_cpu = cpu_delta(cpu_end.feeder, cpu_start.feeder);
    snapshot.semantic_cpu = cpu_delta(cpu_end.semantic, cpu_start.semantic);
    snapshot.engine_cpu   = cpu_delta(cpu_end.engine, cpu_start.engine);
    return true;
}

}  // namespace bench::chain
