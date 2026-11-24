/**
 * @file bench_semantic.cc
 * @brief 语义段压测：原始通道 → 语义聚合 → 语义通道
 * @details
 * 语料全部读入内存后循环回放。生产者按「head memcpy + payload memcpy」重建
 * 栈上的 syscall_event 再推入原始通道；语义线程用 SemanticFactory 构造的组件
 * 消费原始通道；语义通道由一条只取空、不做事、不构造语义数据的线程排空。
 *
 * 三条工作线程启动后发布各自的 tid，主线程在预热结束与窗口结束两个时刻读
 * /proc/self/task/<tid>/stat，得到只覆盖统计窗口的 CPU 时间。
 *
 * --no-semantic 跳过语义组件，只保留生产者与原始通道取空线程，用于测生产者
 * 天花板。语料格式见 test/bench/bench_trace.hpp。
 */

#include "test/bench/stages.hpp"
#include "test/bench/bench_trace.hpp"

#include "agent/event_data/include/syscall_event.hpp"
#include "agent/semantic/include/semantic_factory.hpp"
#include "agent/util/include/event_channel.hpp"
#include "kernel/include/syscall_event_type.h"

#include <poll.h>
#include <sys/types.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cinttypes>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace {

/// @brief 退出码：运行期失败
constexpr int kExitRuntimeFailure = 1;
/// @brief 退出码：参数错误
constexpr int kExitUsage          = 3;

/// @brief 取空线程轮询唤醒 fd 的间隔，仅用于防住意外丢失的唤醒
constexpr int kDrainPollMs        = 10;
/// @brief 等待取空线程退出的上限；超过后告警并再等一次
constexpr std::chrono::seconds kDrainJoinLimit(2);
/// @brief 等待工作线程发布 tid 的上限
constexpr std::chrono::milliseconds kTidWaitLimit(1000);

/// @brief 语义段私有选项的多行用法
constexpr const char* kExtraHelp =
    "  --events MODE     回放类别：all|syscall|lifecycle（默认 all）；PROCESS 与 "
    "EXEC 归为 lifecycle，在转换前按原始记录过滤\n"
    "  --no-semantic     只跑生产者与原始通道取空线程，测生产者天花板\n";

/// @brief 回放的事件类别
enum class EventClass : std::uint8_t { ALL, SYSCALL, LIFECYCLE };

/// @brief 类别在命令行与结果配置里的名字
const char* event_class_name(EventClass value)
{
    switch (value) {
        case EventClass::SYSCALL:
            return "syscall";
        case EventClass::LIFECYCLE:
            return "lifecycle";
        case EventClass::ALL:
            break;
    }
    return "all";
}

/// @brief 语义子类型是否属于生命周期类（进程与 exec）
bool is_lifecycle_class(enum syscall_event_type subtype)
{
    return subtype == PROCESS_EVENT || subtype == EXEC_EVENT;
}

/// @brief 该子类型是否落在所选类别里
bool class_selected(EventClass mode, enum syscall_event_type subtype)
{
    switch (mode) {
        case EventClass::SYSCALL:
            return !is_lifecycle_class(subtype);
        case EventClass::LIFECYCLE:
            return is_lifecycle_class(subtype);
        case EventClass::ALL:
            break;
    }
    return true;
}

/// @brief 语义段私有选项
struct SemanticStageOptions {
    EventClass events = EventClass::ALL;  ///< 回放类别
    bool no_semantic  = false;            ///< 跳过语义组件
};

/// @brief 读入内存的语料
struct TraceData {
    std::vector<std::vector<char>> records;  ///< 逐条记录，含 head 原文
    std::uint64_t skipped = 0;               ///< 尺寸不合法而跳过的条数
};

/**
 * @brief 读入并校验语料，在转换前按类别过滤记录
 * @param[in] path 语料路径
 * @param[in] events 参与回放的类别；被排除的记录不进入生产者
 * @param[out] data 读入结果
 * @param[out] error 失败原因
 * @return 成功时为 true
 * @note 记录尺寸须不小于 syscall_event_head 且不大于 syscall_event；尺寸非法
 *       的记录跳过并计数。全部尺寸非法或所选类别为空时返回 false。
 */
bool load_trace(const std::string& path, EventClass events, TraceData& data,
                std::string& error)
{
    bench::TraceReader reader;
    std::string reader_error;
    if (!reader.open(path, reader_error)) {
        error = "打开语料 " + path + " 失败：" + reader_error;
        return false;
    }

    std::vector<char> record;
    while (reader.next(record, reader_error)) {
        if (record.size() < sizeof(struct syscall_event_head) ||
            record.size() > sizeof(struct syscall_event)) {
            ++data.skipped;
            continue;
        }
        struct syscall_event_head head;
        std::memcpy(&head, record.data(), sizeof(head));
        if (!class_selected(events, head.subtype)) {
            continue;
        }
        data.records.push_back(record);
    }
    if (!reader_error.empty()) {
        error = "读取语料 " + path + " 失败：" + reader_error;
        return false;
    }
    if (data.records.empty()) {
        error = "语料 " + path + " 在 --events " + event_class_name(events) +
                " 下没有可回放的事件（尺寸非法 " + std::to_string(data.skipped) +
                " 条）";
        return false;
    }
    return true;
}

/// @brief 按 head + payload 两段把语料记录拷进栈上事件
void rebuild_event(const std::vector<char>& record, struct syscall_event& event)
{
    std::memcpy(&event.hdr, record.data(), sizeof(event.hdr));
    std::memcpy(reinterpret_cast<char*>(&event) + sizeof(event.hdr),
                record.data() + sizeof(event.hdr),
                record.size() - sizeof(event.hdr));
}

/// @brief 通道容量向上取整为 2 的幂，与 SPSC_Queue 的容量语义一致
std::size_t channel_capacity(int queue)
{
    std::size_t capacity = 1;
    while (capacity < static_cast<std::size_t>(queue)) {
        capacity <<= 1;
    }
    return capacity;
}

/**
 * @brief 持续取空并丢弃一个通道，直到写端关闭且队列取空
 * @param[in,out] reader 通道读端
 * @param[out] done 退出标志
 */
template <class T>
void drain_until_closed(hng::EventChannelReader<T>& reader,
                        std::atomic<bool>& done)
{
    T item;
    while (true) {
        if (reader.try_pop(item)) {
            continue;
        }
        if (reader.closed()) {
            break;
        }
        struct pollfd descriptor;
        descriptor.fd      = reader.fd();
        descriptor.events  = POLLIN;
        descriptor.revents = 0;
        (void)::poll(&descriptor, 1, kDrainPollMs);
    }
    done.store(true, std::memory_order_release);
}

/// @brief 等待取空线程退出并 join；超时返回 false 且不 join
bool wait_for_drain(std::thread& thread, const std::atomic<bool>& done,
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
 * @brief 等待工作线程发布 tid
 * @param[in] producer_tid 生产者线程 tid
 * @param[in] semantic_tid 语义线程 tid，--no-semantic 时不要求
 * @param[in] drain_tid 取空线程 tid
 * @param[in] no_semantic 是否跳过语义线程
 * @param[out] error 失败原因
 * @return 三条线程的 tid 都发布时为 true
 * @note 最多等待 1 秒；超时后列出尚未发布的线程。
 */
bool wait_for_tids(const std::atomic<pid_t>& producer_tid,
                   const std::atomic<pid_t>& semantic_tid,
                   const std::atomic<pid_t>& drain_tid, bool no_semantic,
                   std::string& error)
{
    const bench::Clock::time_point deadline = bench::Clock::now() + kTidWaitLimit;
    while (true) {
        const bool producer_ready =
            producer_tid.load(std::memory_order_acquire) != 0;
        const bool semantic_ready =
            no_semantic || semantic_tid.load(std::memory_order_acquire) != 0;
        const bool drain_ready = drain_tid.load(std::memory_order_acquire) != 0;
        if (producer_ready && semantic_ready && drain_ready) {
            return true;
        }
        if (bench::Clock::now() >= deadline) {
            error = "等待线程 tid 发布超时（1s）：";
            if (!producer_ready) {
                error += " producer";
            }
            if (!semantic_ready) {
                error += " semantic";
            }
            if (!drain_ready) {
                error += " drain";
            }
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

/// @brief 三条工作线程的窗口 CPU 快照
struct CpuSnapshot {
    double producer = 0.0;  ///< 生产者线程
    double semantic = 0.0;  ///< 语义线程
    double drain    = 0.0;  ///< 取空线程
};

/// @brief 窗口计数快照
struct CounterSnapshot {
    std::uint64_t events            = 0;  ///< 语义 processed 或 push 成功
    std::uint64_t raw_drops         = 0;  ///< 原始通道 dropped + rejected
    std::uint64_t out_drops         = 0;  ///< 语义通道 dropped + rejected
    std::uint64_t push_calls        = 0;  ///< 生产者 push 尝试次数
    std::uint64_t push_ok           = 0;  ///< 生产者 push 成功次数
    std::uint64_t push_ok_syscall   = 0;  ///< 成功入队的 syscall 类记录数
    std::uint64_t push_ok_lifecycle = 0;  ///< 成功入队的 lifecycle 类记录数
};

/// @brief 拆出 --name 或 --name=value；不是长选项时返回 false
bool split_option(const std::string& raw, std::string& name, std::string& value,
                  bool& has_value)
{
    if (raw.size() < 2 || raw[0] != '-' || raw[1] != '-') {
        return false;
    }
    const std::size_t equals = raw.find('=');
    if (equals == std::string::npos) {
        name = raw;
        value.clear();
        has_value = false;
        return true;
    }
    name.assign(raw, 0, equals);
    value.assign(raw, equals + 1, std::string::npos);
    has_value = true;
    return true;
}

/**
 * @brief 解析语义段私有选项
 * @param[in] rest 入口未识别的参数，保持原序
 * @param[out] options 解析结果
 * @param[out] error 失败原因
 * @return 解析成功时为 true
 * @note 支持 --name value 与 --name=value 两种写法。
 */
bool parse_rest(const std::vector<std::string>& rest,
                SemanticStageOptions& options, std::string& error)
{
    for (std::size_t index = 0; index < rest.size(); ++index) {
        std::string name;
        std::string inline_value;
        bool has_inline = false;
        if (!split_option(rest[index], name, inline_value, has_inline)) {
            error = "未知选项 " + rest[index];
            return false;
        }

        const auto take_value = [&](std::string& out) -> bool {
            if (has_inline) {
                out = inline_value;
                return true;
            }
            if (index + 1 >= rest.size()) {
                return false;
            }
            out = rest[++index];
            return true;
        };

        if (name == "--no-semantic") {
            if (has_inline) {
                error = "--no-semantic 不接受取值";
                return false;
            }
            options.no_semantic = true;
            continue;
        }
        if (name == "--events") {
            std::string text;
            if (!take_value(text)) {
                error = "--events 缺少取值";
                return false;
            }
            if (text == "all") {
                options.events = EventClass::ALL;
            }
            else if (text == "syscall") {
                options.events = EventClass::SYSCALL;
            }
            else if (text == "lifecycle") {
                options.events = EventClass::LIFECYCLE;
            }
            else {
                error = "--events 需为 all|syscall|lifecycle";
                return false;
            }
            continue;
        }
        error = "未知选项 " + name;
        return false;
    }
    return true;
}

/// @brief 语义段实现
int run_semantic(const bench::CommonOptions& options,
                 const std::vector<std::string>& rest)
{
    SemanticStageOptions stage_options;
    std::string error;
    if (!parse_rest(rest, stage_options, error)) {
        std::fprintf(stderr, "参数错误：%s\n", error.c_str());
        std::fprintf(stderr, "semantic 段选项：\n%s", kExtraHelp);
        return kExitUsage;
    }
    const bool no_semantic = stage_options.no_semantic;

    TraceData trace;
    if (!load_trace(options.trace_path, stage_options.events, trace, error)) {
        std::fprintf(stderr, "%s\n", error.c_str());
        return kExitRuntimeFailure;
    }

    // 通道由本函数持有，读写端只借用
    hng::EventChannel<struct syscall_event> raw(
        static_cast<std::size_t>(options.queue));
    hng::EventChannel<hng::syscall_semantic_data> out(
        static_cast<std::size_t>(options.queue));

    // 组件必须在任何线程启动前构造，构造失败时没有需要回收的线程
    std::unique_ptr<hng::SemanticComponent> semantic;
    if (!no_semantic) {
        hng::SemanticOptions semantic_options;
        semantic_options.raw_syscall = &raw.reader();
        semantic_options.out_syscall = &out.writer();
        semantic = hng::SemanticFactory::create(semantic_options);
        if (!semantic) {
            std::fprintf(stderr, "语义组件构造失败：工厂未返回实例\n");
            return kExitRuntimeFailure;
        }
    }

    std::atomic<bool> producer_stop{false};
    std::atomic<std::uint64_t> push_calls{0};
    std::atomic<std::uint64_t> push_ok{0};
    std::atomic<std::uint64_t> push_failed{0};
    // 成功入队记录的类别计数，用于人类输出的 events by class
    std::atomic<std::uint64_t> push_ok_syscall{0};
    std::atomic<std::uint64_t> push_ok_lifecycle{0};
    std::atomic<pid_t> producer_tid{0};
    std::atomic<pid_t> semantic_tid{0};
    std::atomic<pid_t> drain_tid{0};
    std::atomic<bool> drain_done{false};

    const bench::Clock::time_point run_start = bench::Clock::now();
    std::unique_ptr<bench::Pacer> pacer;
    if (options.rate > 0.0) {
        pacer = std::make_unique<bench::Pacer>(options.rate);
    }
    const bench::Clock::time_point measure_start =
        run_start + std::chrono::seconds(options.warmup_seconds);
    const bench::Clock::time_point measure_end =
        measure_start + std::chrono::seconds(options.seconds);

    std::thread producer([&] {
        producer_tid.store(::gettid(), std::memory_order_release);
        if (options.pin_producer >= 0) {
            std::string pin_error;
            if (!bench::pin_this_thread(options.pin_producer, pin_error)) {
                std::fprintf(stderr, "生产者绑核失败：%s\n", pin_error.c_str());
            }
        }
        std::uint64_t index = 0;
        while (!producer_stop.load(std::memory_order_acquire)) {
            for (const std::vector<char>& record : trace.records) {
                if (producer_stop.load(std::memory_order_relaxed)) {
                    break;
                }
                if (pacer) {
                    (void)pacer->wait(index);
                }
                ++index;

                struct syscall_event event;
                rebuild_event(record, event);
                const bool lifecycle = is_lifecycle_class(event.hdr.subtype);
                push_calls.fetch_add(1, std::memory_order_relaxed);
                if (raw.writer().push(std::move(event))) {
                    push_ok.fetch_add(1, std::memory_order_relaxed);
                    if (lifecycle) {
                        push_ok_lifecycle.fetch_add(1, std::memory_order_relaxed);
                    }
                    else {
                        push_ok_syscall.fetch_add(1, std::memory_order_relaxed);
                    }
                }
                else {
                    push_failed.fetch_add(1, std::memory_order_relaxed);
                }
            }
        }
    });

    std::thread semantic_thread;
    if (!no_semantic) {
        semantic_thread = std::thread([&] {
            semantic_tid.store(::gettid(), std::memory_order_release);
            if (options.pin_consumer >= 0) {
                std::string pin_error;
                if (!bench::pin_this_thread(options.pin_consumer, pin_error)) {
                    std::fprintf(stderr, "语义线程绑核失败：%s\n",
                                 pin_error.c_str());
                }
            }
            semantic->run();
        });
    }

    std::thread drain_thread([&] {
        drain_tid.store(::gettid(), std::memory_order_release);
        if (no_semantic && options.pin_consumer >= 0) {
            std::string pin_error;
            if (!bench::pin_this_thread(options.pin_consumer, pin_error)) {
                std::fprintf(stderr, "取空线程绑核失败：%s\n", pin_error.c_str());
            }
        }
        if (no_semantic) {
            drain_until_closed(raw.reader(), drain_done);
        }
        else {
            drain_until_closed(out.reader(), drain_done);
        }
    });

    // 收尾顺序：先停生产者，再停语义并等它排空，最后等取空线程
    bool threads_stopped    = false;
    const auto stop_threads = [&]() {
        if (threads_stopped) {
            return;
        }
        threads_stopped = true;
        producer_stop.store(true, std::memory_order_release);
        if (producer.joinable()) {
            producer.join();
        }
        if (no_semantic) {
            raw.writer().close();
        }
        else {
            semantic->stop();
            if (semantic_thread.joinable()) {
                semantic_thread.join();
            }
            // 语义线程可能尚未进入 run()（tid 等待超时等早退路径），
            // 这里确保语义通道关闭，取空线程不会无限等待
            out.writer().close();
        }
        if (drain_thread.joinable()) {
            if (!wait_for_drain(drain_thread, drain_done, kDrainJoinLimit)) {
                std::fprintf(stderr,
                             "告警：取空线程在 %lld 秒内未退出，再等一次\n",
                             static_cast<long long>(kDrainJoinLimit.count()));
                if (!wait_for_drain(drain_thread, drain_done, kDrainJoinLimit)) {
                    std::fprintf(stderr, "取空线程仍未退出，退出进程\n");
                    std::_Exit(kExitRuntimeFailure);
                }
            }
        }
    };

    if (!wait_for_tids(producer_tid, semantic_tid, drain_tid, no_semantic,
                       error)) {
        std::fprintf(stderr, "%s\n", error.c_str());
        stop_threads();
        return kExitRuntimeFailure;
    }

    const auto sample_cpu = [&](CpuSnapshot& snapshot,
                                std::string& sample_error) -> bool {
        const std::uint64_t producer_id = static_cast<std::uint64_t>(
            producer_tid.load(std::memory_order_acquire));
        if (!bench::read_thread_cpu(producer_id, snapshot.producer,
                                    sample_error)) {
            sample_error = "读取生产者线程 CPU 失败：" + sample_error;
            return false;
        }
        if (!no_semantic) {
            const std::uint64_t semantic_id = static_cast<std::uint64_t>(
                semantic_tid.load(std::memory_order_acquire));
            if (!bench::read_thread_cpu(semantic_id, snapshot.semantic,
                                        sample_error)) {
                sample_error = "读取语义线程 CPU 失败：" + sample_error;
                return false;
            }
        }
        const std::uint64_t drain_id =
            static_cast<std::uint64_t>(drain_tid.load(std::memory_order_acquire));
        if (!bench::read_thread_cpu(drain_id, snapshot.drain, sample_error)) {
            sample_error = "读取取空线程 CPU 失败：" + sample_error;
            return false;
        }
        return true;
    };

    const auto sample_counters = [&](CounterSnapshot& snapshot) {
        snapshot.raw_drops = raw.reader().dropped() + raw.reader().rejected();
        snapshot.out_drops =
            no_semantic ? 0 : out.reader().dropped() + out.reader().rejected();
        snapshot.push_calls = push_calls.load(std::memory_order_relaxed);
        snapshot.push_ok    = push_ok.load(std::memory_order_relaxed);
        snapshot.push_ok_syscall =
            push_ok_syscall.load(std::memory_order_relaxed);
        snapshot.push_ok_lifecycle =
            push_ok_lifecycle.load(std::memory_order_relaxed);
        snapshot.events =
            no_semantic ? snapshot.push_ok : semantic->stats().processed_syscall;
    };

    std::this_thread::sleep_until(measure_start);
    CpuSnapshot cpu_start;
    CounterSnapshot counter_start;
    if (!sample_cpu(cpu_start, error)) {
        std::fprintf(stderr, "%s\n", error.c_str());
        stop_threads();
        return kExitRuntimeFailure;
    }
    sample_counters(counter_start);

    // EventChannel::size() 只保证单线程观察；第三方线程采样可能读到瞬时
    // 不一致的 head/tail 而下溢，超出容量的样本视为无效并丢弃
    const std::size_t capacity = channel_capacity(options.queue);
    bench::OccupancySampler raw_occupancy([&raw, capacity] {
        const std::size_t value = raw.size();
        return value <= capacity ? value : 0;
    });
    raw_occupancy.start();
    std::unique_ptr<bench::OccupancySampler> out_occupancy;
    if (!no_semantic) {
        out_occupancy =
            std::make_unique<bench::OccupancySampler>([&out, capacity] {
                const std::size_t value = out.size();
                return value <= capacity ? value : 0;
            });
        out_occupancy->start();
    }

    std::this_thread::sleep_until(measure_end);
    CpuSnapshot cpu_end;
    if (!sample_cpu(cpu_end, error)) {
        raw_occupancy.stop();
        if (out_occupancy) {
            out_occupancy->stop();
        }
        std::fprintf(stderr, "%s\n", error.c_str());
        stop_threads();
        return kExitRuntimeFailure;
    }
    CounterSnapshot counter_end;
    sample_counters(counter_end);
    raw_occupancy.stop();
    if (out_occupancy) {
        out_occupancy->stop();
    }

    stop_threads();

    const auto delta = [](std::uint64_t end, std::uint64_t start) {
        return end >= start ? end - start : 0;
    };
    const auto cpu_delta = [](double end, double start) {
        return end >= start ? end - start : 0.0;
    };

    const std::uint64_t events = delta(counter_end.events, counter_start.events);
    const std::uint64_t raw_drops =
        delta(counter_end.raw_drops, counter_start.raw_drops);
    const std::uint64_t out_drops =
        delta(counter_end.out_drops, counter_start.out_drops);
    const std::uint64_t drops = raw_drops + out_drops;
    const std::uint64_t calls =
        delta(counter_end.push_calls, counter_start.push_calls);
    const std::uint64_t pushes_ok =
        delta(counter_end.push_ok, counter_start.push_ok);
    const std::uint64_t pushes_failed =
        calls >= pushes_ok ? calls - pushes_ok : 0;
    const std::uint64_t syscall_events =
        delta(counter_end.push_ok_syscall, counter_start.push_ok_syscall);
    const std::uint64_t lifecycle_events =
        delta(counter_end.push_ok_lifecycle, counter_start.push_ok_lifecycle);
    const double producer_cpu   = cpu_delta(cpu_end.producer, cpu_start.producer);
    const double semantic_cpu   = cpu_delta(cpu_end.semantic, cpu_start.semantic);
    const double drain_cpu      = cpu_delta(cpu_end.drain, cpu_start.drain);
    const double window_seconds = static_cast<double>(options.seconds);

    bench::Result result;
    result.stage  = "semantic";
    result.config = std::string("fidelity=") +
                    bench::fidelity_name(options.fidelity) +
                    ",events=" + event_class_name(stage_options.events) +
                    ",queue=" + std::to_string(options.queue) +
                    (no_semantic ? ",no-semantic" : "");
    result.rate    = options.rate;
    result.seconds = window_seconds;
    result.events  = events;
    result.events_per_s =
        window_seconds > 0.0 ? static_cast<double>(events) / window_seconds : 0.0;
    result.us_per_event = (!no_semantic && events > 0)
                              ? semantic_cpu * 1e6 / static_cast<double>(events)
                              : 0.0;
    result.producer_us_per_event =
        calls > 0 ? producer_cpu * 1e6 / static_cast<double>(calls) : 0.0;
    result.producer_us_per_success =
        pushes_ok > 0 ? producer_cpu * 1e6 / static_cast<double>(pushes_ok) : 0.0;
    result.drops          = drops;
    result.raw_drops      = raw_drops;
    result.out_drops      = out_drops;
    result.rss_kb         = bench::rss_kb();
    result.peak_queue     = raw_occupancy.peak();
    result.out_peak_queue = out_occupancy ? out_occupancy->peak() : 0;

    bench::print_human(result, options);
    std::printf("events by class: syscall=%" PRIu64 " lifecycle=%" PRIu64
                "（按成功入队记录统计）\n",
                syscall_events, lifecycle_events);
    if (out_drops > 0) {
        std::fprintf(stderr,
                     "提示：out 通道丢弃 %" PRIu64
                     " 次，语义 push 被下游取空丢弃；"
                     "下游取空可能不是瓶颈\n",
                     out_drops);
    }
    std::printf("pacer overruns=%" PRIu64
                " (落后节拍次数，不代表丢事件) push_calls=%" PRIu64
                " push_failed=%" PRIu64 " skipped=%" PRIu64 "\n",
                pacer ? pacer->overruns() : 0, calls, pushes_failed,
                trace.skipped);
    if (options.rate == 0.0 && raw_drops > 0) {
        std::printf(
            "提示：rate=0 时生产者以单核自旋重试，读数含缓存行争用；"
            "容量请取 0 丢的最高限速（用 --rate 扫描）\n");
    }
    std::printf("window cpu: producer=%.3fs semantic=%.3fs drain=%.3fs\n",
                producer_cpu, semantic_cpu, drain_cpu);
    if (!no_semantic) {
        std::printf(
            "注意：本段取空线程会立即取空输出通道，唤醒按事件计；"
            "该数字是下游零积压下的下界，生产下游（引擎）通常存在积压\n");
    }
    if (no_semantic) {
        std::printf("no-semantic: 无语义线程\n");
    }
    if (!bench::append_tsv(options.out_path, result)) {
        std::fprintf(
            stderr, "写 TSV 失败：%s\n",
            options.out_path.empty() ? "stdout" : options.out_path.c_str());
        return kExitRuntimeFailure;
    }
    return 0;
}

bench::StageSpec make_semantic_stage()
{
    bench::StageSpec stage;
    stage.name           = "semantic";
    stage.extra_help     = kExtraHelp;
    stage.requires_trace = true;
    stage.supports_l2    = false;
    stage.run            = &run_semantic;
    return stage;
}

}  // namespace

namespace bench {

const StageSpec& semantic_stage()
{
    static const StageSpec stage = make_semantic_stage();
    return stage;
}

}  // namespace bench
