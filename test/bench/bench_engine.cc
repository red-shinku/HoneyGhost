/**
 * @file bench_engine.cc
 * @brief 引擎段压测：语义通道 → RuntimeEngineComponent → 订阅端
 * @details
 * 在测量开始前读取 raw 语料并离线语义化、常驻内存。
 * 真实引擎组件在独立线程上消费、组装运行时事件并分发给计数订阅端。
 */

#include "test/bench/stages.hpp"
#include "test/bench/bench_trace.hpp"
#include "test/bench/l1_control_plane.hpp"
#include "test/bench/l2_control_plane.hpp"

#include "agent/context_maintainer/include/context_maintainer.hpp"
#include "agent/control_plane/include/process_service.hpp"
#include "agent/event_data/include/runtime_event.hpp"
#include "agent/event_data/include/runtime_info_filter.hpp"
#include "agent/event_data/include/syscall_event.hpp"
#include "agent/runtime_engine/include/runtime_decision_sink.hpp"
#include "agent/runtime_engine/include/runtime_engine_component.hpp"
#include "agent/runtime_engine/include/runtime_engine_factory.hpp"
#include "agent/runtime_engine/include/runtime_event_sink.hpp"
#include "agent/semantic/src/semantic.hpp"
#include "agent/util/include/event_channel.hpp"
#include "kernel/include/syscall_event_type.h"

#include <poll.h>
#include <sys/types.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <chrono>
#include <cinttypes>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <variant>
#include <vector>

namespace {

/// @brief 退出码：运行期失败
constexpr int kExitRuntimeFailure = 1;
/// @brief 退出码：参数错误
constexpr int kExitUsage          = 3;

/// @brief 取空线程轮询唤醒 fd 的间隔，仅用于防住意外丢失的唤醒
constexpr int kDrainPollMs        = 10;
/// @brief 等待工作线程退出的上限；超过后告警并再等一次
constexpr std::chrono::seconds kThreadJoinLimit(2);
/// @brief 等待工作线程发布 tid 的上限
constexpr std::chrono::milliseconds kTidWaitLimit(1000);

/// @brief 引擎段私有选项的多行用法
constexpr const char* kExtraHelp =
    "  --streams N       CLI subscription streams, 0..1024 (default 1)\n"
    "  --system-sinks K  number of counting system subscriptions, engine mode "
    "1..64; ignored with --no-engine (default 1)\n"
    "  --filter MODE     subscription filter: none|etype|role (default none)\n"
    "  --events MODE     replay event class: all|syscall|lifecycle (default "
    "all); "
    "seed always uses the full trace\n"
    "  --settled R       seed settle ratio, 0..1 (default 1); under L2 it only "
    "applies to role stubs\n"
    "  --pids N          compress process identity to N (remaps "
    "pid/ppid/target_pid "
    "and normalizes start_time), 0 keeps the original values (default 0)\n"
    "  --no-engine       run only the producer and the semantic channel drain "
    "thread "
    "to measure the producer ceiling; mutually exclusive with --fidelity l2\n";

/// @brief 订阅过滤器模式
enum class FilterMode : std::uint8_t { NONE, ETYPE, ROLE };

/// @brief 回放的事件类别
enum class EventClass : std::uint8_t { ALL, SYSCALL, LIFECYCLE };

/// @brief 引擎段私有选项
struct EngineOptions {
    int streams       = 1;                 ///< CLI 订阅流数
    int system_sinks  = 1;                 ///< 计数系统订阅数
    FilterMode filter = FilterMode::NONE;  ///< 订阅过滤器
    EventClass events = EventClass::ALL;   ///< 回放的事件类别
    double settled    = 1.0;               ///< 种子落定比例
    int pids          = 0;                 ///< 进程身份压缩到 N 个，0 表示保留
    bool no_engine    = false;             ///< 跳过引擎
};

/// @brief 过滤器模式的命令行名字
const char* filter_name(FilterMode mode)
{
    switch (mode) {
        case FilterMode::ETYPE:
            return "etype";
        case FilterMode::ROLE:
            return "role";
        case FilterMode::NONE:
            break;
    }
    return "none";
}

/// @brief 回放类别的命令行名字
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

/// @brief 该类别是否参与本次回放
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

/// @brief 严格十进制整数解析
bool parse_integer(const std::string& text, long minimum, long maximum,
                   int& value)
{
    if (text.empty()) {
        return false;
    }
    errno             = 0;
    char* end         = nullptr;
    const long parsed = std::strtol(text.c_str(), &end, 10);
    if (errno != 0 || end == text.c_str() || *end != '\0' || parsed < minimum ||
        parsed > maximum) {
        return false;
    }
    value = static_cast<int>(parsed);
    return true;
}

/// @brief 严格浮点解析，取值须在 [0, 1]
bool parse_fraction(const std::string& text, double& value)
{
    if (text.empty()) {
        return false;
    }
    errno               = 0;
    char* end           = nullptr;
    const double parsed = std::strtod(text.c_str(), &end);
    if (errno != 0 || end == text.c_str() || *end != '\0' ||
        !std::isfinite(parsed) || parsed < 0.0 || parsed > 1.0) {
        return false;
    }
    value = parsed;
    return true;
}

/**
 * @brief 解析引擎段私有选项
 * @param[in] rest 入口未识别的参数，保持原序
 * @param[out] options 解析结果
 * @param[out] error 失败原因
 * @return 解析成功时为 true
 * @note 支持 --name value 与 --name=value 两种写法。
 */
bool parse_rest(const std::vector<std::string>& rest, EngineOptions& options,
                std::string& error)
{
    for (std::size_t index = 0; index < rest.size(); ++index) {
        std::string name;
        std::string inline_value;
        bool has_inline = false;
        if (!split_option(rest[index], name, inline_value, has_inline)) {
            error = "unknown option " + rest[index];
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

        if (name == "--no-engine") {
            if (has_inline) {
                error = "--no-engine does not take a value";
                return false;
            }
            options.no_engine = true;
            continue;
        }
        if (name == "--streams") {
            std::string text;
            if (!take_value(text) ||
                !parse_integer(text, 0, 1024, options.streams)) {
                error = "--streams must be an integer in 0..1024";
                return false;
            }
            continue;
        }
        if (name == "--system-sinks") {
            std::string text;
            if (!take_value(text) ||
                !parse_integer(text, 0, 64, options.system_sinks)) {
                error = "--system-sinks must be an integer in 0..64";
                return false;
            }
            continue;
        }
        if (name == "--pids") {
            std::string text;
            if (!take_value(text) ||
                !parse_integer(text, 0, 1048576, options.pids)) {
                error = "--pids must be an integer in 0..1048576";
                return false;
            }
            continue;
        }
        if (name == "--settled") {
            std::string text;
            if (!take_value(text) || !parse_fraction(text, options.settled)) {
                error = "--settled must be a float in 0..1";
                return false;
            }
            continue;
        }
        if (name == "--events") {
            std::string text;
            if (!take_value(text)) {
                error = "--events is missing a value";
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
                error = "--events must be all|syscall|lifecycle";
                return false;
            }
            continue;
        }
        if (name == "--filter") {
            std::string text;
            if (!take_value(text)) {
                error = "--filter is missing a value";
                return false;
            }
            if (text == "none") {
                options.filter = FilterMode::NONE;
            }
            else if (text == "etype") {
                options.filter = FilterMode::ETYPE;
            }
            else if (text == "role") {
                options.filter = FilterMode::ROLE;
            }
            else {
                error = "--filter must be none|etype|role";
                return false;
            }
            continue;
        }
        error = "unknown option " + name;
        return false;
    }
    return true;
}

/// @brief 读入内存并离线语义化后的语料
struct TraceData {
    std::vector<hng::syscall_semantic_data> events;  ///< 逐条语义事件
    std::uint64_t skipped = 0;                       ///< 尺寸不合法而跳过的条数
};

/// @brief 按 head + payload 两段把语料记录拷进原始事件
void rebuild_raw(const std::vector<char>& record, struct syscall_event& raw)
{
    std::memcpy(&raw.hdr, record.data(), sizeof(raw.hdr));
    std::memcpy(reinterpret_cast<char*>(&raw) + sizeof(raw.hdr),
                record.data() + sizeof(raw.hdr), record.size() - sizeof(raw.hdr));
}

/// @brief 把非 0 pid 映射到 [1, mod]；0 是森林根哨兵，保持不变
std::uint32_t remap_pid(std::uint32_t pid, std::uint32_t mod)
{
    return pid == 0 ? 0 : ((pid - 1) % mod) + 1;
}

/// @brief 按 remap 后的 pid 归一化 start_time，使同一 pid 收敛为同一 Process
std::uint64_t remapped_start_time(std::uint32_t remapped_pid)
{
    return remapped_pid == 0 ? 0 : 1000ULL + remapped_pid;
}

/// @brief 把事件头与载荷里的 pid 类字段压缩到 mod 个身份
void remap_event(hng::syscall_semantic_data& event, std::uint32_t mod)
{
    const std::uint32_t pid    = remap_pid(event.head.pid, mod);
    const std::uint32_t ppid   = remap_pid(event.head.ppid, mod);
    event.head.pid             = pid;
    event.head.pid_start_time  = remapped_start_time(pid);
    event.head.ppid            = ppid;
    event.head.ppid_start_time = remapped_start_time(ppid);

    if (auto* payload = std::get_if<hng::process_semantic_data>(&event.data)) {
        if (payload->target_pid() != 0) {
            payload->set_target_pid(remap_pid(payload->target_pid(), mod));
        }
    }
    else if (auto* kernel = std::get_if<hng::kernel_semantic_data>(&event.data)) {
        if (kernel->target_pid() != 0) {
            kernel->set_target_pid(remap_pid(kernel->target_pid(), mod));
        }
    }
    else if (auto* signal = std::get_if<hng::signal_semantic_data>(&event.data)) {
        if (signal->target_pid() != 0) {
            signal->set_target_pid(remap_pid(signal->target_pid(), mod));
        }
        if (signal->target_tid() != 0) {
            signal->set_target_tid(remap_pid(signal->target_tid(), mod));
        }
    }
}

/**
 * @brief 读入并校验语料，逐条离线语义化
 * @param[in] path 语料路径
 * @param[in] pid_mod 非 0 时把进程身份压成 pid_mod 个并重映射 pid 类字段
 * @param[out] data 读入结果
 * @param[out] error 失败原因
 * @return 成功时为 true
 * @note 记录尺寸须不小于 syscall_event_head 且不大于 syscall_event；不合法的
 *       记录跳过并计数，全部不合法等同空语料。
 */
bool load_trace(const std::string& path, std::uint32_t pid_mod, TraceData& data,
                std::string& error)
{
    bench::TraceReader reader;
    std::string reader_error;
    if (!reader.open(path, reader_error)) {
        error = "failed to open trace " + path + ": " + reader_error;
        return false;
    }

    Semantic_syscall semantic;
    std::vector<char> record;
    while (reader.next(record, reader_error)) {
        if (record.size() < sizeof(struct syscall_event_head) ||
            record.size() > sizeof(struct syscall_event)) {
            ++data.skipped;
            continue;
        }
        struct syscall_event raw{};
        rebuild_raw(record, raw);
        hng::syscall_semantic_data event;
        semantic.transform_one(raw, event);
        if (pid_mod != 0) {
            remap_event(event, pid_mod);
        }
        data.events.push_back(std::move(event));
    }
    if (!reader_error.empty()) {
        error = "failed to read trace " + path + ": " + reader_error;
        return false;
    }
    if (data.events.empty()) {
        error = "trace " + path + " has no usable records (skipped " +
                std::to_string(data.skipped) + " records)";
        return false;
    }
    return true;
}

// ---- 订阅端 ----

/// @brief 按过滤器模式构造一份过滤器
RuntimeInfoFilter make_filter(FilterMode mode)
{
    RuntimeInfoFilter filter;
    switch (mode) {
        case FilterMode::ETYPE:
            filter.set_etype(
                std::vector<hng::EventType>{hng::EventType::SYSCALL_EVENT});
            break;
        case FilterMode::ROLE: {
            std::vector<std::uint32_t> role_ids;
            role_ids.reserve(8);
            for (std::uint32_t role_id = 1; role_id <= 8; ++role_id) {
                role_ids.push_back(role_id);
            }
            filter.set_role(std::move(role_ids), {});
            break;
        }
        case FilterMode::NONE:
            break;
    }
    return filter;
}

/**
 * @brief CLI 订阅计数端
 * @details on_event 的形参按值，与接口一致；拷贝成本计入分发路径。
 */
class CountSink final : public RuntimeEventSink {
   public:
    explicit CountSink(RuntimeInfoFilter filter_value)
        : filter(std::move(filter_value))
    {
    }

    void on_event(const hng::RuntimeEvent) override
    {
        count_.fetch_add(1, std::memory_order_relaxed);
    }

    std::uint64_t count() const { return count_.load(std::memory_order_relaxed); }

    RuntimeInfoFilter filter;  ///< 本流持有的过滤器副本

   private:
    std::atomic<std::uint64_t> count_{0};
};

/// @brief 系统订阅计数端，同时充当事件总数与类别计数器
class CountSystemSink final : public RuntimeDecisionSink {
   public:
    void on_event(const hng::RuntimeEvent& event,
                  const ContextDeriveDecision&) override
    {
        count_.fetch_add(1, std::memory_order_relaxed);
        if (is_lifecycle_class(event.runtimeInfo.subtype)) {
            lifecycle_.fetch_add(1, std::memory_order_relaxed);
        }
        else {
            syscall_.fetch_add(1, std::memory_order_relaxed);
        }
    }

    std::uint64_t count() const { return count_.load(std::memory_order_relaxed); }

    /// @brief syscall 类事件计数
    std::uint64_t syscall_count() const
    {
        return syscall_.load(std::memory_order_relaxed);
    }

    /// @brief lifecycle 类事件（进程与 exec）计数
    std::uint64_t lifecycle_count() const
    {
        return lifecycle_.load(std::memory_order_relaxed);
    }

   private:
    std::atomic<std::uint64_t> count_{0};
    std::atomic<std::uint64_t> syscall_{0};
    std::atomic<std::uint64_t> lifecycle_{0};
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
 * @brief 等待生产者与消费侧工作线程发布 tid
 * @param[in] producer_tid 生产者 tid
 * @param[in] consumer_tid 引擎线程或取空线程的 tid
 * @param[out] error 失败原因
 * @return 两个 tid 都发布时为 true
 * @note 最多等待 1 秒；超时后列出尚未发布的线程。
 */
bool wait_for_tids(const std::atomic<pid_t>& producer_tid,
                   const std::atomic<pid_t>& consumer_tid, std::string& error)
{
    const bench::Clock::time_point deadline = bench::Clock::now() + kTidWaitLimit;
    while (true) {
        const bool producer_ready =
            producer_tid.load(std::memory_order_acquire) != 0;
        const bool consumer_ready =
            consumer_tid.load(std::memory_order_acquire) != 0;
        if (producer_ready && consumer_ready) {
            return true;
        }
        if (bench::Clock::now() >= deadline) {
            error = "timed out after 1s waiting for threads to publish tid: ";
            if (!producer_ready) {
                error += " producer";
            }
            if (!consumer_ready) {
                error += " engine/drain";
            }
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

/// @brief 工作线程的窗口 CPU 快照
struct CpuSnapshot {
    double producer = 0.0;  ///< 生产者线程
    double engine   = 0.0;  ///< 引擎线程
    double drain    = 0.0;  ///< 取空线程（仅 --no-engine）
    double process  = 0.0;  ///< 进程总 CPU（全部线程）
};

/// @brief 窗口计数快照
struct CounterSnapshot {
    std::uint64_t system_events    = 0;  ///< 系统订阅端计数之和
    std::uint64_t cli_events       = 0;  ///< CLI 订阅端计数之和
    std::uint64_t drops            = 0;  ///< 语义通道 dropped + rejected
    std::uint64_t push_calls       = 0;  ///< 生产者 push 尝试次数
    std::uint64_t push_ok          = 0;  ///< 生产者 push 成功次数
    std::uint64_t syscall_events   = 0;  ///< 窗口内 syscall 类事件数
    std::uint64_t lifecycle_events = 0;  ///< 窗口内 lifecycle 类事件数
    hng::RuntimeEngineStats stats;       ///< 引擎统计快照
};

/// @brief L2 控制面的窗口统计快照
using ControlSnapshot = bench::l2::ControlPlaneSnapshot;

/// @brief 引擎段实现
int run_engine(const bench::CommonOptions& options,
               const std::vector<std::string>& rest)
{
    EngineOptions engine_options;
    std::string error;
    if (!parse_rest(rest, engine_options, error)) {
        std::fprintf(stderr, "parameter error: %s\n", error.c_str());
        std::fprintf(stderr, "engine stage options:\n%s", kExtraHelp);
        return kExitUsage;
    }
    if (!engine_options.no_engine && engine_options.system_sinks == 0) {
        std::fprintf(
            stderr,
            "parameter error: engine mode needs at least 1 system subscription "
            "for"
            " counting; use --no-engine to measure the producer ceiling\n");
        std::fprintf(stderr, "engine stage options:\n%s", kExtraHelp);
        return kExitUsage;
    }

    const bool l2 = options.fidelity == bench::Fidelity::L2;
    if (l2 && engine_options.no_engine) {
        std::fprintf(
            stderr,
            "parameter error: --no-engine and --fidelity l2 are mutually "
            "exclusive; use --fidelity l1 to measure the producer ceiling\n");
        return kExitUsage;
    }

    TraceData trace;
    if (!load_trace(options.trace_path,
                    static_cast<std::uint32_t>(engine_options.pids), trace,
                    error)) {
        std::fprintf(stderr, "%s\n", error.c_str());
        return kExitRuntimeFailure;
    }

    // 回放集合只挑 --events 指定的类别；seed 仍用 trace.events 全量
    std::vector<const hng::syscall_semantic_data*> playback;
    playback.reserve(trace.events.size());
    for (const hng::syscall_semantic_data& event : trace.events) {
        if (class_selected(engine_options.events, event.head.subtype)) {
            playback.push_back(&event);
        }
    }
    if (playback.empty()) {
        std::fprintf(stderr, "trace has no replayable events under --events %s\n",
                     event_class_name(engine_options.events));
        return kExitRuntimeFailure;
    }

    // 通道、替身、维护器、引擎与 sink 都由本函数持有；声明顺序保证线程
    // 收尾后引擎先于通道与 sink 析构
    hng::EventChannel<hng::syscall_semantic_data> channel(
        static_cast<std::size_t>(options.queue));

    // L2 控制面；声明在维护器之前，收尾后维护器先于组件析构
    bench::l2::ControlPlane l2_control;

    bench::l1::FakeProcessJoin process_join;
    bench::l1::FakeProcessUpdate process_update;
    bench::l1::FakeProcessLookup process_lookup;
    bench::l1::FakeRoleJoin role_join;
    bench::l1::FakeRoleLookup role_lookup;
    bench::l1::FakeContextService context_service;
    ContextMaintainer maintainer;
    if (!l2) {
        maintainer.set_context_service(&context_service, &context_service,
                                       &context_service);
    }

    // 引擎注入点：L1 全部指向内存替身，L2 的进程与 context 维度指向真实组件
    ProcessJoinService* process_join_target     = &process_join;
    ProcessUpdateService* process_update_target = &process_update;
    ProcessLookupService* process_lookup_target = &process_lookup;

    if (l2) {
        if (!l2_control.start(trace.events, engine_options.settled, maintainer,
                              role_join, role_lookup, error)) {
            std::fprintf(stderr, "%s\n", error.c_str());
            return kExitRuntimeFailure;
        }
        process_join_target   = &l2_control.process_join();
        process_update_target = &l2_control.process_update();
        process_lookup_target = &l2_control.process_lookup();
    }

    bench::l1::SeedCounts seeds;
    if (!l2 && !engine_options.no_engine) {
        bench::l1::seed_services(trace.events, engine_options.settled,
                                 process_lookup, role_lookup, context_service,
                                 seeds);
    }

    std::vector<std::unique_ptr<CountSystemSink>> system_sinks;
    std::vector<std::unique_ptr<CountSink>> cli_sinks;
    if (!engine_options.no_engine) {
        system_sinks.reserve(
            static_cast<std::size_t>(engine_options.system_sinks));
        for (int index = 0; index < engine_options.system_sinks; ++index) {
            system_sinks.push_back(std::make_unique<CountSystemSink>());
        }
        cli_sinks.reserve(static_cast<std::size_t>(engine_options.streams));
        for (int index = 0; index < engine_options.streams; ++index) {
            cli_sinks.push_back(
                std::make_unique<CountSink>(make_filter(engine_options.filter)));
        }
    }

    std::unique_ptr<hng::RuntimeEngineComponent> engine;
    if (!engine_options.no_engine) {
        hng::RuntimeEngineOptions engine_settings;
        engine_settings.syscall_input  = &channel.reader();
        engine_settings.ctx_maintainer = &maintainer;
        engine_settings.process_join   = process_join_target;
        engine_settings.process_update = process_update_target;
        engine_settings.process_lookup = process_lookup_target;
        engine_settings.role_join      = &role_join;
        engine_settings.role_lookup    = &role_lookup;
        try {
            engine = hng::RuntimeEngineFactory::create(engine_settings);
        }
        catch (const std::exception& failure) {
            std::fprintf(stderr, "failed to construct the engine: %s\n",
                         failure.what());
            return kExitRuntimeFailure;
        }
        for (const std::unique_ptr<CountSystemSink>& sink : system_sinks) {
            engine->add_system_sink(sink.get());
        }
        for (const std::unique_ptr<CountSink>& sink : cli_sinks) {
            if (!engine->subscriber_service().subscribe(sink.get(), sink->filter,
                                                        nullptr)) {
                std::fprintf(stderr,
                             "failed to register the subscription: engine "
                             "already stopped\n");
                return kExitRuntimeFailure;
            }
        }
    }

    std::atomic<bool> producer_stop{false};
    std::atomic<std::uint64_t> push_calls{0};
    std::atomic<std::uint64_t> push_ok{0};
    // --no-engine 没有系统订阅，类别计数退回到成功入队侧
    std::atomic<std::uint64_t> push_ok_syscall{0};
    std::atomic<std::uint64_t> push_ok_lifecycle{0};
    std::atomic<pid_t> producer_tid{0};
    std::atomic<pid_t> consumer_tid{0};
    std::atomic<bool> consumer_done{false};
    std::atomic<bool> engine_failed{false};

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
                std::fprintf(stderr, "producer CPU pinning failed: %s\n",
                             pin_error.c_str());
            }
        }
        std::uint64_t index = 0;
        while (!producer_stop.load(std::memory_order_acquire)) {
            for (const hng::syscall_semantic_data* event : playback) {
                if (producer_stop.load(std::memory_order_relaxed)) {
                    break;
                }
                if (pacer) {
                    (void)pacer->wait(index);
                }
                ++index;
                push_calls.fetch_add(1, std::memory_order_relaxed);
                if (channel.writer().push(*event)) {
                    push_ok.fetch_add(1, std::memory_order_relaxed);
                    if (engine_options.no_engine) {
                        if (is_lifecycle_class(event->head.subtype)) {
                            push_ok_lifecycle.fetch_add(
                                1, std::memory_order_relaxed);
                        }
                        else {
                            push_ok_syscall.fetch_add(1,
                                                      std::memory_order_relaxed);
                        }
                    }
                }
            }
        }
    });

    std::thread consumer;
    if (engine_options.no_engine) {
        consumer = std::thread([&] {
            consumer_tid.store(::gettid(), std::memory_order_release);
            if (options.pin_consumer >= 0) {
                std::string pin_error;
                if (!bench::pin_this_thread(options.pin_consumer, pin_error)) {
                    std::fprintf(stderr, "drain thread CPU pinning failed: %s\n",
                                 pin_error.c_str());
                }
            }
            drain_until_closed(channel.reader(), consumer_done);
        });
    }
    else {
        consumer = std::thread([&] {
            consumer_tid.store(::gettid(), std::memory_order_release);
            if (options.pin_consumer >= 0) {
                std::string pin_error;
                if (!bench::pin_this_thread(options.pin_consumer, pin_error)) {
                    std::fprintf(stderr, "engine thread CPU pinning failed: %s\n",
                                 pin_error.c_str());
                }
            }
            try {
                engine->run();
            }
            catch (const std::exception& failure) {
                std::fprintf(stderr, "engine thread failed: %s\n",
                             failure.what());
                engine_failed.store(true);
            }
            catch (...) {
                std::fprintf(stderr, "engine thread failed: unknown exception\n");
                engine_failed.store(true);
            }
            consumer_done.store(true, std::memory_order_release);
        });
    }

    // 收尾顺序：先停生产者，再停引擎（或关闭通道并等取空线程）
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
        if (engine_options.no_engine) {
            channel.writer().close();
            if (consumer.joinable() &&
                !wait_for_thread(consumer, consumer_done, kThreadJoinLimit)) {
                std::fprintf(stderr,
                             "warning: drain thread did not exit within %lld "
                             "seconds, waiting once more\n",
                             static_cast<long long>(kThreadJoinLimit.count()));
                if (!wait_for_thread(consumer, consumer_done, kThreadJoinLimit)) {
                    std::fprintf(
                        stderr,
                        "drain thread still did not exit, exiting the process\n");
                    std::_Exit(kExitRuntimeFailure);
                }
            }
        }
        else {
            engine->stop();
            if (consumer.joinable() &&
                !wait_for_thread(consumer, consumer_done, kThreadJoinLimit)) {
                std::fprintf(stderr,
                             "warning: engine thread did not exit within %lld "
                             "seconds, waiting once more\n",
                             static_cast<long long>(kThreadJoinLimit.count()));
                if (!wait_for_thread(consumer, consumer_done, kThreadJoinLimit)) {
                    std::fprintf(stderr,
                                 "engine thread still did not exit, exiting the "
                                 "process\n");
                    std::_Exit(kExitRuntimeFailure);
                }
            }
        }
        // 引擎停稳后再停控制面，顺序与装配层一致：先 process，再 context
        l2_control.stop();
    };

    if (!wait_for_tids(producer_tid, consumer_tid, error)) {
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
            sample_error = "failed to read producer thread CPU: " + sample_error;
            return false;
        }
        const std::uint64_t consumer_id = static_cast<std::uint64_t>(
            consumer_tid.load(std::memory_order_acquire));
        if (engine_options.no_engine) {
            if (!bench::read_thread_cpu(consumer_id, snapshot.drain,
                                        sample_error)) {
                sample_error = "failed to read drain thread CPU: " + sample_error;
                return false;
            }
        }
        else if (!bench::read_thread_cpu(consumer_id, snapshot.engine,
                                         sample_error)) {
            sample_error = "failed to read engine thread CPU: " + sample_error;
            return false;
        }
        if (!bench::read_process_cpu(::getpid(), snapshot.process,
                                     sample_error)) {
            sample_error = "failed to read process total CPU: " + sample_error;
            return false;
        }
        return true;
    };

    const auto sample_counters = [&](CounterSnapshot& snapshot) {
        snapshot.system_events = 0;
        for (const std::unique_ptr<CountSystemSink>& sink : system_sinks) {
            snapshot.system_events += sink->count();
        }
        snapshot.cli_events = 0;
        for (const std::unique_ptr<CountSink>& sink : cli_sinks) {
            snapshot.cli_events += sink->count();
        }
        snapshot.drops = channel.reader().dropped() + channel.reader().rejected();
        snapshot.push_calls = push_calls.load(std::memory_order_relaxed);
        snapshot.push_ok    = push_ok.load(std::memory_order_relaxed);
        if (engine_options.no_engine) {
            snapshot.syscall_events =
                push_ok_syscall.load(std::memory_order_relaxed);
            snapshot.lifecycle_events =
                push_ok_lifecycle.load(std::memory_order_relaxed);
        }
        else {
            std::uint64_t syscall_total   = 0;
            std::uint64_t lifecycle_total = 0;
            for (const std::unique_ptr<CountSystemSink>& sink : system_sinks) {
                syscall_total   += sink->syscall_count();
                lifecycle_total += sink->lifecycle_count();
            }
            const std::uint64_t sinks = static_cast<std::uint64_t>(
                engine_options.system_sinks > 0 ? engine_options.system_sinks
                                                : 1);
            snapshot.syscall_events   = syscall_total / sinks;
            snapshot.lifecycle_events = lifecycle_total / sinks;
        }
        if (engine) {
            snapshot.stats = engine->stats();
        }
    };

    const auto sample_control = [&](ControlSnapshot& snapshot) {
        if (l2) {
            snapshot = l2_control.snapshot();
        }
    };

    std::this_thread::sleep_until(measure_start);
    CpuSnapshot cpu_start;
    CounterSnapshot counter_start;
    ControlSnapshot control_start;
    if (!sample_cpu(cpu_start, error)) {
        std::fprintf(stderr, "%s\n", error.c_str());
        stop_threads();
        return kExitRuntimeFailure;
    }
    sample_counters(counter_start);
    sample_control(control_start);

    // EventChannel::size() 只保证单线程观察；第三方线程采样可能读到瞬时
    // 不一致的 head/tail 而下溢，超出容量的样本视为无效并丢弃
    const std::size_t capacity = channel_capacity(options.queue);
    bench::OccupancySampler occupancy([&channel, capacity] {
        const std::size_t value = channel.size();
        return value <= capacity ? value : 0;
    });
    occupancy.start();

    std::this_thread::sleep_until(measure_end);
    CpuSnapshot cpu_end;
    if (!sample_cpu(cpu_end, error)) {
        occupancy.stop();
        std::fprintf(stderr, "%s\n", error.c_str());
        stop_threads();
        return kExitRuntimeFailure;
    }
    CounterSnapshot counter_end;
    ControlSnapshot control_end;
    sample_control(control_end);
    sample_counters(counter_end);
    occupancy.stop();

    stop_threads();

    if (engine_failed.load(std::memory_order_acquire)) {
        std::fprintf(stderr, "engine thread failed, no result produced\n");
        return kExitRuntimeFailure;
    }
    if (l2_control.failed()) {
        std::fprintf(
            stderr,
            "control plane component thread failed, no result produced\n");
        return kExitRuntimeFailure;
    }

    const auto delta = [](std::uint64_t end, std::uint64_t start) {
        return end >= start ? end - start : 0;
    };
    const auto cpu_delta = [](double end, double start) {
        return end >= start ? end - start : 0.0;
    };

    // 每个系统 sink 都收到全量事件；K>1 时直接求和会把事件数放大 K 倍，
    // 故按 sink 数取均值。K=1 时即规格中的计数器之和。
    const std::uint64_t system_events =
        delta(counter_end.system_events, counter_start.system_events);
    const std::uint64_t events =
        engine_options.no_engine
            ? delta(counter_end.push_ok, counter_start.push_ok)
            : (engine_options.system_sinks > 0
                   ? system_events /
                         static_cast<std::uint64_t>(engine_options.system_sinks)
                   : 0);
    const std::uint64_t syscall_events =
        delta(counter_end.syscall_events, counter_start.syscall_events);
    const std::uint64_t lifecycle_events =
        delta(counter_end.lifecycle_events, counter_start.lifecycle_events);
    const std::uint64_t drops = delta(counter_end.drops, counter_start.drops);
    const std::uint64_t calls =
        delta(counter_end.push_calls, counter_start.push_calls);
    const std::uint64_t pushes_ok =
        delta(counter_end.push_ok, counter_start.push_ok);
    const std::uint64_t pushes_failed =
        calls >= pushes_ok ? calls - pushes_ok : 0;
    const std::uint64_t cli_events =
        delta(counter_end.cli_events, counter_start.cli_events);
    const std::uint64_t unsettled = delta(counter_end.stats.unsettled_events,
                                          counter_start.stats.unsettled_events);
    const std::uint64_t rejected  = delta(counter_end.stats.queue_rejected,
                                          counter_start.stats.queue_rejected);
    const std::uint64_t idle_waits =
        delta(counter_end.stats.idle_waits, counter_start.stats.idle_waits);
    const std::uint64_t syscall_dropped = delta(
        counter_end.stats.syscall_dropped, counter_start.stats.syscall_dropped);
    const double producer_cpu   = cpu_delta(cpu_end.producer, cpu_start.producer);
    const double engine_cpu     = cpu_delta(cpu_end.engine, cpu_start.engine);
    const double drain_cpu      = cpu_delta(cpu_end.drain, cpu_start.drain);
    const double process_cpu    = cpu_delta(cpu_end.process, cpu_start.process);
    const double window_seconds = static_cast<double>(options.seconds);
    // 控制面 CPU：进程总量减去按 tid 归属的生产者与消费侧线程；占用采样线程、
    // 组件的消费线程等只能落在这一差值里
    const double consumer_cpu = engine_options.no_engine ? drain_cpu : engine_cpu;
    const double control_cpu  = process_cpu > producer_cpu + consumer_cpu
                                    ? process_cpu - producer_cpu - consumer_cpu
                                    : 0.0;

    // 控制面统计：累计字段取窗口增量，tombstone/pending_depth 取当前值
    const std::uint64_t pm_pid_reused =
        delta(control_end.process.pid_reused, control_start.process.pid_reused);
    const std::uint64_t pm_stale_add =
        delta(control_end.process.stale_add, control_start.process.stale_add);
    const std::uint64_t pm_parent_missing = delta(
        control_end.process.parent_missing, control_start.process.parent_missing);
    const std::uint64_t cm_pending_deferred =
        delta(control_end.context.pending_deferred,
              control_start.context.pending_deferred);
    const std::uint64_t cm_pending_resolved =
        delta(control_end.context.pending_resolved,
              control_start.context.pending_resolved);
    const std::uint64_t cm_pending_rejected =
        delta(control_end.context.pending_rejected,
              control_start.context.pending_rejected);
    const std::uint64_t cm_pending_expired =
        delta(control_end.context.pending_expired,
              control_start.context.pending_expired);
    const std::uint64_t cm_pending_cancelled =
        delta(control_end.context.pending_cancelled,
              control_start.context.pending_cancelled);
    const std::uint64_t cm_bind_orphaned = delta(
        control_end.context.bind_orphaned, control_start.context.bind_orphaned);
    const std::uint64_t cm_extra_orphaned = delta(
        control_end.context.extra_orphaned, control_start.context.extra_orphaned);
    const std::uint64_t cm_parent_missing = delta(
        control_end.context.parent_missing, control_start.context.parent_missing);
    const std::uint64_t cm_late_register = delta(
        control_end.context.late_register, control_start.context.late_register);
    const std::uint64_t cm_late_bind =
        delta(control_end.context.late_bind, control_start.context.late_bind);
    const std::uint64_t cm_duplicate_context =
        delta(control_end.context.duplicate_context,
              control_start.context.duplicate_context);
    const std::uint64_t cm_ownership_conflict =
        delta(control_end.context.ownership_conflict,
              control_start.context.ownership_conflict);
    const std::uint64_t cm_tombstone_hits = delta(
        control_end.context.tombstone_hits, control_start.context.tombstone_hits);
    const std::uint64_t cm_ctxroot_parent_unsettled =
        delta(control_end.context.ctxroot_parent_unsettled,
              control_start.context.ctxroot_parent_unsettled);
    const std::uint64_t cm_unknown_unregister =
        delta(control_end.context.unknown_unregister,
              control_start.context.unknown_unregister);

    const bench::l2::SeedReport& l2_seeds = control_end.seed;
    char settled_text[32]                 = {};
    std::snprintf(settled_text, sizeof(settled_text), "%g",
                  engine_options.settled);
    const std::string config =
        std::string("fidelity=") + bench::fidelity_name(options.fidelity) +
        ",events=" + event_class_name(engine_options.events) +
        ",streams=" + std::to_string(engine_options.streams) +
        ",system=" + std::to_string(engine_options.system_sinks) +
        ",filter=" + filter_name(engine_options.filter) +
        ",settled=" + settled_text +
        ",pids=" + std::to_string(engine_options.pids) +
        (engine_options.no_engine ? ",no-engine" : "");

    bench::Result result;
    result.stage   = "engine";
    result.config  = config;
    result.rate    = options.rate;
    result.seconds = window_seconds;
    result.events  = events;
    result.events_per_s =
        window_seconds > 0.0 ? static_cast<double>(events) / window_seconds : 0.0;
    result.us_per_event = (!engine_options.no_engine && events > 0)
                              ? engine_cpu * 1e6 / static_cast<double>(events)
                              : 0.0;
    result.producer_us_per_event =
        calls > 0 ? producer_cpu * 1e6 / static_cast<double>(calls) : 0.0;
    result.producer_us_per_success =
        pushes_ok > 0 ? producer_cpu * 1e6 / static_cast<double>(pushes_ok) : 0.0;
    result.drops          = drops;
    result.raw_drops      = drops;
    result.out_drops      = 0;
    result.rss_kb         = bench::rss_kb();
    result.peak_queue     = occupancy.peak();
    result.out_peak_queue = 0;

    bench::print_human(result, options);
    std::printf(
        "config: fidelity=%s events=%s streams=%d system_sinks=%d filter=%s "
        "settled=%s pids=%d%s\n",
        bench::fidelity_name(options.fidelity),
        event_class_name(engine_options.events), engine_options.streams,
        engine_options.system_sinks, filter_name(engine_options.filter),
        settled_text, engine_options.pids,
        engine_options.no_engine ? " no-engine" : "");
    std::printf("events by class: syscall=%" PRIu64 " lifecycle=%" PRIu64 "\n",
                syscall_events, lifecycle_events);
    if (l2) {
        std::printf(
            "fidelity: L2 (Process/Context are real components, Role is a "
            "stub)\n");
    }
    else if (!engine_options.no_engine) {
        std::printf(
            "fidelity: L1 (control plane is in-memory stubs, no lock or enqueue "
            "cost)\n");
    }
    if (!engine_options.no_engine) {
        std::printf("engine stats: unsettled_events=+%" PRIu64
                    " peak_cli_streams=%" PRIu64 " queue_rejected=+%" PRIu64
                    " idle_waits=+%" PRIu64 " syscall_dropped=+%" PRIu64
                    " cli_events=+%" PRIu64 "\n",
                    unsettled, counter_end.stats.peak_cli_streams, rejected,
                    idle_waits, syscall_dropped, cli_events);
    }
    std::printf("peak_queue=%" PRIu64
                " (semantic channel, capacity=%zu) "
                "rss_kb=%" PRIu64 "\n",
                result.peak_queue, capacity, result.rss_kb);
    if (l2) {
        std::printf(
            "seeds: role stubs settled=%s seeded=%" PRIu64
            " (under L2 --settled only applies to role stubs; context is a "
            "real seed, all trace processes are hit)\n",
            settled_text, l2_seeds.roles);
        std::printf("process seed: batch=%zu (supplemented parents %" PRIu64
                    "), inserted=%" PRIu64 " duplicate=%" PRIu64
                    " pid_reused=%" PRIu64 " parent_missing=%" PRIu64
                    " invalid=%" PRIu64 " rejected_state=%" PRIu64 "\n",
                    l2_seeds.batch_entries, l2_seeds.supplemented,
                    l2_seeds.process.inserted, l2_seeds.process.duplicate,
                    l2_seeds.process.pid_reused, l2_seeds.process.parent_missing,
                    l2_seeds.process.invalid, l2_seeds.process.rejected_state);
        std::printf("seed exe: real=%" PRIu64 " synthetic=%" PRIu64 "\n",
                    l2_seeds.exe_real, l2_seeds.exe_synthetic);
        std::printf(
            "context seed: inserted=%" PRIu64 " bound=%" PRIu64
            " plan_derive=%" PRIu64 " plan_bind=%" PRIu64 " duplicate=%" PRIu64
            " rejected_out_of_order=%" PRIu64 " rejected_invalid=%" PRIu64
            " rejected_state=%" PRIu64 "\n",
            l2_seeds.context.inserted, l2_seeds.context.bound,
            l2_seeds.plan_derive, l2_seeds.plan_bind, l2_seeds.context.duplicate,
            l2_seeds.context.rejected_out_of_order,
            l2_seeds.context.rejected_invalid, l2_seeds.context.rejected_state);
        std::printf("PM stats: pid_reused=+%" PRIu64 "(now %" PRIu64
                    ") stale_add=+%" PRIu64 "(now %" PRIu64
                    ") parent_missing=+%" PRIu64 "(now %" PRIu64
                    ") tombstone_depth=%" PRIu64 "\n",
                    pm_pid_reused, control_end.process.pid_reused, pm_stale_add,
                    control_end.process.stale_add, pm_parent_missing,
                    control_end.process.parent_missing,
                    control_end.process.tombstone_depth);
        std::printf("CM stats: pending_deferred=+%" PRIu64
                    " pending_resolved=+%" PRIu64 " pending_rejected=+%" PRIu64
                    " pending_expired=+%" PRIu64 " pending_cancelled=+%" PRIu64
                    " pending_depth=%" PRIu64 " bind_orphaned=+%" PRIu64
                    " extra_orphaned=+%" PRIu64 " parent_missing=+%" PRIu64
                    "(now %" PRIu64 ") late_register=+%" PRIu64
                    " late_bind=+%" PRIu64 " duplicate_context=+%" PRIu64
                    "(now %" PRIu64 ") ownership_conflict=+%" PRIu64
                    " tombstone_hits=+%" PRIu64 " tombstone_depth=%" PRIu64
                    " ctxroot_parent_unsettled=+%" PRIu64
                    " unknown_unregister=+%" PRIu64 "\n",
                    cm_pending_deferred, cm_pending_resolved, cm_pending_rejected,
                    cm_pending_expired, cm_pending_cancelled,
                    control_end.context.pending_depth, cm_bind_orphaned,
                    cm_extra_orphaned, cm_parent_missing,
                    control_end.context.parent_missing, cm_late_register,
                    cm_late_bind, cm_duplicate_context,
                    control_end.context.duplicate_context, cm_ownership_conflict,
                    cm_tombstone_hits, control_end.context.tombstone_depth,
                    cm_ctxroot_parent_unsettled, cm_unknown_unregister);
        if (pm_stale_add > 0 || cm_late_register > 0) {
            std::printf(
                "hint: replaying the trace in a loop resurrects exited process "
                "identities (stale_add=+%" PRIu64 " late_register=+%" PRIu64
                "), so this stage's lifecycle cost includes the tombstone path; "
                "use --events syscall for steady-state capacity\n",
                pm_stale_add, cm_late_register);
        }
        std::printf("pacer overruns=%" PRIu64 " push_calls=%" PRIu64
                    " push_failed=%" PRIu64 " skipped=%" PRIu64 "\n",
                    pacer ? pacer->overruns() : 0, calls, pushes_failed,
                    trace.skipped);
    }
    else {
        std::printf("pacer overruns=%" PRIu64 " push_calls=%" PRIu64
                    " push_failed=%" PRIu64 " skipped=%" PRIu64
                    " seeds: processes=%" PRIu64 " roles=%" PRIu64
                    " contexts=%" PRIu64 " context_registers=%" PRIu64 "\n",
                    pacer ? pacer->overruns() : 0, calls, pushes_failed,
                    trace.skipped, seeds.processes, seeds.roles, seeds.contexts,
                    context_service.register_calls);
    }
    std::printf("window cpu: producer=%.3fs engine=%.3fs drain=%.3fs\n",
                producer_cpu, engine_cpu, drain_cpu);
    std::printf(
        "cp cpu=%.3fs (control plane + other threads) cp_us/event=%.3f "
        "total_cpu=%.3fs%s\n",
        control_cpu,
        events > 0 ? control_cpu * 1e6 / static_cast<double>(events) : 0.0,
        process_cpu,
        l2 ? " (includes threads that cannot be attributed by tid)"
           : " (L1 control plane runs inside the engine thread)");
    if (engine_options.no_engine) {
        std::printf(
            "no-engine: no semantic engine thread; events counts successful "
            "pushes\n");
    }
    if (options.rate == 0.0 && drops > 0) {
        std::printf(
            "hint: at rate=0 the producer spins and retries on a single core, so "
            "readings "
            "include cache-line contention; take the highest rate with 0 drops "
            "as the capacity (scan with --rate)\n");
    }
    if (!bench::append_tsv(options.out_path, result)) {
        std::fprintf(
            stderr, "failed to write TSV: %s\n",
            options.out_path.empty() ? "stdout" : options.out_path.c_str());
        return kExitRuntimeFailure;
    }
    return 0;
}

bench::StageSpec make_engine_stage()
{
    bench::StageSpec stage;
    stage.name           = "engine";
    stage.extra_help     = kExtraHelp;
    stage.requires_trace = true;
    stage.supports_l2    = true;
    stage.run            = &run_engine;
    return stage;
}

}  // namespace

namespace bench {

const StageSpec& engine_stage()
{
    static const StageSpec stage = make_engine_stage();
    return stage;
}

}  // namespace bench
