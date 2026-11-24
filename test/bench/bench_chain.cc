/**
 * @file bench_chain.cc
 * @brief chain 段压测：replay feeder → 语义 → 引擎，以及整链 CLI 后端
 * @details
 * 本段把采集、语义与引擎串成一条链，测量一次输入事件走完整条链的窗口成本。
 * 生产侧没有真实采集器，用与采集器等价解析的语料回放（见 chain_feeder.hpp）；
 * 消费侧是真实语义组件、真实引擎与 L1 控制面替身（见 chain_core.hpp）。
 * --backend sink 在一进程内跑完整链，写 4 行 TSV；--backend cli 在子进程里跑
 * 同样的链并加上真实 RunCliServer。父进程先订阅并等服务端登记全部流，再发 go
 * 文件放行子进程；子进程收到 go 才取 T0、启动回放，两端按同一个 T0 对齐窗口。
 * CLI 后端写 5 行 TSV（多一行 chain/cli）。
 */

#include "test/bench/chain_core.hpp"
#include "test/bench/stages.hpp"

#ifdef HNG_BENCH_CLI_STAGE
#include "test/bench/cli_client.hpp"

#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#include <cerrno>
#include <cinttypes>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace {

/// @brief 退出码：运行期失败
constexpr int kExitRuntimeFailure       = 1;
/// @brief 退出码：参数错误
constexpr int kExitUsage                = 3;

/// @brief 判定「CPU 证据与丢包归因冲突」的核数余量
constexpr double kConflictCores         = 0.10;
/// @brief delivered/dispatched 与 streams 的允许偏差
constexpr double kFanoutTolerance       = 0.02;
/// @brief 控制面利用率告警阈值，占满一核为 1
constexpr double kControlCores          = 0.80;

/// @brief 客户端流数的解析上限，与服务端并发配额（64）区分
constexpr long kMaxStreams              = 1024;
/// @brief 单批事件数的上界，与服务端钳制一致
constexpr long kMaxBatch                = 256;
/// @brief CLI 每流队列容量的合法区间
constexpr long kCliQueueMin             = 2;
constexpr long kCliQueueMax             = 1048576;
/// @brief 服务端 cli-tp 线程的 comm 前缀
constexpr const char* kCliTaskProcessor = "cli-tp";

/// @brief chain 段私有选项的多行用法
constexpr const char* kExtraHelp =
    "  --backend MODE    backend: cli|sink (default: cli when this build has a "
    "CLI server, sink otherwise)\n"
    "  --events MODE     replay class: all|syscall|lifecycle (default all); "
    "PROCESS and EXEC count as lifecycle; the seed always uses the full trace\n"
    "  --system-sinks K  counting system subscriptions, 1..64, also the engine "
    "dispatch count (default 1)\n"
    "  --settled R       seed settle fraction, 0..1 (default 1); under L2 it "
    "only applies to role stubs (context is a real seed over the full trace)\n"
    "  --fidelity l1|l2  control plane fidelity (default l1); l2 uses real "
    "Process/Context components while Role stays a stub; the sink backend "
    "reports control-plane CPU, PM/CM window stats and the seed report\n"
    "  --streams N       concurrent subscription streams of the CLI backend, "
    "1..1024 (default 1)\n"
    "  --batch N         max events per response of the CLI backend, 1..256 "
    "(default 64)\n"
    "  --cli-queue N     per-stream queue capacity of the CLI server, 2..1048576 "
    "(default 8192)\n"
    "  --socket PATH     absolute Unix socket path of the CLI backend child "
    "process; empty means "
    "/tmp/hng-chain-cli-<pid>.sock\n"
    "  --filter MODE     subscription filter, v1 supports only none; role/miss "
    "are not yet wired up\n"
    "  the sink backend runs replay feeder → semantic → engine in one process, "
    "without CLI or wire; "
    "--backend sink rejects --streams/--batch/--filter/--cli-queue/--socket.\n"
#ifdef HNG_BENCH_CLI_STAGE
    "  the cli backend runs the same chain plus the real RunCliServer in a child "
    "process; the parent "
    "subscribes first, waits until the server has registered all streams, then "
    "sends go; the child takes "
    "T0 and starts replay only after receiving go; both ends align the window on "
    "the same T0, with --warmup counted from T0.\n"
#else
    "  this build has no CLI server (userver); --backend cli reports a parameter "
    "error.\n"
#endif
    "  this stage does not use --pin-consumer or --pin-producer.\n";

/// @brief 后端选择
enum class ChainBackend : std::uint8_t { CLI, SINK };

/// @brief chain 段私有选项
struct ChainRun {
    bench::chain::ChainOptions chain;  ///< 语料、速率与通道参数
    ChainBackend backend;              ///< 后端，构造时按构建能力取默认

    int streams   = 1;        ///< CLI 后端的并发订阅流数
    int batch     = 64;       ///< CLI 后端的单条响应事件数上限
    int cli_queue = 8192;     ///< CLI 服务端每流队列容量
    std::string socket_path;  ///< CLI 后端的 socket 路径；空表示临时路径

    bool backend_set   = false;  ///< 显式指定了 --backend
    bool streams_set   = false;  ///< 显式指定了 --streams
    bool batch_set     = false;  ///< 显式指定了 --batch
    bool cli_queue_set = false;  ///< 显式指定了 --cli-queue
    bool socket_set    = false;  ///< 显式指定了 --socket
    bool filter_set    = false;  ///< 显式指定了 --filter

    ChainRun()
    {
#ifdef HNG_BENCH_CLI_STAGE
        backend = ChainBackend::CLI;
#else
        backend = ChainBackend::SINK;
#endif
    }
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
 * @brief 解析 chain 段私有选项
 * @param[in] rest 入口未识别的参数，保持原序
 * @param[out] run 语料之外的回放参数与后端参数
 * @param[out] error 失败原因
 * @return 解析成功时为 true
 * @note 支持 --name value 与 --name=value 两种写法。解析结束后若后端为 sink
 *       且显式给了任一 CLI 选项，按参数错误拒绝。无 userver 构建里
 *       --backend cli 直接报错。
 */
bool parse_rest(const std::vector<std::string>& rest, ChainRun& run,
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

        if (name == "--backend") {
            std::string text;
            if (!take_value(text)) {
                error = "--backend is missing a value";
                return false;
            }
            if (text == "sink") {
                run.backend = ChainBackend::SINK;
            }
            else if (text == "cli") {
#ifdef HNG_BENCH_CLI_STAGE
                run.backend = ChainBackend::CLI;
#else
                error =
                    "this build has no CLI server (userver), --backend cli is "
                    "unavailable; use --backend sink, or "
                    "rebuild with -DHNG_ENABLE_CLI_SERVER=ON";
                return false;
#endif
            }
            else {
                error = "--backend must be cli|sink";
                return false;
            }
            run.backend_set = true;
            continue;
        }
        if (name == "--streams") {
            std::string text;
            if (!take_value(text) ||
                !parse_integer(text, 1, kMaxStreams, run.streams)) {
                error = "--streams must be an integer in 1.." +
                        std::to_string(kMaxStreams) + " (inclusive)";
                return false;
            }
            run.streams_set = true;
            continue;
        }
        if (name == "--batch") {
            std::string text;
            if (!take_value(text) ||
                !parse_integer(text, 1, kMaxBatch, run.batch)) {
                error = "--batch must be an integer in 1.." +
                        std::to_string(kMaxBatch) + " (inclusive)";
                return false;
            }
            run.batch_set = true;
            continue;
        }
        if (name == "--cli-queue") {
            std::string text;
            if (!take_value(text) ||
                !parse_integer(text, kCliQueueMin, kCliQueueMax, run.cli_queue)) {
                error = "--cli-queue must be an integer in " +
                        std::to_string(kCliQueueMin) + ".." +
                        std::to_string(kCliQueueMax) + " (inclusive)";
                return false;
            }
            run.cli_queue_set = true;
            continue;
        }
        if (name == "--socket") {
            if (!take_value(run.socket_path) || run.socket_path.empty() ||
                run.socket_path.front() != '/') {
                error = "--socket must be an absolute path";
                return false;
            }
            run.socket_set = true;
            continue;
        }
        if (name == "--filter") {
            std::string text;
            if (!take_value(text)) {
                error = "--filter is missing a value";
                return false;
            }
            if (text != "none") {
                error =
                    "--filter supports only none in v1; role/miss change the "
                    "delivery ratio and are not yet wired up in the chain "
                    "backend";
                return false;
            }
            run.filter_set = true;
            continue;
        }
        if (name == "--events") {
            std::string text;
            if (!take_value(text)) {
                error = "--events is missing a value";
                return false;
            }
            if (text == "all") {
                run.chain.events = bench::chain::EventClass::ALL;
            }
            else if (text == "syscall") {
                run.chain.events = bench::chain::EventClass::SYSCALL;
            }
            else if (text == "lifecycle") {
                run.chain.events = bench::chain::EventClass::LIFECYCLE;
            }
            else {
                error = "--events must be all|syscall|lifecycle";
                return false;
            }
            continue;
        }
        if (name == "--system-sinks") {
            std::string text;
            if (!take_value(text) ||
                !parse_integer(text, 1, 64, run.chain.system_sinks)) {
                error = "--system-sinks must be an integer in 1..64";
                return false;
            }
            continue;
        }
        if (name == "--settled") {
            std::string text;
            if (!take_value(text) || !parse_fraction(text, run.chain.settled)) {
                error = "--settled must be a float in 0..1";
                return false;
            }
            continue;
        }
        error = "unknown option " + name;
        return false;
    }

    if (run.backend == ChainBackend::SINK) {
        std::string used;
        const auto note = [&used](const char* option) {
            if (!used.empty()) {
                used += " ";
            }
            used += option;
        };
        if (run.streams_set) {
            note("--streams");
        }
        if (run.batch_set) {
            note("--batch");
        }
        if (run.cli_queue_set) {
            note("--cli-queue");
        }
        if (run.socket_set) {
            note("--socket");
        }
        if (run.filter_set) {
            note("--filter");
        }
        if (!used.empty()) {
            error =
                "--backend sink runs only the in-process whole chain and takes "
                "no CLI backend options: " +
                used;
            return false;
        }
    }
    return true;
}

/// @brief 一段的 CPU 利用率，占满一核为 1
struct SegmentLoad {
    const char* name;  ///< 段名
    double cores;      ///< 窗口 CPU / 窗口秒数
};

/// @brief 利用率最高的一段
const SegmentLoad& tightest_segment(const std::vector<SegmentLoad>& loads)
{
    const SegmentLoad* tightest = &loads.front();
    for (const SegmentLoad& load : loads) {
        if (load.cores > tightest->cores) {
            tightest = &load;
        }
    }
    return *tightest;
}

/// @brief 某段利用率超过另一段至少 kConflictCores 时视为 CPU 证据冲突
bool covers_other(double cores, double other)
{
    return cores > other + kConflictCores;
}

/// @brief 一段事件的 CPU 微秒
double us_per_event(std::uint64_t events, double cpu_seconds)
{
    return events > 0 ? cpu_seconds * 1e6 / static_cast<double>(events) : 0.0;
}

/// @brief 通道容量向上取整为 2 的幂，与 SPSC_Queue 的容量语义一致
std::size_t queue_capacity(int queue)
{
    std::size_t capacity = 1;
    while (capacity < static_cast<std::size_t>(queue)) {
        capacity <<= 1;
    }
    return capacity;
}

/// @brief sink 后端的三段 CPU 利用率，按 collector、semantic、engine 排列
std::vector<SegmentLoad> sink_segment_loads(
    const bench::chain::ChainSnapshot& snapshot)
{
    const double seconds = snapshot.seconds > 0.0 ? snapshot.seconds : 1.0;
    std::vector<SegmentLoad> loads;
    loads.push_back({"collector", snapshot.feeder_cpu / seconds});
    loads.push_back({"semantic", snapshot.semantic_cpu / seconds});
    loads.push_back({"engine", snapshot.engine_cpu / seconds});
    return loads;
}

/**
 * @brief sink 后端的瓶颈结论
 * @param[in] snapshot 窗口结果
 * @param[in] l2 是否 L2：引擎线程内联执行真实控制面调用
 * @return 一行结论文本
 * @note 归因规则：原始通道拒收指向语义段慢，语义通道拒收指向引擎段慢，无拒收
 *       则报未饱和并给出 CPU 利用率最高的一段；当被指向段的 CPU 明显低于最紧
 *       的一段时，标「未定」并同时给出两侧证据。L2 只给引擎段加标注，不改变
 *       归因。
 */
std::string sink_bottleneck_text(const bench::chain::ChainSnapshot& snapshot,
                                 bool l2)
{
    const std::vector<SegmentLoad> loads = sink_segment_loads(snapshot);
    const SegmentLoad& tightest          = tightest_segment(loads);
    const bool semantic_slow             = snapshot.raw_drops > 0;
    const bool engine_slow               = snapshot.sem_drops > 0;
    const char* engine_label =
        l2 ? "engine (L2: control-plane lookups/enqueues run inline on the "
             "engine thread)"
           : "engine";
    char text[768] = {};

    if (!semantic_slow && !engine_slow) {
        std::snprintf(text, sizeof(text),
                      "not saturated (no drops); tightest stage=%s (CPU "
                      "utilization %.2f cores)",
                      tightest.name, tightest.cores);
        return text;
    }

    double attributed_cores = 0.0;
    if (semantic_slow) {
        attributed_cores = loads[1].cores;
    }
    if (engine_slow) {
        attributed_cores =
            attributed_cores > loads[2].cores ? attributed_cores : loads[2].cores;
    }
    const bool conflict = covers_other(tightest.cores, attributed_cores);

    if (semantic_slow && engine_slow) {
        std::snprintf(
            text, sizeof(text),
            "%sboth semantic and %s are slow: raw channel rejected %" PRIu64
            " times (the semantic stage cannot keep up with replay); the "
            "semantic channel rejected %" PRIu64
            " times (the engine cannot keep up with semantic); CPU: semantic "
            "%.2f cores, engine %.2f cores",
            conflict ? "inconclusive: " : "", engine_label, snapshot.raw_drops,
            snapshot.sem_drops, loads[1].cores, loads[2].cores);
    }
    else if (semantic_slow) {
        std::snprintf(text, sizeof(text),
                      "%ssemantic stage is slow: raw channel rejected %" PRIu64
                      " times (the semantic stage cannot keep up with replay); "
                      "CPU evidence: semantic %.2f cores",
                      conflict ? "inconclusive: " : "", snapshot.raw_drops,
                      loads[1].cores);
    }
    else {
        std::snprintf(text, sizeof(text),
                      "%s%s stage is slow: semantic channel rejected %" PRIu64
                      " times (the engine cannot keep up with semantic); CPU "
                      "evidence: engine %.2f cores",
                      conflict ? "inconclusive: " : "", engine_label,
                      snapshot.sem_drops, loads[2].cores);
    }

    std::string conclusion = text;
    if (conflict) {
        char evidence[256] = {};
        std::snprintf(evidence, sizeof(evidence),
                      "; the tightest stage by CPU=%s (%.2f cores) conflicts "
                      "with the drop attribution, so the result is inconclusive",
                      tightest.name, tightest.cores);
        conclusion += evidence;
    }
    return conclusion;
}

/// @brief sink 后端的 config 摘要
std::string sink_config(const bench::CommonOptions& options,
                        const bench::chain::ChainOptions& chain_options)
{
    char settled_text[32] = {};
    std::snprintf(settled_text, sizeof(settled_text), "%g",
                  chain_options.settled);
    return std::string("fidelity=") + bench::fidelity_name(options.fidelity) +
           ",events=" + bench::chain::event_class_name(chain_options.events) +
           ",queue=" + std::to_string(chain_options.queue) +
           ",system=" + std::to_string(chain_options.system_sinks) +
           ",settled=" + settled_text + ",backend=sink";
}

/// @brief sink 后端实现
int run_sink(const bench::CommonOptions& options, const ChainRun& run)
{
    bench::chain::ChainSnapshot snapshot;
    std::string error;
    if (!bench::chain::run_chain_sink(run.chain, snapshot, error)) {
        std::fprintf(stderr, "%s\n", error.c_str());
        return kExitRuntimeFailure;
    }

    const double window        = snapshot.seconds > 0.0 ? snapshot.seconds : 1.0;
    const double input_per_s   = static_cast<double>(snapshot.consumed) / window;
    const std::size_t capacity = queue_capacity(run.chain.queue);
    const std::string config   = sink_config(options, run.chain);

    const bool l2              = run.chain.fidelity == bench::Fidelity::L2;
    const bench::l2::ControlPlaneSnapshot& control = snapshot.control;
    const std::vector<SegmentLoad> loads           = sink_segment_loads(snapshot);
    // 合并行纳入控制面 CPU；L1 的控制面成本已经落在引擎线程里
    const double total_cpu = snapshot.feeder_cpu + snapshot.semantic_cpu +
                             snapshot.engine_cpu + (l2 ? snapshot.cp_cpu : 0.0);
    const std::uint64_t rss = bench::rss_kb();
    char settled_text[32]   = {};
    std::snprintf(settled_text, sizeof(settled_text), "%g", run.chain.settled);

    std::printf(
        "stage   : chain (sink backend: replay feeder → semantic → engine)\n");
    std::printf("config  : %s\n", config.c_str());
    if (l2) {
        std::printf(
            "fidelity: L2 (Process/Context are real components, Role is a "
            "stub)\n");
    }
    std::printf("trace   : %s\n", options.trace_path.c_str());
    std::printf("corpus  : records=%" PRIu64 " playback=%" PRIu64
                " malformed=%" PRIu64 "\n",
                snapshot.records, snapshot.playback, snapshot.malformed);
    std::printf(
        "window  : %.3fs warmup=%d rate=%g%s\n", snapshot.seconds,
        options.warmup_seconds, options.rate,
        options.rate == 0.0 ? " (full speed)" : " (collector input records/s)");
    std::printf("input   : %.1f records/s consumed=%" PRIu64 "\n", input_per_s,
                snapshot.consumed);
    std::printf("events by class: syscall=%" PRIu64 " lifecycle=%" PRIu64
                " (feeder-side window counts)\n",
                snapshot.consumed - snapshot.consumed_lifecycle,
                snapshot.consumed_lifecycle);
    std::printf("segments (us/event, core utilization):\n");
    std::printf("  collector  consumed=%" PRIu64
                " us/event=%.3f cpu=%.3fs util=%.2f cores"
                " peak_queue=%" PRIu64 "\n",
                snapshot.consumed,
                us_per_event(snapshot.consumed, snapshot.feeder_cpu),
                snapshot.feeder_cpu, loads[0].cores, snapshot.raw_peak);
    std::printf("  semantic   processed=%" PRIu64
                " us/event=%.3f cpu=%.3fs util=%.2f cores"
                " drops=%" PRIu64 " peak_queue=%" PRIu64 "\n",
                snapshot.processed,
                us_per_event(snapshot.processed, snapshot.semantic_cpu),
                snapshot.semantic_cpu, loads[1].cores, snapshot.raw_drops,
                snapshot.sem_peak);
    std::printf("  engine     dispatched=%" PRIu64
                " us/event=%.3f cpu=%.3fs util=%.2f cores"
                " drops=%" PRIu64 " peak_queue=%" PRIu64 "\n",
                snapshot.dispatched,
                us_per_event(snapshot.dispatched, snapshot.engine_cpu),
                snapshot.engine_cpu, loads[2].cores, snapshot.sem_drops,
                snapshot.sem_peak);
    if (l2) {
        std::printf(
            "  control    us/event=%.3f cpu=%.3fs util=%.2f cores"
            " (queue depth is not observable)\n",
            us_per_event(snapshot.dispatched, snapshot.cp_cpu), snapshot.cp_cpu,
            snapshot.cp_cpu / window);
    }
    std::printf("queues  : raw peak=%" PRIu64 "/%zu sem peak=%" PRIu64
                "/%zu system_sinks=%d unsettled=%" PRIu64 "\n",
                snapshot.raw_peak, capacity, snapshot.sem_peak, capacity,
                run.chain.system_sinks, snapshot.unsettled);
    std::printf(
        "chain   : dispatched=%" PRIu64
        " events/s=%.1f us/event=%.3f"
        " drops=%" PRIu64 " cpu=%.3fs rss_kb=%" PRIu64 "\n",
        snapshot.dispatched,
        window > 0.0 ? static_cast<double>(snapshot.dispatched) / window : 0.0,
        us_per_event(snapshot.dispatched, total_cpu),
        snapshot.raw_drops + snapshot.sem_drops, total_cpu, rss);
    std::printf("bottleneck: %s\n", sink_bottleneck_text(snapshot, l2).c_str());
    if (l2 && snapshot.sem_drops > 0) {
        const char* note_tail =
            snapshot.raw_drops == 0
                ? " the capacity drop comes mainly from the control plane, do "
                  "not judge it by cp CPU alone"
                : " do not judge control-plane cost by cp CPU alone";
        std::printf(
            "note: under L2 part of the control-plane cost runs inline on the "
            "engine thread (compare the us/event gap with L1), the rest runs on "
            "the cp threads (%.2f cores);%s\n",
            snapshot.cp_cpu / window, note_tail);
    }
    if (l2) {
        std::printf("cp util=%.2f cores (queue depth is not observable)\n",
                    snapshot.cp_cpu / window);
    }
    if (l2 && window > 0.0 && snapshot.cp_cpu / window > kControlCores) {
        std::printf(
            "signal: control plane utilization is high (%.2f cores; queue "
            "depth is not observable)\n",
            snapshot.cp_cpu / window);
    }
    if (l2) {
        std::printf(
            "cp cpu=%.3fs (control plane; queue depth is not observable) "
            "cp_us/event=%.3f\n",
            snapshot.cp_cpu, us_per_event(snapshot.dispatched, snapshot.cp_cpu));
        std::printf(
            "seeds: role stubs settled=%s seeded=%" PRIu64
            " (under L2 --settled only applies to role stubs; context is a real "
            "seed, all trace processes are hit)\n",
            settled_text, control.seed.roles);
        std::printf(
            "process seed: batch=%zu (supplemented parents %" PRIu64
            "), inserted=%" PRIu64 " duplicate=%" PRIu64 " pid_reused=%" PRIu64
            " parent_missing=%" PRIu64 " invalid=%" PRIu64
            " rejected_state=%" PRIu64 "\n",
            control.seed.batch_entries, control.seed.supplemented,
            control.seed.process.inserted, control.seed.process.duplicate,
            control.seed.process.pid_reused, control.seed.process.parent_missing,
            control.seed.process.invalid, control.seed.process.rejected_state);
        std::printf("seed exe: real=%" PRIu64 " synthetic=%" PRIu64 "\n",
                    control.seed.exe_real, control.seed.exe_synthetic);
        std::printf("context seed: inserted=%" PRIu64 " bound=%" PRIu64
                    " plan_derive=%" PRIu64 " plan_bind=%" PRIu64
                    " duplicate=%" PRIu64 " rejected_out_of_order=%" PRIu64
                    " rejected_invalid=%" PRIu64 " rejected_state=%" PRIu64 "\n",
                    control.seed.context.inserted, control.seed.context.bound,
                    control.seed.plan_derive, control.seed.plan_bind,
                    control.seed.context.duplicate,
                    control.seed.context.rejected_out_of_order,
                    control.seed.context.rejected_invalid,
                    control.seed.context.rejected_state);
        std::printf("PM stats: pid_reused=+%" PRIu64 " stale_add=+%" PRIu64
                    " parent_missing=+%" PRIu64 " tombstone_depth=%" PRIu64 "\n",
                    control.process.pid_reused, control.process.stale_add,
                    control.process.parent_missing,
                    control.process.tombstone_depth);
        std::printf(
            "CM stats: pending_deferred=+%" PRIu64 " pending_resolved=+%" PRIu64
            " pending_rejected=+%" PRIu64 " pending_expired=+%" PRIu64
            " pending_cancelled=+%" PRIu64 " pending_depth=%" PRIu64
            " bind_orphaned=+%" PRIu64 " extra_orphaned=+%" PRIu64
            " parent_missing=+%" PRIu64 " late_register=+%" PRIu64
            " late_bind=+%" PRIu64 " duplicate_context=+%" PRIu64
            " ownership_conflict=+%" PRIu64 " tombstone_hits=+%" PRIu64
            " tombstone_depth=%" PRIu64 " ctxroot_parent_unsettled=+%" PRIu64
            " unknown_unregister=+%" PRIu64 "\n",
            control.context.pending_deferred, control.context.pending_resolved,
            control.context.pending_rejected, control.context.pending_expired,
            control.context.pending_cancelled, control.context.pending_depth,
            control.context.bind_orphaned, control.context.extra_orphaned,
            control.context.parent_missing, control.context.late_register,
            control.context.late_bind, control.context.duplicate_context,
            control.context.ownership_conflict, control.context.tombstone_hits,
            control.context.tombstone_depth,
            control.context.ctxroot_parent_unsettled,
            control.context.unknown_unregister);
        if (control.process.stale_add > 0 || control.context.late_register > 0) {
            std::printf(
                "hint: replaying the trace in a loop resurrects exited process "
                "identities (stale_add=+%" PRIu64 " late_register=+%" PRIu64
                "), so this stage's lifecycle cost includes the tombstone path; "
                "use --events syscall for steady-state capacity\n",
                control.process.stale_add, control.context.late_register);
        }
    }
    std::printf(
        "collector=replay feeder (equivalent parsing); CLI/wire not included\n");
    std::printf(
        "hint: when compared with the standalone semantic stage, note that its "
        "drain thread uses zero-backlog accounting (a lower bound)\n");

    const auto build_result =
        [&](const std::string& stage, std::uint64_t events, double cpu_seconds,
            std::uint64_t drops, std::uint64_t raw_drops, std::uint64_t out_drops,
            std::uint64_t peak_queue, std::uint64_t out_peak_queue) {
            bench::Result result;
            result.stage        = stage;
            result.config       = config;
            result.rate         = options.rate;
            result.seconds      = snapshot.seconds;
            result.events       = events;
            result.events_per_s = events / window;
            result.us_per_event = us_per_event(events, cpu_seconds);
            result.producer_us_per_event =
                us_per_event(snapshot.consumed, snapshot.feeder_cpu);
            result.producer_us_per_success =
                us_per_event(snapshot.push_ok, snapshot.feeder_cpu);
            result.drops          = drops;
            result.raw_drops      = raw_drops;
            result.out_drops      = out_drops;
            result.rss_kb         = rss;
            result.peak_queue     = peak_queue;
            result.out_peak_queue = out_peak_queue;
            return result;
        };

    const std::vector<bench::Result> results = {
        build_result("chain", snapshot.dispatched, total_cpu,
                     snapshot.raw_drops + snapshot.sem_drops, snapshot.raw_drops,
                     snapshot.sem_drops, snapshot.raw_peak, snapshot.sem_peak),
        build_result("chain/collector", snapshot.consumed, snapshot.feeder_cpu,
                     snapshot.raw_drops, snapshot.raw_drops, 0, snapshot.raw_peak,
                     0),
        build_result("chain/semantic", snapshot.processed, snapshot.semantic_cpu,
                     snapshot.raw_drops, snapshot.raw_drops, snapshot.sem_drops,
                     snapshot.raw_peak, snapshot.sem_peak),
        build_result("chain/engine", snapshot.dispatched, snapshot.engine_cpu,
                     snapshot.sem_drops, 0, snapshot.sem_drops, snapshot.sem_peak,
                     0),
    };
    for (const bench::Result& result : results) {
        if (!bench::append_tsv(options.out_path, result)) {
            std::fprintf(
                stderr, "failed to write TSV: %s\n",
                options.out_path.empty() ? "stdout" : options.out_path.c_str());
            return kExitRuntimeFailure;
        }
    }
    return 0;
}

#ifdef HNG_BENCH_CLI_STAGE

// ============================================================
// CLI 后端：T0、侧车与子进程
// ============================================================

/// @brief 子进程 T0 与侧车的路径；pid 为子进程号
std::string chain_temp_path(pid_t pid, const char* suffix)
{
    return "/tmp/hng-chain-" + std::to_string(static_cast<long>(pid)) + suffix;
}

/// @brief 写一个短文本文件；用于 T0
bool write_text_file(const std::string& path, const std::string& content)
{
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    if (!file.is_open()) {
        return false;
    }
    file << content;
    file.flush();
    const bool good = file.good();
    file.close();
    return good;
}

/// @brief 读 T0 文件，内容为 t0_ns=<单调时钟纳秒>；最多等 20s
bool read_t0_file(const std::string& path, bench::cli::ServerProcess& server,
                  bench::Clock::time_point& t0, std::string& error)
{
    constexpr const char kPrefix[] = "t0_ns=";
    const bench::Clock::time_point deadline =
        bench::Clock::now() + std::chrono::seconds(20);
    for (;;) {
        int code = 0;
        if (!server.alive(code)) {
            error = "child process exited before writing the T0 file (" +
                    bench::cli::describe_exit(code) + ")";
            return false;
        }
        std::ifstream file(path);
        if (file.is_open()) {
            std::string line;
            if (std::getline(file, line)) {
                const std::size_t prefix_size = sizeof(kPrefix) - 1;
                if (line.compare(0, prefix_size, kPrefix) == 0) {
                    const char* text      = line.c_str() + prefix_size;
                    errno                 = 0;
                    char* end             = nullptr;
                    const long long value = std::strtoll(text, &end, 10);
                    if (errno == 0 && end != text && *end == '\0' && value >= 0) {
                        t0 = bench::Clock::time_point(
                            std::chrono::nanoseconds(value));
                        error.clear();
                        return true;
                    }
                }
            }
        }
        if (bench::Clock::now() >= deadline) {
            error = "timed out after 20s waiting for T0 file " + path +
                    ", or its content is invalid";
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

/**
 * @brief 原子写 go 文件：先写 <path>.tmp 再 rename
 * @param[in] path 目标路径
 * @return 成功时为 true
 * @note 与侧车一样用 rename 落地，子进程轮询时不会读到半截内容。
 */
bool write_go_file(const std::string& path)
{
    const std::string staging = path + ".tmp";
    if (!write_text_file(staging, "go\n")) {
        return false;
    }
    if (std::rename(staging.c_str(), path.c_str()) != 0) {
        const int saved = errno;
        (void)::unlink(staging.c_str());
        errno = saved;
        return false;
    }
    return true;
}

/**
 * @brief 等父进程写 go 文件；最多等 20s
 * @param[in] path go 文件路径
 * @param[in] stop 主线程置位后提前退出
 * @param[out] error 超时或停机原因
 * @return 收到 go 时为 true
 */
bool wait_for_go_file(const std::string& path, const std::atomic<bool>& stop,
                      std::string& error)
{
    const bench::Clock::time_point deadline =
        bench::Clock::now() + std::chrono::seconds(20);
    while (!stop.load(std::memory_order_acquire)) {
        {
            std::ifstream probe(path);
            if (probe.is_open()) {
                error.clear();
                return true;
            }
        }
        if (bench::Clock::now() >= deadline) {
            error = "timed out waiting for go file " + path + " after 20s";
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    error = "received a stop signal before the go file appeared";
    return false;
}

/// @brief 子进程窗口侧车
struct ChainSidecar {
    std::int64_t t0_ns = 0;                ///< 子进程写入的 T0（纳秒）
    double warmup_s    = 0.0;              ///< 子进程的预热秒数
    double window_s    = 0.0;              ///< 子进程的窗口秒数
    bench::chain::ChainSnapshot snapshot;  ///< 窗口内的增量
};

/// @brief 严格无符号整数解析
bool parse_unsigned(const std::string& text, std::uint64_t& value)
{
    if (text.empty()) {
        return false;
    }
    errno                           = 0;
    char* end                       = nullptr;
    const unsigned long long parsed = std::strtoull(text.c_str(), &end, 10);
    if (errno != 0 || end == text.c_str() || *end != '\0') {
        return false;
    }
    value = static_cast<std::uint64_t>(parsed);
    return true;
}

/// @brief 严格有符号整数解析
bool parse_signed(const std::string& text, std::int64_t& value)
{
    if (text.empty()) {
        return false;
    }
    errno                  = 0;
    char* end              = nullptr;
    const long long parsed = std::strtoll(text.c_str(), &end, 10);
    if (errno != 0 || end == text.c_str() || *end != '\0') {
        return false;
    }
    value = static_cast<std::int64_t>(parsed);
    return true;
}

/// @brief 严格浮点解析
bool parse_real(const std::string& text, double& value)
{
    if (text.empty()) {
        return false;
    }
    errno               = 0;
    char* end           = nullptr;
    const double parsed = std::strtod(text.c_str(), &end);
    if (errno != 0 || end == text.c_str() || *end != '\0' ||
        !std::isfinite(parsed)) {
        return false;
    }
    value = parsed;
    return true;
}

/**
 * @brief 子进程写出的窗口侧车
 * @param[in] path 目标路径
 * @param[in] t0_ns T0 的单调时钟纳秒
 * @param[in] chain_options 预热与窗口秒数
 * @param[in] window 窗口内的增量
 * @return 成功时为 true
 * @note 先写 <path>.tmp 再 rename，父进程轮询最终路径时不会读到半截文件。
 */
bool write_sidecar(const std::string& path, std::int64_t t0_ns,
                   const bench::chain::ChainOptions& chain_options,
                   const bench::chain::ChainSnapshot& window)
{
    const std::string staging = path + ".tmp";
    std::ofstream file(staging, std::ios::binary | std::ios::trunc);
    if (!file.is_open()) {
        return false;
    }
    file << "t0_ns=" << t0_ns << "\n"
         << "warmup_s=" << chain_options.warmup_seconds << "\n"
         << "window_s=" << chain_options.seconds << "\n"
         << "collector.consumed=" << window.consumed << "\n"
         << "collector.malformed=" << window.malformed << "\n"
         << "collector.push_ok=" << window.push_ok << "\n"
         << "collector.push_fail=" << window.push_fail << "\n"
         << "collector.lifecycle=" << window.consumed_lifecycle << "\n"
         << "semantic.processed=" << window.processed << "\n"
         << "semantic.raw_drops=" << window.raw_drops << "\n"
         << "semantic.out_drops=" << window.sem_drops << "\n"
         << "engine.dispatched=" << window.dispatched << "\n"
         << "engine.syscall_dropped=" << window.engine_syscall_dropped << "\n"
         << "engine.unsettled=" << window.unsettled << "\n"
         << "engine.idle_waits=" << window.engine_idle_waits << "\n"
         << "queue.raw_peak=" << window.raw_peak << "\n"
         << "queue.sem_peak=" << window.sem_peak << "\n"
         << "cpu.feeder=" << window.feeder_cpu << "\n"
         << "cpu.semantic=" << window.semantic_cpu << "\n"
         << "cpu.engine=" << window.engine_cpu << "\n";
    file.flush();
    const bool good = file.good();
    file.close();
    if (!good) {
        (void)::unlink(staging.c_str());
        return false;
    }
    if (std::rename(staging.c_str(), path.c_str()) != 0) {
        (void)::unlink(staging.c_str());
        return false;
    }
    return true;
}

/// @brief 读侧车并校验所有键都存在且可解析
bool load_sidecar(const std::string& path, ChainSidecar& sidecar,
                  std::string& error)
{
    std::ifstream file(path);
    if (!file.is_open()) {
        error = "cannot open " + path;
        return false;
    }
    std::map<std::string, std::string> fields;
    std::string line;
    while (std::getline(file, line)) {
        if (line.empty()) {
            continue;
        }
        const std::size_t equals = line.find('=');
        if (equals == std::string::npos) {
            error = "sidecar line is missing '=': " + line;
            return false;
        }
        fields[line.substr(0, equals)] = line.substr(equals + 1);
    }
    if (file.bad()) {
        error = "failed to read sidecar: " + path;
        return false;
    }

    std::string missing;
    std::string invalid;
    const auto take = [&](const char* key, const std::string*& out) -> bool {
        const auto found = fields.find(key);
        if (found == fields.end()) {
            if (!missing.empty()) {
                missing += ",";
            }
            missing += key;
            return false;
        }
        out = &found->second;
        return true;
    };
    const auto take_u64 = [&](const char* key, std::uint64_t& out) {
        const std::string* text = nullptr;
        if (!take(key, text)) {
            return;
        }
        if (!parse_unsigned(*text, out)) {
            if (!invalid.empty()) {
                invalid += ",";
            }
            invalid += key;
        }
    };
    const auto take_real = [&](const char* key, double& out) {
        const std::string* text = nullptr;
        if (!take(key, text)) {
            return;
        }
        if (!parse_real(*text, out)) {
            if (!invalid.empty()) {
                invalid += ",";
            }
            invalid += key;
        }
    };

    const std::string* t0_value = nullptr;
    if (take("t0_ns", t0_value) && !parse_signed(*t0_value, sidecar.t0_ns)) {
        invalid += invalid.empty() ? "t0_ns" : ",t0_ns";
    }
    take_real("warmup_s", sidecar.warmup_s);
    take_real("window_s", sidecar.window_s);

    bench::chain::ChainSnapshot& snapshot = sidecar.snapshot;
    take_u64("collector.consumed", snapshot.consumed);
    take_u64("collector.malformed", snapshot.malformed);
    take_u64("collector.push_ok", snapshot.push_ok);
    take_u64("collector.push_fail", snapshot.push_fail);
    take_u64("collector.lifecycle", snapshot.consumed_lifecycle);
    take_u64("semantic.processed", snapshot.processed);
    take_u64("semantic.raw_drops", snapshot.raw_drops);
    take_u64("semantic.out_drops", snapshot.sem_drops);
    take_u64("engine.dispatched", snapshot.dispatched);
    take_u64("engine.syscall_dropped", snapshot.engine_syscall_dropped);
    take_u64("engine.unsettled", snapshot.unsettled);
    take_u64("engine.idle_waits", snapshot.engine_idle_waits);
    take_u64("queue.raw_peak", snapshot.raw_peak);
    take_u64("queue.sem_peak", snapshot.sem_peak);
    take_real("cpu.feeder", snapshot.feeder_cpu);
    take_real("cpu.semantic", snapshot.semantic_cpu);
    take_real("cpu.engine", snapshot.engine_cpu);
    snapshot.seconds = sidecar.window_s;

    if (!missing.empty()) {
        error = "sidecar is missing keys: " + missing;
        return false;
    }
    if (!invalid.empty()) {
        error = "sidecar has invalid values: " + invalid;
        return false;
    }
    error.clear();
    return true;
}

/// @brief 轮询侧车直到它出现；最多等 2s，出现后立刻解析
bool wait_for_sidecar(const std::string& path, ChainSidecar& sidecar,
                      std::string& error)
{
    const bench::Clock::time_point deadline =
        bench::Clock::now() + std::chrono::seconds(2);
    for (;;) {
        {
            std::ifstream probe(path);
            if (probe.is_open()) {
                probe.close();
                return load_sidecar(path, sidecar, error);
            }
        }
        if (bench::Clock::now() >= deadline) {
            error = "timed out waiting for sidecar " + path + " after 2s";
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

/// @brief 睡到绝对时刻；期间看到停止标志就提前返回 false
bool sleep_until_or_stop(bench::Clock::time_point deadline,
                         const std::atomic<bool>& stop)
{
    while (!stop.load(std::memory_order_acquire)) {
        const bench::Clock::time_point now = bench::Clock::now();
        if (now >= deadline) {
            return true;
        }
        const auto remaining = deadline - now;
        const auto step      = std::chrono::milliseconds(10);
        std::this_thread::sleep_for(remaining < step ? remaining : step);
    }
    return false;
}

/**
 * @brief 子进程控制线程：等 go 握手、启动回放、窗口两端取快照并写侧车
 * @param[in,out] runtime 已启动（defer_feeder）的整链
 * @param[in] go_path 父进程写出的 go 文件
 * @param[in] t0_path T0 文件
 * @param[in] chain_options 预热与窗口秒数
 * @param[in] sidecar_path 侧车路径
 * @param[in] stop 主线程置位后提前退出
 * @param[out] failed 快照、写 T0 或写侧车失败时置位
 * @note 收到 go 后才取 T0、启动回放并写 T0 文件，父进程据此对齐窗口；go 等待
 *       超时直接 _exit(1)。侧车写完后再小睡直到停止标志。
 */
void run_chain_control(bench::chain::ChainRuntime& runtime,
                       const std::string& go_path, const std::string& t0_path,
                       const bench::chain::ChainOptions& chain_options,
                       const std::string& sidecar_path,
                       const std::atomic<bool>& stop, std::atomic<bool>& failed)
{
    (void)::prctl(PR_SET_NAME, "hng-chain-ctl");
    std::string error;
    if (!wait_for_go_file(go_path, stop, error)) {
        if (stop.load(std::memory_order_acquire)) {
            return;
        }
        std::fprintf(stderr, "chain control thread: %s\n", error.c_str());
        failed.store(true, std::memory_order_release);
        ::_exit(kExitRuntimeFailure);
    }

    const bench::Clock::time_point t0 = bench::Clock::now();
    if (!runtime.start_feeder(error)) {
        std::fprintf(
            stderr,
            "chain control thread: failed to start the replay thread: %s\n",
            error.c_str());
        failed.store(true, std::memory_order_release);
        ::_exit(kExitRuntimeFailure);
    }
    const std::int64_t t0_ns =
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            t0.time_since_epoch())
            .count();
    if (!write_text_file(t0_path, "t0_ns=" + std::to_string(t0_ns) + "\n")) {
        std::fprintf(stderr, "chain control thread: failed to write T0 file %s\n",
                     t0_path.c_str());
        failed.store(true, std::memory_order_release);
        ::_exit(kExitRuntimeFailure);
    }

    const bench::Clock::time_point begin_time =
        t0 + std::chrono::seconds(chain_options.warmup_seconds);
    const bench::Clock::time_point end_time =
        begin_time + std::chrono::seconds(chain_options.seconds);

    if (!sleep_until_or_stop(begin_time, stop)) {
        return;
    }
    bench::chain::ChainSnapshot begin;
    if (!runtime.snapshot(begin, error)) {
        std::fprintf(
            stderr,
            "chain control thread: failed to snapshot the window start: %s\n",
            error.c_str());
        failed.store(true, std::memory_order_release);
        return;
    }
    if (!sleep_until_or_stop(end_time, stop)) {
        return;
    }
    bench::chain::ChainSnapshot end;
    if (!runtime.snapshot(end, error)) {
        std::fprintf(
            stderr,
            "chain control thread: failed to snapshot the window end: %s\n",
            error.c_str());
        failed.store(true, std::memory_order_release);
        return;
    }

    const bench::chain::ChainSnapshot window =
        bench::chain::window_delta(begin, end);
    if (!write_sidecar(sidecar_path, t0_ns, chain_options, window)) {
        std::fprintf(stderr, "chain control thread: failed to write sidecar %s\n",
                     sidecar_path.c_str());
        failed.store(true, std::memory_order_release);
        return;
    }

    while (!stop.load(std::memory_order_acquire)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

/**
 * @brief CLI 子进程入口：整链（defer feeder）→ 控制线程 → RunCliServer
 * @param[in] chain_options 语料、速率与通道参数
 * @param[in] run 后端参数（每流队列容量）
 * @param[in] socket_path 最终生效的 socket
 * @param[in] go_path 父进程写出的 go 文件
 * @param[in] t0_path T0 文件
 * @param[in] sidecar_path 窗口侧车
 * @note 调用点必须已 fork 且尚未创建任何线程；PDEATHSIG、临时配置与退出码由
 *       bench::cli::run_cli_server_child 处理。回放线程由控制线程在收到 go 后
 *       启动；RunCliServer 返回后置停止标志、join 控制线程、停机、删除三个
 *       临时文件，再以 _exit(0) 收尾；异常以 _exit(1) 收尾。
 */
[[noreturn]] void run_chain_child(const bench::chain::ChainOptions& chain_options,
                                  const ChainRun& run,
                                  const std::string& socket_path,
                                  const std::string& go_path,
                                  const std::string& t0_path,
                                  const std::string& sidecar_path)
{
    bench::cli::ServerConfigSpec spec;
    spec.socket_path            = socket_path;
    spec.queue_capacity         = run.cli_queue;
    spec.max_concurrent_streams = 64;

    bench::cli::run_cli_server_child(
        spec, [&](const PreparedCliServerConfig& prepared) {
            bench::chain::ChainRuntime runtime;
            std::string error;
            if (!runtime.start(chain_options, error, /*defer_feeder=*/true)) {
                std::fprintf(stderr,
                             "failed to start the chain child process: %s\n",
                             error.c_str());
                ::_exit(kExitRuntimeFailure);
            }

            std::atomic<bool> stop{false};
            std::atomic<bool> control_failed{false};
            std::thread control([&] {
                run_chain_control(runtime, go_path, t0_path, chain_options,
                                  sidecar_path, stop, control_failed);
            });

            CLIServerDeps deps;
            deps.role    = &runtime.role_lookup_service();
            deps.context = &runtime.context_lookup_service();
            deps.process = &runtime.process_lookup_service();
            deps.subs    = &runtime.subscriber_service();
            deps.stats   = &runtime.stats_service();

            RunCliServer(deps, prepared);

            stop.store(true, std::memory_order_release);
            if (control.joinable()) {
                control.join();
            }
            runtime.stop();
            (void)::unlink(go_path.c_str());
            (void)::unlink(t0_path.c_str());
            (void)::unlink(sidecar_path.c_str());
            if (control_failed.load(std::memory_order_acquire)) {
                std::fprintf(stderr,
                             "chain child control thread failed (see stderr for "
                             "go/T0/sidecar)\n");
                ::_exit(kExitRuntimeFailure);
            }
        });
}

// ============================================================
// CLI 后端：父进程
// ============================================================

/// @brief 析构时删除一个临时文件的守卫
class ScopedUnlink final {
   public:
    explicit ScopedUnlink(std::string path) : path_(std::move(path)) {}
    ~ScopedUnlink()
    {
        if (!path_.empty()) {
            (void)::unlink(path_.c_str());
        }
    }

    ScopedUnlink(const ScopedUnlink&)            = delete;
    ScopedUnlink& operator=(const ScopedUnlink&) = delete;

   private:
    std::string path_;
};

/// @brief 读取指定进程的常驻内存，单位 KiB；读取失败返回 0
std::uint64_t read_process_rss_kb(pid_t pid)
{
    std::ifstream status("/proc/" + std::to_string(static_cast<long>(pid)) +
                         "/status");
    std::string line;
    while (std::getline(status, line)) {
        if (line.compare(0, 6, "VmRSS:") != 0) {
            continue;
        }
        const char* text = line.c_str() + 6;
        while (*text == ' ' || *text == '\t') {
            ++text;
        }
        errno                          = 0;
        char* end                      = nullptr;
        const unsigned long long value = std::strtoull(text, &end, 10);
        if (end != text && errno == 0) {
            return static_cast<std::uint64_t>(value);
        }
        break;
    }
    return 0;
}

/// @brief CLI 后端的瓶颈结论
std::string cli_bottleneck_text(const bench::chain::ChainSnapshot& snapshot,
                                std::uint64_t cli_drops,
                                const std::vector<SegmentLoad>& loads,
                                double client_cores, double cli_cores)
{
    const SegmentLoad& tightest = tightest_segment(loads);
    char text[512]              = {};
    if (cli_drops > 0) {
        std::snprintf(
            text, sizeof(text),
            "cli seam is slow: cli queue rejected %" PRIu64
            " times (the client cannot drain as fast as the server delivers); "
            "CPU evidence: cli-tp %.2f cores, client %.2f cores",
            cli_drops, cli_cores, client_cores);
        return text;
    }
    if (snapshot.sem_drops > 0) {
        std::snprintf(text, sizeof(text),
                      "engine stage is slow: semantic channel rejected %" PRIu64
                      " times (the engine cannot keep up with semantic); CPU "
                      "evidence: engine %.2f cores",
                      snapshot.sem_drops, loads[2].cores);
        return text;
    }
    if (snapshot.raw_drops > 0) {
        std::snprintf(text, sizeof(text),
                      "semantic stage is slow: raw channel rejected %" PRIu64
                      " times (the semantic stage cannot keep up with replay); "
                      "CPU evidence: semantic %.2f cores",
                      snapshot.raw_drops, loads[1].cores);
        return text;
    }
    std::snprintf(text, sizeof(text),
                  "not saturated (no drops); tightest stage=%s (CPU utilization "
                  "%.2f cores)",
                  tightest.name, tightest.cores);
    return text;
}

/**
 * @brief 轮询 GetPipelineStats 直到服务端登记了全部订阅流
 * @param[in,out] stub 客户端 stub
 * @param[in] streams 期望的活跃流数
 * @param[out] snapshot 最后一次成功的快照；失败时 active 为最后读到的值
 * @param[out] error 超时原因
 * @return 在 5s 内达到时为 true
 * @note 流线程启动不代表服务端已建流；建流完成前开始推事件会让每流队列在窗口
 *       起点就积压，故把它作为 go 握手的一部分。
 */
bool wait_for_active_streams(hng::clisv::RuntimeService::Stub& stub, int streams,
                             bench::cli::PipelineStatsSnapshot& snapshot,
                             std::string& error)
{
    const bench::Clock::time_point deadline =
        bench::Clock::now() + std::chrono::seconds(5);
    std::string last_error;
    while (bench::Clock::now() < deadline) {
        if (bench::cli::fetch_pipeline_stats(stub, snapshot, last_error) &&
            snapshot.active >= static_cast<std::uint64_t>(streams)) {
            error.clear();
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    error =
        "server did not register all subscription streams within 5s (active=" +
        std::to_string(snapshot.active) + "/" + std::to_string(streams) +
        (last_error.empty() ? "" : ": " + last_error) + ")";
    return false;
}

/// @brief CLI 后端的 config 摘要
std::string cli_config(const bench::CommonOptions& options, const ChainRun& run)
{
    char settled_text[32] = {};
    std::snprintf(settled_text, sizeof(settled_text), "%g", run.chain.settled);
    return std::string("fidelity=") + bench::fidelity_name(options.fidelity) +
           ",events=" + bench::chain::event_class_name(run.chain.events) +
           ",queue=" + std::to_string(run.chain.queue) +
           ",cli_queue=" + std::to_string(run.cli_queue) +
           ",system=" + std::to_string(run.chain.system_sinks) +
           ",settled=" + settled_text + ",backend=cli" +
           ",streams=" + std::to_string(run.streams) +
           ",batch=" + std::to_string(run.batch);
}

/// @brief CLI 后端实现
int run_cli_backend(const bench::CommonOptions& options, const ChainRun& run)
{
    const bool owns_socket = run.socket_path.empty();
    const std::string socket_path =
        owns_socket ? bench::cli::temporary_socket_path("hng-chain-cli")
                    : run.socket_path;
    if (owns_socket) {
        (void)::unlink(socket_path.c_str());
    }

    // 子进程必须在任何线程创建之前 fork：userver 与整链都会建线程
    const pid_t child = bench::cli::fork_server_process();
    if (child < 0) {
        return kExitRuntimeFailure;
    }

    if (child == 0) {
        // fork 之后 child 恒为 0：路径必须按子进程自己的 pid 生成
        const pid_t self = ::getpid();
        run_chain_child(run.chain, run, socket_path, chain_temp_path(self, ".go"),
                        chain_temp_path(self, ".start"),
                        chain_temp_path(self, ".stats"));
    }
    const std::string go_path      = chain_temp_path(child, ".go");
    const std::string t0_path      = chain_temp_path(child, ".start");
    const std::string sidecar_path = chain_temp_path(child, ".stats");
    // 先清掉同 pid 的旧文件，避免子进程把上一轮的 go 当成本轮握手
    (void)::unlink(go_path.c_str());
    (void)::unlink(t0_path.c_str());
    (void)::unlink(sidecar_path.c_str());

    ScopedUnlink go_guard(go_path);
    ScopedUnlink t0_guard(t0_path);
    ScopedUnlink sidecar_guard(sidecar_path);
    bench::cli::ServerProcess server(child);
    bench::cli::SocketFile socket_file(socket_path, owns_socket);
    bench::cli::Client client              = bench::cli::make_client(socket_path);
    hng::clisv::RuntimeService::Stub& stub = *client.stub;
    bench::cli::StreamList streams = bench::cli::make_streams(run.streams);

    const auto fail                = [&](const std::string& message) {
        bench::cli::stop_streams(streams);
        std::string ignored;
        (void)server.shutdown(ignored);
        std::fprintf(stderr, "runtime failure: %s\n", message.c_str());
        return kExitRuntimeFailure;
    };

    std::string error;
    if (!bench::cli::wait_for_server(stub, server, socket_path, error)) {
        int code = 0;
        if (!server.alive(code) &&
            error.find("server child process exited before becoming ready") ==
                std::string::npos) {
            return fail("server child process exited before becoming ready (" +
                        bench::cli::describe_exit(code) + "): " + error);
        }
        return fail(error);
    }

    // 先订阅并等服务端登记全部流，再发 go：T0 时客户端已就绪，1s 预热里
    // 不再含建流瞬态，窗口起点也不会带着已积压的每流队列
    const std::vector<std::uint32_t> role_ids;
    bench::cli::start_streams(stub, streams,
                              static_cast<std::uint32_t>(run.batch), role_ids);
    if (!bench::cli::wait_stream_tids(streams)) {
        return fail("timed out waiting for client stream threads to publish tid");
    }
    bench::cli::PipelineStatsSnapshot ready_stats;
    if (!wait_for_active_streams(stub, run.streams, ready_stats, error)) {
        return fail(error);
    }
    const bench::Clock::time_point subscribed_at = bench::Clock::now();

    // 握手：服务端就绪且全部订阅流已登记后，子进程才取 T0 并启动回放
    errno                                        = 0;
    if (!write_go_file(go_path)) {
        const std::string reason =
            errno != 0 ? std::strerror(errno) : "unknown reason";
        return fail("failed to write go file " + go_path + ": " + reason);
    }

    bench::Clock::time_point t0;
    if (!read_t0_file(t0_path, server, t0, error)) {
        return fail("failed to read child T0: " + error);
    }

    const std::chrono::seconds warmup(run.chain.warmup_seconds);
    const bench::Clock::time_point measure_start = t0 + warmup;
    const bench::Clock::time_point measure_end =
        measure_start + std::chrono::seconds(run.chain.seconds);

    // 订阅早于 T0，正常情况下必过；保留检查以防将来把订阅挪回 T0 之后
    if (subscribed_at > measure_start) {
        const double late =
            std::chrono::duration<double>(subscribed_at - measure_start).count();
        char detail[256] = {};
        std::snprintf(detail, sizeof(detail),
                      "subscription finished %.3fs after the window start "
                      "(warmup=%d s), so the window "
                      "cannot be aligned; increase --warmup (recommended >= %d)",
                      late, run.chain.warmup_seconds,
                      run.chain.warmup_seconds + static_cast<int>(late) + 1);
        return fail(detail);
    }

    std::this_thread::sleep_until(measure_start);
    double client_cpu_start = 0.0;
    if (!bench::cli::sample_client_cpu(streams, client_cpu_start, error)) {
        return fail(error);
    }
    std::vector<bench::cli::StreamCounts> counts_start(streams.size());
    for (std::size_t index = 0; index < streams.size(); ++index) {
        counts_start[index] = bench::cli::read_counts(*streams[index]);
    }
    const double cli_tp_start =
        bench::cli::thread_cpu_by_comm(child, kCliTaskProcessor);
    bench::cli::PipelineStatsSnapshot stats_start;
    if (!bench::cli::fetch_pipeline_stats(stub, stats_start, error)) {
        return fail("GetPipelineStats at the window start failed: " + error);
    }

    std::this_thread::sleep_until(measure_end);
    double client_cpu_end = 0.0;
    if (!bench::cli::sample_client_cpu(streams, client_cpu_end, error)) {
        return fail(error);
    }
    std::vector<bench::cli::StreamCounts> counts_end(streams.size());
    for (std::size_t index = 0; index < streams.size(); ++index) {
        counts_end[index] = bench::cli::read_counts(*streams[index]);
    }
    const double cli_tp_end =
        bench::cli::thread_cpu_by_comm(child, kCliTaskProcessor);
    bench::cli::PipelineStatsSnapshot stats_end;
    if (!bench::cli::fetch_pipeline_stats(stub, stats_end, error)) {
        return fail("GetPipelineStats at the window end failed: " + error);
    }
    const std::uint64_t child_rss_kb = read_process_rss_kb(child);

    ChainSidecar sidecar;
    if (!wait_for_sidecar(sidecar_path, sidecar, error)) {
        return fail("failed to read sidecar: " + error);
    }
    const std::int64_t t0_ns =
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            t0.time_since_epoch())
            .count();
    if (sidecar.t0_ns != t0_ns ||
        sidecar.warmup_s != static_cast<double>(run.chain.warmup_seconds) ||
        sidecar.window_s != static_cast<double>(run.chain.seconds)) {
        char detail[256] = {};
        std::snprintf(detail, sizeof(detail),
                      "sidecar window disagrees with the parent: t0_ns=%lld/%lld "
                      "warmup=%.0f/%d "
                      "window=%.0f/%d",
                      static_cast<long long>(sidecar.t0_ns),
                      static_cast<long long>(t0_ns), sidecar.warmup_s,
                      run.chain.warmup_seconds, sidecar.window_s,
                      run.chain.seconds);
        return fail(detail);
    }

    bench::cli::stop_streams(streams);
    std::string shutdown_error;
    const bool clean_shutdown = server.shutdown(shutdown_error);
    const int child_code      = server.exit_code();

    std::vector<std::string> stream_failures;
    for (std::size_t index = 0; index < streams.size(); ++index) {
        const grpc::StatusCode code = streams[index]->code;
        if (code == grpc::StatusCode::OK || code == grpc::StatusCode::CANCELLED) {
            continue;
        }
        stream_failures.push_back("stream " + std::to_string(index) + ": " +
                                  bench::cli::status_code_name(code) + "(" +
                                  std::to_string(static_cast<int>(code)) + ") " +
                                  streams[index]->message);
    }

    const auto delta = [](std::uint64_t end, std::uint64_t start) {
        return end >= start ? end - start : 0;
    };
    const auto cpu_delta = [](double end, double start) {
        return end >= start ? end - start : 0.0;
    };

    std::uint64_t delivered    = 0;
    std::uint64_t stream_drops = 0;
    for (std::size_t index = 0; index < streams.size(); ++index) {
        delivered +=
            delta(counts_end[index].records, counts_start[index].records);
        stream_drops += delta(counts_end[index].drops, counts_start[index].drops);
    }
    const std::uint64_t cli_drops = delta(stats_end.dropped, stats_start.dropped);
    const std::uint64_t engine_dropped =
        stats_end.engine_valid && stats_start.engine_valid
            ? delta(stats_end.syscall_dropped, stats_start.syscall_dropped)
            : 0;
    const double client_cpu = cpu_delta(client_cpu_end, client_cpu_start);
    const double cli_tp_cpu = cpu_delta(cli_tp_end, cli_tp_start);

    const bench::chain::ChainSnapshot& snapshot = sidecar.snapshot;
    const double window =
        run.chain.seconds > 0 ? static_cast<double>(run.chain.seconds) : 1.0;
    const double total_cpu = snapshot.feeder_cpu + snapshot.semantic_cpu +
                             snapshot.engine_cpu + cli_tp_cpu;
    const double input_per_s = static_cast<double>(snapshot.consumed) / window;
    const double dispatched_per_s =
        static_cast<double>(snapshot.dispatched) / window;
    const double delivered_per_s = static_cast<double>(delivered) / window;
    const double fanout          = snapshot.dispatched > 0
                                       ? static_cast<double>(delivered) /
                                    static_cast<double>(snapshot.dispatched)
                                       : 0.0;
    const double fanout_deviation =
        run.streams > 0 ? fanout / static_cast<double>(run.streams) - 1.0 : 0.0;
    const std::size_t capacity           = queue_capacity(run.chain.queue);
    const std::uint64_t rss              = child_rss_kb;
    const std::string config             = cli_config(options, run);

    const std::vector<SegmentLoad> loads = {
        {"collector", snapshot.feeder_cpu / window},
        {"semantic", snapshot.semantic_cpu / window},
        {"engine", snapshot.engine_cpu / window},
        {"cli", cli_tp_cpu / window},
    };

    std::printf(
        "stage   : chain (cli backend: replay feeder → semantic → engine → CLI "
        "server → client)\n");
    std::printf("config  : %s\n", config.c_str());
    std::printf("trace   : %s\n", options.trace_path.c_str());
    std::printf(
        "window  : %.3fs warmup=%d rate=%g%s (child and parent align on the "
        "same T0)\n",
        window, options.warmup_seconds, options.rate,
        options.rate == 0.0 ? " (full speed)" : " (collector input records/s)");
    std::printf("input   : %.1f records/s consumed=%" PRIu64 "\n", input_per_s,
                snapshot.consumed);
    std::printf("dispatched: %.1f events/s dispatched=%" PRIu64 "\n",
                dispatched_per_s, snapshot.dispatched);
    std::printf("delivered: %.1f events/s delivered=%" PRIu64
                " (streams=%d, each input event fans out to all streams)\n",
                delivered_per_s, delivered, run.streams);
    std::printf(
        "fan-out : delivered/dispatched=%.3f expected=%d deviation=%+.2f%%\n",
        fanout, run.streams, fanout_deviation * 100.0);
    if (std::fabs(fanout_deviation) > kFanoutTolerance) {
        std::printf(
            "hint: delivered/dispatched deviates from streams by more than "
            "%.0f%%, which means filtering, loss, or events still in flight "
            "at the end of the window (dispatched by the server, not yet "
            "received by the client)\n",
            kFanoutTolerance * 100.0);
    }
    std::printf("events by class: syscall=%" PRIu64 " lifecycle=%" PRIu64
                " (feeder-side window counts)\n",
                snapshot.consumed - snapshot.consumed_lifecycle,
                snapshot.consumed_lifecycle);
    std::printf("segments (us/event, core utilization):\n");
    std::printf("  collector  consumed=%" PRIu64
                " us/event=%.3f cpu=%.3fs util=%.2f cores"
                " peak_queue=%" PRIu64 "\n",
                snapshot.consumed,
                us_per_event(snapshot.consumed, snapshot.feeder_cpu),
                snapshot.feeder_cpu, loads[0].cores, snapshot.raw_peak);
    std::printf("  semantic   processed=%" PRIu64
                " us/event=%.3f cpu=%.3fs util=%.2f cores"
                " drops=%" PRIu64 " peak_queue=%" PRIu64 "\n",
                snapshot.processed,
                us_per_event(snapshot.processed, snapshot.semantic_cpu),
                snapshot.semantic_cpu, loads[1].cores, snapshot.raw_drops,
                snapshot.sem_peak);
    std::printf("  engine     dispatched=%" PRIu64
                " us/event=%.3f cpu=%.3fs util=%.2f cores"
                " drops=%" PRIu64 " peak_queue=%" PRIu64 "\n",
                snapshot.dispatched,
                us_per_event(snapshot.dispatched, snapshot.engine_cpu),
                snapshot.engine_cpu, loads[2].cores, snapshot.sem_drops,
                snapshot.sem_peak);
    std::printf("  cli        delivered=%" PRIu64
                " us/event=%.3f cpu=%.3fs util=%.2f cores"
                " drops=%" PRIu64
                " peak_queue=0 (CLI queue occupancy is not observable)\n",
                delivered, us_per_event(delivered, cli_tp_cpu), cli_tp_cpu,
                loads[3].cores, cli_drops);
    std::printf("queues  : raw peak=%" PRIu64 "/%zu sem peak=%" PRIu64
                "/%zu cli_queue=%d system_sinks=%d unsettled=%" PRIu64 "\n",
                snapshot.raw_peak, capacity, snapshot.sem_peak, capacity,
                run.cli_queue, run.chain.system_sinks, snapshot.unsettled);
    std::printf("chain   : dispatched=%" PRIu64
                " events/s=%.1f us/event=%.3f"
                " drops=%" PRIu64 " cpu=%.3fs rss_kb=%" PRIu64 "\n",
                snapshot.dispatched, dispatched_per_s,
                us_per_event(snapshot.dispatched, total_cpu),
                snapshot.raw_drops + snapshot.sem_drops + cli_drops, total_cpu,
                rss);
    std::printf("bottleneck: %s\n",
                cli_bottleneck_text(snapshot, cli_drops, loads,
                                    client_cpu / window, loads[3].cores)
                    .c_str());
    std::printf(
        "collector=replay feeder (equivalent parsing); cli stage=server cli-tp "
        "thread; delivery is counted by the parent client\n");
    if (cli_drops > 0 && cli_tp_cpu > 0.0 && client_cpu >= cli_tp_cpu * 0.8) {
        std::printf(
            "hint: client CPU %.3fs is close to server cli-tp CPU %.3fs, so the "
            "benchmarker may become the bottleneck\n",
            client_cpu, cli_tp_cpu);
    }
    if (stream_drops != cli_drops) {
        std::printf("hint: streamstats drops %" PRIu64
                    " disagree with the GetPipelineStats cli delta %" PRIu64
                    " (the per-stream stats may not have arrived yet)\n",
                    stream_drops, cli_drops);
    }
    if (stats_end.engine_valid &&
        engine_dropped != snapshot.engine_syscall_dropped) {
        std::printf("hint: sidecar engine.syscall_dropped=%" PRIu64
                    " disagrees with the GetPipelineStats delta %" PRIu64
                    " (the sampling instants differ slightly)\n",
                    snapshot.engine_syscall_dropped, engine_dropped);
    }
    if (!clean_shutdown) {
        std::printf("hint: %s\n", shutdown_error.c_str());
    }
    if (child_code != 0) {
        std::printf("warning: server child process %s\n",
                    bench::cli::describe_exit(child_code).c_str());
    }
    if (!stream_failures.empty()) {
        std::fprintf(stderr,
                     "runtime failure: %zu streams did not end normally\n",
                     stream_failures.size());
        for (const std::string& failure : stream_failures) {
            std::fprintf(stderr, "  %s\n", failure.c_str());
        }
        return kExitRuntimeFailure;
    }

    const auto build_result =
        [&](const std::string& stage, std::uint64_t events, double cpu_seconds,
            std::uint64_t drops, std::uint64_t raw_drops, std::uint64_t out_drops,
            std::uint64_t peak_queue, std::uint64_t out_peak_queue) {
            bench::Result result;
            result.stage        = stage;
            result.config       = config;
            result.rate         = options.rate;
            result.seconds      = window;
            result.events       = events;
            result.events_per_s = events / window;
            result.us_per_event = us_per_event(events, cpu_seconds);
            result.producer_us_per_event =
                us_per_event(snapshot.consumed, snapshot.feeder_cpu);
            result.producer_us_per_success =
                us_per_event(snapshot.push_ok, snapshot.feeder_cpu);
            result.drops          = drops;
            result.raw_drops      = raw_drops;
            result.out_drops      = out_drops;
            result.rss_kb         = rss;
            result.peak_queue     = peak_queue;
            result.out_peak_queue = out_peak_queue;
            return result;
        };

    const std::vector<bench::Result> results = {
        build_result("chain", snapshot.dispatched, total_cpu,
                     snapshot.raw_drops + snapshot.sem_drops + cli_drops,
                     snapshot.raw_drops, snapshot.sem_drops + cli_drops,
                     snapshot.raw_peak, snapshot.sem_peak),
        build_result("chain/collector", snapshot.consumed, snapshot.feeder_cpu,
                     snapshot.raw_drops, snapshot.raw_drops, 0, snapshot.raw_peak,
                     0),
        build_result("chain/semantic", snapshot.processed, snapshot.semantic_cpu,
                     snapshot.raw_drops, snapshot.raw_drops, snapshot.sem_drops,
                     snapshot.raw_peak, snapshot.sem_peak),
        build_result("chain/engine", snapshot.dispatched, snapshot.engine_cpu,
                     snapshot.sem_drops, 0, snapshot.sem_drops, snapshot.sem_peak,
                     0),
        build_result("chain/cli", delivered, cli_tp_cpu, cli_drops, cli_drops, 0,
                     0, 0),
    };
    for (const bench::Result& result : results) {
        if (!bench::append_tsv(options.out_path, result)) {
            std::fprintf(
                stderr, "failed to write TSV: %s\n",
                options.out_path.empty() ? "stdout" : options.out_path.c_str());
            return kExitRuntimeFailure;
        }
    }

    return 0;
}

#endif  // HNG_BENCH_CLI_STAGE

/// @brief chain 段实现
int run_chain(const bench::CommonOptions& options,
              const std::vector<std::string>& rest)
{
    ChainRun run;
    run.chain.trace_path     = options.trace_path;
    run.chain.rate           = options.rate;
    run.chain.seconds        = options.seconds;
    run.chain.warmup_seconds = options.warmup_seconds;
    run.chain.queue          = options.queue;
    run.chain.fidelity       = options.fidelity;

    std::string error;
    if (!parse_rest(rest, run, error)) {
        std::fprintf(stderr, "parameter error: %s\n", error.c_str());
        std::fprintf(stderr, "chain stage options:\n%s", kExtraHelp);
        return kExitUsage;
    }

    if (run.backend == ChainBackend::SINK) {
        return run_sink(options, run);
    }
#ifdef HNG_BENCH_CLI_STAGE
    return run_cli_backend(options, run);
#else
    std::fprintf(stderr,
                 "parameter error: this build has no CLI server (userver), "
                 "--backend cli is unavailable\n");
    return kExitUsage;
#endif
}

bench::StageSpec make_chain_stage()
{
    bench::StageSpec stage;
    stage.name           = "chain";
    stage.extra_help     = kExtraHelp;
    stage.requires_trace = true;
    stage.supports_l2    = true;
    stage.run            = &run_chain;
    return stage;
}

}  // namespace

namespace bench {

const StageSpec& chain_stage()
{
    static const StageSpec stage = make_chain_stage();
    return stage;
}

}  // namespace bench
