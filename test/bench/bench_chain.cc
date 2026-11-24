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
#include <chrono>
#include <cinttypes>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <map>
#include <string>
#include <utility>
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
    "  --backend MODE    后端：cli|sink（默认：本构建有 CLI 服务端时为 cli，"
    "否则 sink）\n"
    "  --events MODE     回放类别：all|syscall|lifecycle（默认 all）；PROCESS "
    "与 EXEC 归为 lifecycle，种子始终用全量语料\n"
    "  --system-sinks K  计数系统订阅数，1..64，兼作引擎分发计数（默认 1）\n"
    "  --settled R       种子落定比例，0..1（默认 1）\n"
    "  --streams N       CLI 后端的并发订阅流数，1..1024（默认 1）\n"
    "  --batch N         CLI 后端单条响应的事件数上限，1..256（默认 64）\n"
    "  --cli-queue N     CLI 服务端每流队列容量，2..1048576（默认 8192）\n"
    "  --socket PATH     CLI 后端子进程的 Unix socket 绝对路径；空则 "
    "/tmp/hng-chain-cli-<pid>.sock\n"
    "  --filter MODE     订阅过滤器，v1 只支持 none；role/miss 尚未接入\n"
    "  sink 后端在一进程内跑 replay feeder → 语义 → 引擎，不含 CLI 与线缆；"
    "--backend sink 时拒绝 --streams/--batch/--filter/--cli-queue/--socket。\n"
#ifdef HNG_BENCH_CLI_STAGE
    "  cli 后端在子进程里跑同一条链加真实 RunCliServer；父进程先订阅、等服务"
    "端登记全部流后发 go，子进程收到 go 才取 T0 并启动回放，两端按同一个 T0 "
    "对齐窗口，--warmup 从 T0 起算。\n"
#else
    "  本构建未启用 CLI 服务端（userver），--backend cli 会报参数错误。\n"
#endif
    "  本段不使用 --pin-consumer 与 --pin-producer。\n";

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

        if (name == "--backend") {
            std::string text;
            if (!take_value(text)) {
                error = "--backend 缺少取值";
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
                    "本构建未启用 CLI 服务端（userver），--backend cli 不可用；"
                    "请用 --backend sink，或用 -DHNG_ENABLE_CLI_SERVER=ON "
                    "重新构建";
                return false;
#endif
            }
            else {
                error = "--backend 需为 cli|sink";
                return false;
            }
            run.backend_set = true;
            continue;
        }
        if (name == "--streams") {
            std::string text;
            if (!take_value(text) ||
                !parse_integer(text, 1, kMaxStreams, run.streams)) {
                error = "--streams 需为 1.." + std::to_string(kMaxStreams) +
                        " 的整数";
                return false;
            }
            run.streams_set = true;
            continue;
        }
        if (name == "--batch") {
            std::string text;
            if (!take_value(text) ||
                !parse_integer(text, 1, kMaxBatch, run.batch)) {
                error =
                    "--batch 需为 1.." + std::to_string(kMaxBatch) + " 的整数";
                return false;
            }
            run.batch_set = true;
            continue;
        }
        if (name == "--cli-queue") {
            std::string text;
            if (!take_value(text) ||
                !parse_integer(text, kCliQueueMin, kCliQueueMax, run.cli_queue)) {
                error = "--cli-queue 需为 " + std::to_string(kCliQueueMin) +
                        ".." + std::to_string(kCliQueueMax) + " 的整数";
                return false;
            }
            run.cli_queue_set = true;
            continue;
        }
        if (name == "--socket") {
            if (!take_value(run.socket_path) || run.socket_path.empty() ||
                run.socket_path.front() != '/') {
                error = "--socket 需为绝对路径";
                return false;
            }
            run.socket_set = true;
            continue;
        }
        if (name == "--filter") {
            std::string text;
            if (!take_value(text)) {
                error = "--filter 缺少取值";
                return false;
            }
            if (text != "none") {
                error =
                    "--filter 在 v1 只支持 none；role/miss 会改变交付比例，"
                    "尚未接入 chain 后端";
                return false;
            }
            run.filter_set = true;
            continue;
        }
        if (name == "--events") {
            std::string text;
            if (!take_value(text)) {
                error = "--events 缺少取值";
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
                error = "--events 需为 all|syscall|lifecycle";
                return false;
            }
            continue;
        }
        if (name == "--system-sinks") {
            std::string text;
            if (!take_value(text) ||
                !parse_integer(text, 1, 64, run.chain.system_sinks)) {
                error = "--system-sinks 需为 1..64 的整数";
                return false;
            }
            continue;
        }
        if (name == "--settled") {
            std::string text;
            if (!take_value(text) || !parse_fraction(text, run.chain.settled)) {
                error = "--settled 需为 0..1 的浮点数";
                return false;
            }
            continue;
        }
        error = "未知选项 " + name;
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
            error = "--backend sink 只跑进程内整链，不接受 CLI 后端选项：" + used;
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
 * @return 一行结论文本
 * @note 归因规则：原始通道拒收指向语义段慢，语义通道拒收指向引擎段慢，无拒收
 *       则报未饱和并给出 CPU 利用率最高的一段；当被指向段的 CPU 明显低于最紧
 *       的一段时，标「未定」并同时给出两侧证据。
 */
std::string sink_bottleneck_text(const bench::chain::ChainSnapshot& snapshot)
{
    const std::vector<SegmentLoad> loads = sink_segment_loads(snapshot);
    const SegmentLoad& tightest          = tightest_segment(loads);
    const bool semantic_slow             = snapshot.raw_drops > 0;
    const bool engine_slow               = snapshot.sem_drops > 0;
    char text[512]                       = {};

    if (!semantic_slow && !engine_slow) {
        std::snprintf(text, sizeof(text),
                      "未饱和（无丢）；最紧的一段=%s（CPU 利用率 %.2f 核）",
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
            "%s语义与引擎均慢：raw 通道拒收 %" PRIu64
            " 次（语义消费不及回放），语义通道拒收 %" PRIu64
            " 次（引擎消费不及语义）；CPU：semantic %.2f 核、engine %.2f 核",
            conflict ? "未定：" : "", snapshot.raw_drops, snapshot.sem_drops,
            loads[1].cores, loads[2].cores);
    }
    else if (semantic_slow) {
        std::snprintf(text, sizeof(text),
                      "%s语义段慢：raw 通道拒收 %" PRIu64
                      " 次（语义消费不及回放）；CPU 证据：semantic %.2f 核",
                      conflict ? "未定：" : "", snapshot.raw_drops,
                      loads[1].cores);
    }
    else {
        std::snprintf(text, sizeof(text),
                      "%s引擎段慢：语义通道拒收 %" PRIu64
                      " 次（引擎消费不及语义）；CPU 证据：engine %.2f 核",
                      conflict ? "未定：" : "", snapshot.sem_drops,
                      loads[2].cores);
    }

    std::string conclusion = text;
    if (conflict) {
        char evidence[256] = {};
        std::snprintf(evidence, sizeof(evidence),
                      "；CPU 最紧的一段=%s（%.2f 核），与丢包归因冲突，判为未定",
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

    const std::vector<SegmentLoad> loads = sink_segment_loads(snapshot);
    const double total_cpu =
        snapshot.feeder_cpu + snapshot.semantic_cpu + snapshot.engine_cpu;
    const std::uint64_t rss = bench::rss_kb();

    std::printf("stage   : chain（sink 后端：replay feeder → 语义 → 引擎）\n");
    std::printf("config  : %s\n", config.c_str());
    std::printf("trace   : %s\n", options.trace_path.c_str());
    std::printf("corpus  : records=%" PRIu64 " playback=%" PRIu64
                " malformed=%" PRIu64 "\n",
                snapshot.records, snapshot.playback, snapshot.malformed);
    std::printf("window  : %.3fs warmup=%d rate=%g%s\n", snapshot.seconds,
                options.warmup_seconds, options.rate,
                options.rate == 0.0 ? "（全速）" : "（collector 输入记录/s）");
    std::printf("input   : %.1f 记录/s consumed=%" PRIu64 "\n", input_per_s,
                snapshot.consumed);
    std::printf("events by class: syscall=%" PRIu64 " lifecycle=%" PRIu64
                "（feeder 侧窗口计数）\n",
                snapshot.consumed - snapshot.consumed_lifecycle,
                snapshot.consumed_lifecycle);
    std::printf("segments（us/事件, 核利用率）:\n");
    std::printf("  collector  consumed=%" PRIu64
                " us/event=%.3f cpu=%.3fs util=%.2f 核"
                " peak_queue=%" PRIu64 "\n",
                snapshot.consumed,
                us_per_event(snapshot.consumed, snapshot.feeder_cpu),
                snapshot.feeder_cpu, loads[0].cores, snapshot.raw_peak);
    std::printf("  semantic   processed=%" PRIu64
                " us/event=%.3f cpu=%.3fs util=%.2f 核"
                " drops=%" PRIu64 " peak_queue=%" PRIu64 "\n",
                snapshot.processed,
                us_per_event(snapshot.processed, snapshot.semantic_cpu),
                snapshot.semantic_cpu, loads[1].cores, snapshot.raw_drops,
                snapshot.sem_peak);
    std::printf("  engine     dispatched=%" PRIu64
                " us/event=%.3f cpu=%.3fs util=%.2f 核"
                " drops=%" PRIu64 " peak_queue=%" PRIu64 "\n",
                snapshot.dispatched,
                us_per_event(snapshot.dispatched, snapshot.engine_cpu),
                snapshot.engine_cpu, loads[2].cores, snapshot.sem_drops,
                snapshot.sem_peak);
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
    std::printf("bottleneck: %s\n", sink_bottleneck_text(snapshot).c_str());
    std::printf("collector=replay feeder（等价解析）；未含 CLI/线缆\n");
    std::printf(
        "对照提示：与单段 semantic 比较时，注意其取空线程为零积压口径（下界）\n");

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
                stderr, "写 TSV 失败：%s\n",
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
            error = "子进程在写 T0 文件前退出（" +
                    bench::cli::describe_exit(code) + "）";
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
            error = "等待 T0 文件 " + path + " 超时（20s）或内容非法";
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
            error = "等待 go 文件 " + path + " 超时（20s）";
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    error = "收到停止信号，未等到 go 文件";
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
        error = "无法打开 " + path;
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
            error = "侧车行缺少 '='：" + line;
            return false;
        }
        fields[line.substr(0, equals)] = line.substr(equals + 1);
    }
    if (file.bad()) {
        error = "读取侧车失败：" + path;
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
        error = "侧车缺少键：" + missing;
        return false;
    }
    if (!invalid.empty()) {
        error = "侧车取值非法：" + invalid;
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
            error = "等待侧车 " + path + " 超时（2s）";
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
        std::fprintf(stderr, "chain 控制线程：%s\n", error.c_str());
        failed.store(true, std::memory_order_release);
        ::_exit(kExitRuntimeFailure);
    }

    const bench::Clock::time_point t0 = bench::Clock::now();
    if (!runtime.start_feeder(error)) {
        std::fprintf(stderr, "chain 控制线程：启动回放线程失败：%s\n",
                     error.c_str());
        failed.store(true, std::memory_order_release);
        ::_exit(kExitRuntimeFailure);
    }
    const std::int64_t t0_ns =
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            t0.time_since_epoch())
            .count();
    if (!write_text_file(t0_path, "t0_ns=" + std::to_string(t0_ns) + "\n")) {
        std::fprintf(stderr, "chain 控制线程：写 T0 文件 %s 失败\n",
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
        std::fprintf(stderr, "chain 控制线程：窗口起点快照失败：%s\n",
                     error.c_str());
        failed.store(true, std::memory_order_release);
        return;
    }
    if (!sleep_until_or_stop(end_time, stop)) {
        return;
    }
    bench::chain::ChainSnapshot end;
    if (!runtime.snapshot(end, error)) {
        std::fprintf(stderr, "chain 控制线程：窗口终点快照失败：%s\n",
                     error.c_str());
        failed.store(true, std::memory_order_release);
        return;
    }

    const bench::chain::ChainSnapshot window =
        bench::chain::window_delta(begin, end);
    if (!write_sidecar(sidecar_path, t0_ns, chain_options, window)) {
        std::fprintf(stderr, "chain 控制线程：写侧车 %s 失败\n",
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
                std::fprintf(stderr, "chain 子进程启动失败：%s\n", error.c_str());
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
                             "chain 子进程控制线程失败（go/T0/侧车见 stderr）\n");
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
            "cli 接缝慢：cli 队列拒收 %" PRIu64
            " 次（客户端取用不及服务端交付）；CPU 证据：cli-tp %.2f 核、"
            "client %.2f 核",
            cli_drops, cli_cores, client_cores);
        return text;
    }
    if (snapshot.sem_drops > 0) {
        std::snprintf(text, sizeof(text),
                      "引擎段慢：语义通道拒收 %" PRIu64
                      " 次（引擎消费不及语义）；CPU 证据：engine %.2f 核",
                      snapshot.sem_drops, loads[2].cores);
        return text;
    }
    if (snapshot.raw_drops > 0) {
        std::snprintf(text, sizeof(text),
                      "语义段慢：raw 通道拒收 %" PRIu64
                      " 次（语义消费不及回放）；CPU 证据：semantic %.2f 核",
                      snapshot.raw_drops, loads[1].cores);
        return text;
    }
    std::snprintf(text, sizeof(text),
                  "未饱和（无丢）；最紧的一段=%s（CPU 利用率 %.2f 核）",
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
    error = "服务端在 5s 内未登记全部订阅流（active=" +
            std::to_string(snapshot.active) + "/" + std::to_string(streams) +
            (last_error.empty() ? "" : "：" + last_error) + "）";
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
        std::fprintf(stderr, "运行期失败：%s\n", message.c_str());
        return kExitRuntimeFailure;
    };

    std::string error;
    if (!bench::cli::wait_for_server(stub, server, socket_path, error)) {
        int code = 0;
        if (!server.alive(code) &&
            error.find("服务端子进程在就绪前退出") == std::string::npos) {
            return fail("服务端子进程在就绪前退出（" +
                        bench::cli::describe_exit(code) + "）：" + error);
        }
        return fail(error);
    }

    // 先订阅并等服务端登记全部流，再发 go：T0 时客户端已就绪，1s 预热里
    // 不再含建流瞬态，窗口起点也不会带着已积压的每流队列
    const std::vector<std::uint32_t> role_ids;
    bench::cli::start_streams(stub, streams,
                              static_cast<std::uint32_t>(run.batch), role_ids);
    if (!bench::cli::wait_stream_tids(streams)) {
        return fail("等待客户端流线程发布 tid 超时");
    }
    bench::cli::PipelineStatsSnapshot ready_stats;
    if (!wait_for_active_streams(stub, run.streams, ready_stats, error)) {
        return fail(error);
    }
    const bench::Clock::time_point subscribed_at = bench::Clock::now();

    // 握手：服务端就绪且全部订阅流已登记后，子进程才取 T0 并启动回放
    errno                                        = 0;
    if (!write_go_file(go_path)) {
        const std::string reason = errno != 0 ? std::strerror(errno) : "未知原因";
        return fail("写 go 文件 " + go_path + " 失败：" + reason);
    }

    bench::Clock::time_point t0;
    if (!read_t0_file(t0_path, server, t0, error)) {
        return fail("读取子进程 T0 失败：" + error);
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
                      "订阅完成时刻比窗口起点晚 %.3fs（warmup=%d 秒），窗口"
                      "无法对齐；请增大 --warmup（建议 >= %d）",
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
        return fail("窗口起点 GetPipelineStats 失败：" + error);
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
        return fail("窗口终点 GetPipelineStats 失败：" + error);
    }
    const std::uint64_t child_rss_kb = read_process_rss_kb(child);

    ChainSidecar sidecar;
    if (!wait_for_sidecar(sidecar_path, sidecar, error)) {
        return fail("读取侧车失败：" + error);
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
                      "侧车窗口与父进程不一致：t0_ns=%lld/%lld warmup=%.0f/%d "
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
        stream_failures.push_back("流 " + std::to_string(index) + "：" +
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
        "stage   : chain（cli 后端：replay feeder → 语义 → 引擎 → CLI 服务端"
        " → 客户端）\n");
    std::printf("config  : %s\n", config.c_str());
    std::printf("trace   : %s\n", options.trace_path.c_str());
    std::printf(
        "window  : %.3fs warmup=%d rate=%g%s（子进程与父进程按同一 T0 "
        "对齐）\n",
        window, options.warmup_seconds, options.rate,
        options.rate == 0.0 ? "（全速）" : "（collector 输入记录/s）");
    std::printf("input   : %.1f 记录/s consumed=%" PRIu64 "\n", input_per_s,
                snapshot.consumed);
    std::printf("dispatched: %.1f 事件/s dispatched=%" PRIu64 "\n",
                dispatched_per_s, snapshot.dispatched);
    std::printf("delivered: %.1f 事件/s delivered=%" PRIu64
                "（streams=%d，每输入事件扇出到全部流）\n",
                delivered_per_s, delivered, run.streams);
    std::printf("fan-out : delivered/dispatched=%.3f 期望=%d 偏差=%+.2f%%\n",
                fanout, run.streams, fanout_deviation * 100.0);
    if (std::fabs(fanout_deviation) > kFanoutTolerance) {
        std::printf(
            "提示：delivered/dispatched 与 streams 偏差超过 %.0f%%，说明有过滤、"
            "丢失，或窗口末仍有在途事件（服务端已分发、客户端未收到）\n",
            kFanoutTolerance * 100.0);
    }
    std::printf("events by class: syscall=%" PRIu64 " lifecycle=%" PRIu64
                "（feeder 侧窗口计数）\n",
                snapshot.consumed - snapshot.consumed_lifecycle,
                snapshot.consumed_lifecycle);
    std::printf("segments（us/事件, 核利用率）:\n");
    std::printf("  collector  consumed=%" PRIu64
                " us/event=%.3f cpu=%.3fs util=%.2f 核"
                " peak_queue=%" PRIu64 "\n",
                snapshot.consumed,
                us_per_event(snapshot.consumed, snapshot.feeder_cpu),
                snapshot.feeder_cpu, loads[0].cores, snapshot.raw_peak);
    std::printf("  semantic   processed=%" PRIu64
                " us/event=%.3f cpu=%.3fs util=%.2f 核"
                " drops=%" PRIu64 " peak_queue=%" PRIu64 "\n",
                snapshot.processed,
                us_per_event(snapshot.processed, snapshot.semantic_cpu),
                snapshot.semantic_cpu, loads[1].cores, snapshot.raw_drops,
                snapshot.sem_peak);
    std::printf("  engine     dispatched=%" PRIu64
                " us/event=%.3f cpu=%.3fs util=%.2f 核"
                " drops=%" PRIu64 " peak_queue=%" PRIu64 "\n",
                snapshot.dispatched,
                us_per_event(snapshot.dispatched, snapshot.engine_cpu),
                snapshot.engine_cpu, loads[2].cores, snapshot.sem_drops,
                snapshot.sem_peak);
    std::printf("  cli        delivered=%" PRIu64
                " us/event=%.3f cpu=%.3fs util=%.2f 核"
                " drops=%" PRIu64 " peak_queue=0（CLI 队列占用不可观测）\n",
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
        "collector=replay feeder（等价解析）；cli 段=服务端 cli-tp 线程，"
        "交付数由父进程客户端统计\n");
    if (cli_drops > 0 && cli_tp_cpu > 0.0 && client_cpu >= cli_tp_cpu * 0.8) {
        std::printf(
            "提示：客户端 CPU %.3fs 已接近服务端 cli-tp CPU %.3fs，"
            "压测器可能成为瓶颈\n",
            client_cpu, cli_tp_cpu);
    }
    if (stream_drops != cli_drops) {
        std::printf("提示：streamstats 的丢弃 %" PRIu64
                    " 与 GetPipelineStats 的 cli 增量 %" PRIu64
                    " 不一致（流上的 stats 可能尚未送达）\n",
                    stream_drops, cli_drops);
    }
    if (stats_end.engine_valid &&
        engine_dropped != snapshot.engine_syscall_dropped) {
        std::printf("提示：侧车 engine.syscall_dropped=%" PRIu64
                    " 与 GetPipelineStats 的增量 %" PRIu64
                    " 不一致（采样时刻略有先后）\n",
                    snapshot.engine_syscall_dropped, engine_dropped);
    }
    if (!clean_shutdown) {
        std::printf("提示：%s\n", shutdown_error.c_str());
    }
    if (child_code != 0) {
        std::printf("警告：服务端子进程%s\n",
                    bench::cli::describe_exit(child_code).c_str());
    }
    if (!stream_failures.empty()) {
        std::fprintf(stderr, "运行期失败：%zu 条流未正常结束\n",
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
                stderr, "写 TSV 失败：%s\n",
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

    std::string error;
    if (!parse_rest(rest, run, error)) {
        std::fprintf(stderr, "参数错误：%s\n", error.c_str());
        std::fprintf(stderr, "chain 段选项：\n%s", kExtraHelp);
        return kExitUsage;
    }

    if (run.backend == ChainBackend::SINK) {
        return run_sink(options, run);
    }
#ifdef HNG_BENCH_CLI_STAGE
    return run_cli_backend(options, run);
#else
    std::fprintf(stderr,
                 "参数错误：本构建未启用 CLI 服务端（userver），"
                 "--backend cli 不可用\n");
    return kExitUsage;
#endif
}

bench::StageSpec make_chain_stage()
{
    bench::StageSpec stage;
    stage.name           = "chain";
    stage.extra_help     = kExtraHelp;
    stage.requires_trace = true;
    stage.supports_l2    = false;
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
