/**
 * @file bench_chain.cc
 * @brief chain 段压测：replay feeder → 语义 → 运行时引擎（sink 后端）
 * @details
 * 本段把采集、语义与引擎串成一条链，测量一次输入事件走完整条链的窗口成本。
 * 生产侧没有真实采集器，用与采集器等价解析的语料回放（见 chain_feeder.hpp）；
 * 消费侧是真实语义组件、真实引擎与 L1 控制面替身（见 chain_core.hpp）。
 * 一次运行写 4 行 TSV：合并行 chain 与 collector/semantic/engine 三段各自的行；
 * 人类输出给出各段 us/事件、核占用、队列峰值与瓶颈结论。
 * CLI 后端（--streams/--batch/--filter/--socket）留到下一步，本步拒绝这些选项。
 */

#include "test/bench/chain_core.hpp"
#include "test/bench/stages.hpp"

#include <cerrno>
#include <chrono>
#include <cinttypes>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

namespace {

/// @brief 退出码：运行期失败
constexpr int kExitRuntimeFailure = 1;
/// @brief 退出码：参数错误
constexpr int kExitUsage          = 3;

/// @brief 判定「CPU 证据与丢包归因冲突」的核数余量
constexpr double kConflictCores   = 0.10;

/// @brief chain 段私有选项的多行用法
constexpr const char* kExtraHelp =
    "  --events MODE     回放类别：all|syscall|lifecycle（默认 all）；PROCESS "
    "与 EXEC 归为 lifecycle，种子始终用全量语料\n"
    "  --system-sinks K  计数系统订阅数，1..64，兼作引擎分发计数（默认 1）\n"
    "  --settled R       种子落定比例，0..1（默认 1）\n"
    "  本段只跑 sink 后端（replay feeder → 语义 → 引擎），不含 CLI 与线缆；"
    "--streams/--batch/--filter/--socket 属于 CLI 后端，将在下一步接入。\n"
    "  本段不使用 --pin-consumer 与 --pin-producer。\n";

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
 * @param[out] options 语料之外的回放参数
 * @param[out] error 失败原因
 * @return 解析成功时为 true
 * @note 支持 --name value 与 --name=value 两种写法。CLI 后端的选项在此显式
 *       拒绝并说明归属，其余未知选项按参数错误处理。
 */
bool parse_rest(const std::vector<std::string>& rest,
                bench::chain::ChainOptions& options, std::string& error)
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

        if (name == "--streams" || name == "--batch" || name == "--filter" ||
            name == "--socket") {
            error = name +
                    " 属于 CLI 后端，将在下一步接入；本步只跑 sink 后端"
                    "（replay feeder → 语义 → 引擎）";
            return false;
        }
        if (name == "--events") {
            std::string text;
            if (!take_value(text)) {
                error = "--events 缺少取值";
                return false;
            }
            if (text == "all") {
                options.events = bench::chain::EventClass::ALL;
            }
            else if (text == "syscall") {
                options.events = bench::chain::EventClass::SYSCALL;
            }
            else if (text == "lifecycle") {
                options.events = bench::chain::EventClass::LIFECYCLE;
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
                !parse_integer(text, 1, 64, options.system_sinks)) {
                error = "--system-sinks 需为 1..64 的整数";
                return false;
            }
            continue;
        }
        if (name == "--settled") {
            std::string text;
            if (!take_value(text) || !parse_fraction(text, options.settled)) {
                error = "--settled 需为 0..1 的浮点数";
                return false;
            }
            continue;
        }
        error = "未知选项 " + name;
        return false;
    }
    return true;
}

/// @brief 一段的 CPU 利用率，占满一核为 1
struct SegmentLoad {
    const char* name;  ///< 段名
    double cores;      ///< 窗口 CPU / 窗口秒数
};

/// @brief 三段的 CPU 利用率，按 collector、semantic、engine 排列
std::vector<SegmentLoad> segment_loads(
    const bench::chain::ChainSnapshot& snapshot)
{
    const double seconds = snapshot.seconds > 0.0 ? snapshot.seconds : 1.0;
    std::vector<SegmentLoad> loads;
    loads.push_back({"collector", snapshot.feeder_cpu / seconds});
    loads.push_back({"semantic", snapshot.semantic_cpu / seconds});
    loads.push_back({"engine", snapshot.engine_cpu / seconds});
    return loads;
}

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

/**
 * @brief 瓶颈结论
 * @param[in] snapshot 窗口结果
 * @return 一行结论文本
 * @note 归因规则：原始通道拒收指向语义段慢，语义通道拒收指向引擎段慢，无拒收
 *       则报未饱和并给出 CPU 利用率最高的一段；当被指向段的 CPU 明显低于最紧
 *       的一段时，标「未定」并同时给出两侧证据。
 */
std::string bottleneck_text(const bench::chain::ChainSnapshot& snapshot)
{
    const std::vector<SegmentLoad> loads = segment_loads(snapshot);
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

/// @brief 一段事件的 CPU 微秒
double us_per_event(std::uint64_t events, double cpu_seconds)
{
    return events > 0 ? cpu_seconds * 1e6 / static_cast<double>(events) : 0.0;
}

/// @brief chain 段实现
int run_chain(const bench::CommonOptions& options,
              const std::vector<std::string>& rest)
{
    bench::chain::ChainOptions chain_options;
    chain_options.trace_path     = options.trace_path;
    chain_options.rate           = options.rate;
    chain_options.seconds        = options.seconds;
    chain_options.warmup_seconds = options.warmup_seconds;
    chain_options.queue          = options.queue;

    std::string error;
    if (!parse_rest(rest, chain_options, error)) {
        std::fprintf(stderr, "参数错误：%s\n", error.c_str());
        std::fprintf(stderr, "chain 段选项：\n%s", kExtraHelp);
        return kExitUsage;
    }

    bench::chain::ChainSnapshot snapshot;
    if (!bench::chain::run_chain_sink(chain_options, snapshot, error)) {
        std::fprintf(stderr, "%s\n", error.c_str());
        return kExitRuntimeFailure;
    }

    const double window        = snapshot.seconds > 0.0 ? snapshot.seconds : 1.0;
    const double input_per_s   = static_cast<double>(snapshot.consumed) / window;
    const std::size_t capacity = [&options] {
        std::size_t value = 1;
        while (value < static_cast<std::size_t>(options.queue)) {
            value <<= 1;
        }
        return value;
    }();

    char settled_text[32] = {};
    std::snprintf(settled_text, sizeof(settled_text), "%g",
                  chain_options.settled);
    const std::string config =
        std::string("fidelity=") + bench::fidelity_name(options.fidelity) +
        ",events=" + bench::chain::event_class_name(chain_options.events) +
        ",queue=" + std::to_string(chain_options.queue) +
        ",system=" + std::to_string(chain_options.system_sinks) +
        ",settled=" + settled_text + ",backend=sink";

    const std::vector<SegmentLoad> loads = segment_loads(snapshot);
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
                chain_options.system_sinks, snapshot.unsettled);
    std::printf(
        "chain   : dispatched=%" PRIu64
        " events/s=%.1f us/event=%.3f"
        " drops=%" PRIu64 " cpu=%.3fs rss_kb=%" PRIu64 "\n",
        snapshot.dispatched,
        window > 0.0 ? static_cast<double>(snapshot.dispatched) / window : 0.0,
        us_per_event(snapshot.dispatched, total_cpu),
        snapshot.raw_drops + snapshot.sem_drops, total_cpu, rss);
    std::printf("bottleneck: %s\n", bottleneck_text(snapshot).c_str());
    std::printf("collector=replay feeder（等价解析）；未含 CLI/线缆\n");

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
