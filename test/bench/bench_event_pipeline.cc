/**
 * @file bench_event_pipeline.cc
 * @brief 事件流水线压测入口
 * @details
 * 解析公共选项、按 --stage 选择压测段，并把未识别的参数原样交给该段。
 * 启动时打印机器指纹与关键参数，收尾由各 stage 打印结果并追加 TSV。
 */

#include "test/bench/stages.hpp"
#include "test/bench/support.hpp"

#include <cerrno>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace {

/// @brief 退出码：运行期失败
constexpr int kExitRuntimeFailure = 1;
/// @brief 退出码：参数错误
constexpr int kExitUsage          = 3;

/// @brief 可选的 stage 表；新增段时在此加一行
const std::vector<const bench::StageSpec*>& available_stages()
{
    static const std::vector<const bench::StageSpec*> stages = {
        &bench::semantic_stage(),
        &bench::engine_stage(),
        &bench::chain_stage(),
#ifdef HNG_BENCH_CLI_STAGE
        &bench::cli_stage(),
#endif
    };
    return stages;
}

/// @brief 按名字查 stage；找不到返回空
const bench::StageSpec* find_stage(const std::string& name)
{
    for (const bench::StageSpec* stage : available_stages()) {
        if (name == stage->name) {
            return stage;
        }
    }
    return nullptr;
}

/// @brief 打印公共选项与各 stage 聚合的私有选项
void print_usage(std::FILE* out)
{
    std::fprintf(
        out,
        "usage: bench_event_pipeline --stage NAME [options]\n"
        "\n"
        "common options:\n"
        "  --stage NAME       benchmark stage (required)\n"
        "  --fidelity l1|l2   control plane fidelity, default l1; engine and "
        "chain "
        "support l2 (see the cli stage for cli l2)\n"
        "  --trace PATH       trace file (required for semantic/engine/chain)\n"
        "  --seconds N        measurement window in seconds, >0 (default 10)\n"
        "  --warmup N         warmup seconds, >=0 (default 1)\n"
        "  --rate R           target rate in Hz, floating point, 0 means "
        "saturated (default 0)\n"
        "  --queue N          channel capacity, >=2 (default 8192)\n"
        "  --pin-consumer N   consumer side CPU index, -1 means no pinning "
        "(default -1)\n"
        "  --pin-producer N   producer side CPU index, -1 means no pinning "
        "(default -1)\n"
        "  --out PATH         file to append TSV to; empty writes to stdout\n"
        "  --quiet            do not print the machine fingerprint and startup "
        "parameters\n"
        "  --help             show this help\n"
        "\n"
        "per-stage private options:\n");
    for (const bench::StageSpec* stage : available_stages()) {
        std::fprintf(out, "\n[%s]\n%s", stage->name, stage->extra_help);
    }
    std::fprintf(
        out,
        "\nexit codes: 0 success; 1 runtime failure; 3 parameter error.\n"
        "TSV columns: stage config rate seconds events events_per_s us_per_event "
        "producer_us_per_event drops rss_kb peak_queue\n");
}

/// @brief 拆出 --name 或 --name=value；不是长选项时返回 false
bool split_option(const char* raw, std::string& name, std::string& value,
                  bool& has_value)
{
    if (raw[0] != '-' || raw[1] != '-') {
        return false;
    }
    const char* equals = std::strchr(raw, '=');
    if (equals == nullptr) {
        name = raw;
        value.clear();
        has_value = false;
        return true;
    }
    name.assign(raw, static_cast<std::size_t>(equals - raw));
    value.assign(equals + 1);
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

/// @brief 严格浮点解析
bool parse_rate(const std::string& text, double& value)
{
    if (text.empty()) {
        return false;
    }
    errno               = 0;
    char* end           = nullptr;
    const double parsed = std::strtod(text.c_str(), &end);
    if (errno != 0 || end == text.c_str() || *end != '\0' ||
        !std::isfinite(parsed) || parsed < 0.0) {
        return false;
    }
    value = parsed;
    return true;
}

/**
 * @brief 解析公共选项
 * @param[out] options 解析结果
 * @param[out] rest 未识别的参数，原样保序
 * @param[out] error 失败原因
 * @param[out] help 请求帮助
 * @return 解析成功时为 true；false 时 error 非空
 * @note 支持 --name value 与 --name=value 两种写法。
 */
bool parse_options(int argc, char** argv, bench::CommonOptions& options,
                   std::vector<std::string>& rest, std::string& error, bool& help)
{
    help = false;
    for (int index = 1; index < argc; ++index) {
        std::string name;
        std::string inline_value;
        bool has_inline = false;
        if (!split_option(argv[index], name, inline_value, has_inline)) {
            rest.push_back(argv[index]);
            continue;
        }

        const auto take_value = [&](std::string& out) -> bool {
            if (has_inline) {
                out = inline_value;
                return true;
            }
            if (index + 1 >= argc) {
                return false;
            }
            out = argv[++index];
            return true;
        };

        if (name == "--help") {
            if (has_inline) {
                error = "--help does not take a value";
                return false;
            }
            help = true;
            continue;
        }
        if (name == "--quiet") {
            if (has_inline) {
                error = "--quiet does not take a value";
                return false;
            }
            options.quiet = true;
            continue;
        }
        if (name == "--stage") {
            if (!take_value(options.stage) || options.stage.empty()) {
                error = "--stage is missing a name";
                return false;
            }
            continue;
        }
        if (name == "--fidelity") {
            std::string text;
            if (!take_value(text)) {
                error = "--fidelity is missing a value";
                return false;
            }
            if (text == "l1") {
                options.fidelity = bench::Fidelity::L1;
            }
            else if (text == "l2") {
                options.fidelity = bench::Fidelity::L2;
            }
            else {
                error = "--fidelity must be l1|l2";
                return false;
            }
            continue;
        }
        if (name == "--trace") {
            if (!take_value(options.trace_path) || options.trace_path.empty()) {
                error = "--trace is missing a path";
                return false;
            }
            continue;
        }
        if (name == "--out") {
            if (!take_value(options.out_path) || options.out_path.empty()) {
                error = "--out is missing a path";
                return false;
            }
            continue;
        }
        if (name == "--seconds") {
            std::string text;
            if (!take_value(text) ||
                !parse_integer(text, 1, 86400, options.seconds)) {
                error = "--seconds must be an integer in 1..86400";
                return false;
            }
            continue;
        }
        if (name == "--warmup") {
            std::string text;
            if (!take_value(text) ||
                !parse_integer(text, 0, 86400, options.warmup_seconds)) {
                error = "--warmup must be an integer in 0..86400";
                return false;
            }
            continue;
        }
        if (name == "--queue") {
            std::string text;
            if (!take_value(text) ||
                !parse_integer(text, 2, 1048576, options.queue)) {
                error = "--queue must be an integer in 2..1048576";
                return false;
            }
            continue;
        }
        if (name == "--pin-consumer" || name == "--pin-producer") {
            std::string text;
            int value = -1;
            if (!take_value(text) || !parse_integer(text, -1, 1048576, value)) {
                error =
                    std::string(name) + " must be -1 or a non-negative integer";
                return false;
            }
            if (name == "--pin-consumer") {
                options.pin_consumer = value;
            }
            else {
                options.pin_producer = value;
            }
            continue;
        }
        if (name == "--rate") {
            std::string text;
            if (!take_value(text) || !parse_rate(text, options.rate)) {
                error = "--rate must be a floating point number >= 0";
                return false;
            }
            continue;
        }

        // 未知参数原样交给 stage；只推入当前参数，后续 token 照常处理
        rest.push_back(argv[index]);
    }
    return true;
}

/// @brief 校验依赖运行环境的选项
bool validate_options(const bench::CommonOptions& options, std::string& error)
{
    const long cpus   = ::sysconf(_SC_NPROCESSORS_ONLN);
    const int online  = cpus > 0 ? static_cast<int>(cpus) : 1;
    const auto pin_ok = [online](int cpu) {
        return cpu == -1 || (cpu >= 0 && cpu < online);
    };
    if (!pin_ok(options.pin_consumer)) {
        error = "--pin-consumer is out of the online CPU range -1.." +
                std::to_string(online - 1);
        return false;
    }
    if (!pin_ok(options.pin_producer)) {
        error = "--pin-producer is out of the online CPU range -1.." +
                std::to_string(online - 1);
        return false;
    }
    return true;
}

}  // namespace

int main(int argc, char** argv)
{
    bench::CommonOptions options;
    std::vector<std::string> rest;
    std::string error;
    bool help = false;
    if (!parse_options(argc, argv, options, rest, error, help)) {
        std::fprintf(stderr, "parameter error: %s\n", error.c_str());
        std::fprintf(stderr, "use --help for usage\n");
        return kExitUsage;
    }
    if (help) {
        print_usage(stdout);
        return 0;
    }

    if (options.stage.empty()) {
        std::fprintf(stderr, "parameter error: missing --stage NAME\n");
        std::fprintf(stderr, "available stages:");
        for (const bench::StageSpec* stage : available_stages()) {
            std::fprintf(stderr, " %s", stage->name);
        }
        std::fprintf(stderr, "\n");
        return kExitUsage;
    }
    const bench::StageSpec* stage = find_stage(options.stage);
    if (stage == nullptr) {
        std::fprintf(stderr, "parameter error: unknown stage %s\n",
                     options.stage.c_str());
        std::fprintf(stderr, "available stages:");
        for (const bench::StageSpec* item : available_stages()) {
            std::fprintf(stderr, " %s", item->name);
        }
        std::fprintf(stderr, "\n");
        return kExitUsage;
    }
    if (options.fidelity == bench::Fidelity::L2 && !stage->supports_l2) {
        std::fprintf(stderr,
                     "parameter error: stage %s supports only --fidelity l1\n",
                     stage->name);
        return kExitUsage;
    }
    if (stage->requires_trace && options.trace_path.empty()) {
        std::fprintf(stderr, "parameter error: missing --trace PATH\n");
        return kExitUsage;
    }
    if (!validate_options(options, error)) {
        std::fprintf(stderr, "parameter error: %s\n", error.c_str());
        return kExitUsage;
    }

    if (!options.quiet) {
        std::fputs(bench::machine_fingerprint().c_str(), stdout);
        std::printf("stage    : %s\n", options.stage.c_str());
        std::printf("fidelity : %s\n", bench::fidelity_name(options.fidelity));
        if (!options.trace_path.empty()) {
            std::printf("trace    : %s\n", options.trace_path.c_str());
        }
        std::printf("seconds  : %d  warmup: %d\n", options.seconds,
                    options.warmup_seconds);
        std::printf("rate     : %g%s\n", options.rate,
                    options.rate == 0.0 ? " (saturated)" : "");
        std::printf("queue    : %d\n", options.queue);
        std::printf("pin      : consumer=%d producer=%d\n", options.pin_consumer,
                    options.pin_producer);
        if (!options.out_path.empty()) {
            std::printf("out      : %s\n", options.out_path.c_str());
        }
        std::printf("\n");
        // 组件日志直接写 fd，先冲刷 stdio 以保持指纹在日志之前
        std::fflush(stdout);
    }

    try {
        return stage->run(options, rest);
    }
    catch (const std::exception& failure) {
        std::fprintf(stderr, "runtime failure: %s\n", failure.what());
        return kExitRuntimeFailure;
    }
}
