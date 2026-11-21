/**
 * @file support.hpp
 * @brief 事件流水线压测的公共测量件
 * @details
 * 供 test/bench 下的压测入口与各 stage 共用：线程 CPU 计时、绝对时刻节拍、
 * 绑核、RSS、机器指纹、通道占用采样与结果格式化。全部 header-only，不引入
 * spdlog 等运行时依赖，可在无 root 的容器里直接使用。
 */

#ifndef HNG_TEST_BENCH_SUPPORT_HPP_
#define HNG_TEST_BENCH_SUPPORT_HPP_

#include <sched.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <chrono>
#include <cinttypes>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <functional>
#include <string>
#include <thread>
#include <utility>

namespace bench {

/// @brief 压测统一使用的单调时钟
using Clock = std::chrono::steady_clock;

/**
 * @brief 读取指定线程的累计 CPU 时间
 * @param[in] tid 线程号（gettid 的返回值）
 * @param[out] seconds 用户态与内核态 CPU 时间之和，单位秒
 * @param[out] error 失败原因
 * @return 成功时为 true
 * @note 读 /proc/self/task/<tid>/stat，取 state 之后的第 11/12 个数值字段
 *       （utime/stime）；线程不存在或字段不足时返回 false，不静默归零。
 */
inline bool read_thread_cpu(std::uint64_t tid, double& seconds,
                            std::string& error);

inline bool read_thread_cpu(std::uint64_t tid, double& seconds,
                            std::string& error)
{
    seconds                = 0.0;
    const std::string path = "/proc/self/task/" + std::to_string(tid) + "/stat";
    std::ifstream stat(path);
    if (!stat.is_open()) {
        error = "无法打开 " + path;
        return false;
    }
    std::string content;
    if (!std::getline(stat, content)) {
        error = "读取 " + path + " 失败";
        return false;
    }
    const std::size_t comm_end = content.rfind(')');
    if (comm_end == std::string::npos) {
        error = path + " 缺少 comm 结束符";
        return false;
    }

    const char* cursor = content.c_str() + comm_end + 1;
    while (*cursor == ' ') {
        ++cursor;
    }
    if (*cursor == '\0') {
        error = path + " 缺少 state 字段";
        return false;
    }
    ++cursor;  // 跳过 state 单字符

    std::uint64_t utime = 0;
    std::uint64_t stime = 0;
    bool got_utime      = false;
    bool got_stime      = false;
    for (int field = 1; field <= 12; ++field) {
        while (*cursor == ' ') {
            ++cursor;
        }
        if (*cursor == '\0') {
            break;
        }
        errno                          = 0;
        char* end                      = nullptr;
        const unsigned long long value = std::strtoull(cursor, &end, 10);
        if (end == cursor || errno != 0) {
            error = path + " 的第 " + std::to_string(field) + " 个数值字段非法";
            return false;
        }
        if (field == 11) {
            utime     = value;
            got_utime = true;
        }
        else if (field == 12) {
            stime     = value;
            got_stime = true;
        }
        cursor = end;
    }
    if (!got_utime || !got_stime) {
        error = path + " 字段不足，无法取 utime/stime";
        return false;
    }

    const long ticks = ::sysconf(_SC_CLK_TCK);
    if (ticks <= 0) {
        error = "无法获取 _SC_CLK_TCK";
        return false;
    }
    seconds = static_cast<double>(utime + stime) / static_cast<double>(ticks);
    error.clear();
    return true;
}

/**
 * @brief 绝对时刻节拍器
 * @details 第 index 拍的时刻为构造点加 index / rate_hz 秒；已经落后于该时刻
 *          时不补拍，直接返回 false 并累计一次 overrun。
 * @note 只应由一条线程调用 wait()；overruns() 可在该线程结束后读取。
 */
class Pacer {
   public:
    /// @param[in] rate_hz 目标频率，必须为正
    explicit Pacer(double rate_hz);

    /**
     * @brief 等到第 index 拍
     * @param[in] index 从 0 开始的拍序号
     * @return 未落后为 true；已落后（未睡眠）为 false
     */
    bool wait(std::uint64_t index);

    /// @brief 累计落后拍数
    std::uint64_t overruns() const;

   private:
    double rate_hz_;
    Clock::time_point start_;
    std::uint64_t overruns_ = 0;
};

inline Pacer::Pacer(double rate_hz) : rate_hz_(rate_hz), start_(Clock::now()) {}

inline bool Pacer::wait(std::uint64_t index)
{
    if (rate_hz_ <= 0.0) {
        return true;
    }
    const auto offset = std::chrono::duration_cast<Clock::duration>(
        std::chrono::duration<double>(static_cast<double>(index) / rate_hz_));
    const Clock::time_point target = start_ + offset;
    const Clock::time_point now    = Clock::now();
    if (now >= target) {
        ++overruns_;
        return false;
    }
    std::this_thread::sleep_until(target);
    return true;
}

inline std::uint64_t Pacer::overruns() const { return overruns_; }

/**
 * @brief 把当前线程绑定到单个 CPU
 * @param[in] cpu 目标 CPU 序号
 * @param[out] error 失败原因
 * @return 成功时为 true
 */
inline bool pin_this_thread(int cpu, std::string& error);

inline bool pin_this_thread(int cpu, std::string& error)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    if (::sched_setaffinity(0, sizeof(set), &set) != 0) {
        error = "sched_setaffinity(cpu=" + std::to_string(cpu) + ") 失败：" +
                std::strerror(errno);
        return false;
    }
    error.clear();
    return true;
}

/// @brief 当前进程的常驻内存，单位 KiB；读取失败返回 0
inline std::uint64_t rss_kb()
{
    std::ifstream status("/proc/self/status");
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

namespace detail {

/// @brief /proc/cpuinfo 的 model name；读不到返回空串
inline std::string cpu_model_name()
{
    std::ifstream info("/proc/cpuinfo");
    std::string line;
    while (std::getline(info, line)) {
        const std::size_t colon = line.find(':');
        if (colon == std::string::npos) {
            continue;
        }
        if (line.compare(0, colon, "model name") != 0) {
            continue;
        }
        std::string model       = line.substr(colon + 1);
        const std::size_t first = model.find_first_not_of(" \t");
        if (first == std::string::npos) {
            return std::string();
        }
        model.erase(0, first);
        const std::size_t last = model.find_last_not_of(" \t");
        model.erase(last + 1);
        return model;
    }
    return std::string();
}

/// @brief /proc/meminfo 的 MemTotal；读不到返回 0
inline std::uint64_t mem_total_kib()
{
    std::ifstream info("/proc/meminfo");
    std::string line;
    while (std::getline(info, line)) {
        if (line.compare(0, 9, "MemTotal:") != 0) {
            continue;
        }
        const char* text = line.c_str() + 9;
        while (*text == ' ' || *text == '\t') {
            ++text;
        }
        char* end                      = nullptr;
        const unsigned long long value = std::strtoull(text, &end, 10);
        if (end != text) {
            return static_cast<std::uint64_t>(value);
        }
        break;
    }
    return 0;
}

}  // namespace detail

/**
 * @brief 机器指纹，格式与 scripts/bench/run_bench.sh 的指纹段一致
 * @return 多行文本，每行以换行结尾
 */
inline std::string machine_fingerprint()
{
    std::string text;
    struct utsname info;
    if (::uname(&info) == 0) {
        text += std::string("kernel   : ") + info.release + "\n";
    }
    else {
        text += "kernel   : 未知\n";
    }

    const long cpus  = ::sysconf(_SC_NPROCESSORS_ONLN);
    text            += "cpus     : " + std::to_string(cpus > 0 ? cpus : 0) + "\n";

    const std::string model = detail::cpu_model_name();
    text += std::string("cpu model: ") + (model.empty() ? "未知" : model) + "\n";

    char memory[64] = {};
    std::snprintf(memory, sizeof(memory), "%.1f GiB",
                  static_cast<double>(detail::mem_total_kib()) / 1048576.0);
    text += std::string("memory   : ") + memory + "\n";
    return text;
}

/**
 * @brief 后台占用采样器
 * @details 启动后每 10ms 调用一次采样函数，记录采样窗口内的最大值。
 * @note start() 与 stop() 由同一条线程调用；采样函数须允许跨线程调用。
 */
class OccupancySampler {
   public:
    /// @param[in] sample 采样函数，返回值参与取峰值
    explicit OccupancySampler(std::function<std::size_t()> sample);
    ~OccupancySampler();

    OccupancySampler(const OccupancySampler&)            = delete;
    OccupancySampler& operator=(const OccupancySampler&) = delete;

    /// @brief 启动后台采样；重复调用无操作
    void start();

    /// @brief 窗口内峰值
    std::size_t peak() const;

    /// @brief 停止并等待采样线程退出；重复调用无操作
    void stop();

   private:
    std::function<std::size_t()> sample_;
    std::atomic<bool> running_{false};
    std::atomic<std::size_t> peak_{0};
    std::thread thread_;
};

inline OccupancySampler::OccupancySampler(std::function<std::size_t()> sample)
    : sample_(std::move(sample))
{
}

inline OccupancySampler::~OccupancySampler() { stop(); }

inline void OccupancySampler::start()
{
    if (running_.exchange(true)) {
        return;
    }
    thread_ = std::thread([this] {
        while (running_.load(std::memory_order_relaxed)) {
            const std::size_t value = sample_();
            std::size_t peak        = peak_.load(std::memory_order_relaxed);
            while (value > peak && !peak_.compare_exchange_weak(
                                       peak, value, std::memory_order_relaxed)) {
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    });
}

inline std::size_t OccupancySampler::peak() const
{
    return peak_.load(std::memory_order_relaxed);
}

inline void OccupancySampler::stop()
{
    running_.store(false, std::memory_order_relaxed);
    if (thread_.joinable()) {
        thread_.join();
    }
}

/**
 * @brief 一条压测结果
 * @details 各 stage 只填写本结构的字段，格式化与追加写入由 print_human()、
 *          append_tsv() 统一完成。
 */
struct Result {
    std::string stage;                     ///< stage 名
    std::string config;                    ///< 该轮的配置摘要
    double rate                    = 0.0;  ///< 目标速率 Hz，0 表示饱和
    double seconds                 = 0.0;  ///< 统计窗口秒数
    std::uint64_t events           = 0;    ///< 窗口内事件数
    double events_per_s            = 0.0;  ///< 窗口内事件率
    double us_per_event            = 0.0;  ///< 消费侧每事件 CPU 微秒
    /// 生产侧每次 push 尝试的 CPU 微秒，TSV 的 producer_us_per_event
    double producer_us_per_event   = 0.0;
    /// 生产侧每次成功 push 的 CPU 微秒
    double producer_us_per_success = 0.0;
    std::uint64_t drops            = 0;  ///< 窗口内通道拒收次数合计
    std::uint64_t raw_drops        = 0;  ///< 窗口内原始通道拒收次数
    std::uint64_t out_drops        = 0;  ///< 窗口内语义通道拒收次数
    std::uint64_t rss_kb           = 0;  ///< 结束时的常驻内存
    std::uint64_t peak_queue       = 0;  ///< 窗口内原始通道占用峰值
    std::uint64_t out_peak_queue   = 0;  ///< 窗口内语义通道占用峰值
};

/**
 * @brief 公共命令行选项
 * @details 入口只解析这些选项，其余参数原样交给 stage。
 */
struct CommonOptions {
    std::string stage;           ///< 压测段名
    std::string trace_path;      ///< 语料文件路径
    std::string out_path;        ///< TSV 追加路径；空表示打到 stdout
    int seconds        = 10;     ///< 统计窗口秒数
    int warmup_seconds = 1;      ///< 预热秒数
    double rate        = 0.0;    ///< 目标速率 Hz，0 表示饱和
    int queue          = 8192;   ///< 通道容量
    int pin_consumer   = -1;     ///< 消费侧绑核序号，-1 不绑
    int pin_producer   = -1;     ///< 生产侧绑核序号，-1 不绑
    bool quiet         = false;  ///< 不打印机器指纹与启动参数
};

/// @brief 打印人类可读的结果行
inline void print_human(const Result& result, const CommonOptions& options)
{
    std::printf("stage=%s config=%s\n", result.stage.c_str(),
                result.config.c_str());
    if (!options.trace_path.empty()) {
        std::printf("trace=%s\n", options.trace_path.c_str());
    }
    std::printf("seconds=%.3f rate=%g\n", result.seconds, result.rate);
    std::printf("events=%" PRIu64 " events/s=%.1f\n", result.events,
                result.events_per_s);
    std::printf(
        "us/event=%.3f producer_us/event(attempt)=%.3f "
        "producer_us/success=%.3f\n",
        result.us_per_event, result.producer_us_per_event,
        result.producer_us_per_success);
    std::printf("drops=%" PRIu64 " (raw=%" PRIu64 " out=%" PRIu64
                ") rss_kb=%" PRIu64 " peak_queue=%" PRIu64
                " out_peak_queue=%" PRIu64 "\n",
                result.drops, result.raw_drops, result.out_drops, result.rss_kb,
                result.peak_queue, result.out_peak_queue);
}

/// @brief 一行的 TSV 文本，含行尾换行
inline std::string result_tsv_line(const Result& result)
{
    char line[1024] = {};
    std::snprintf(line, sizeof(line),
                  "TSV\t%s\t%s\t%g\t%.3f\t%" PRIu64
                  "\t%.1f\t%.3f\t%.3f"
                  "\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64 "\n",
                  result.stage.c_str(), result.config.c_str(), result.rate,
                  result.seconds, result.events, result.events_per_s,
                  result.us_per_event, result.producer_us_per_event, result.drops,
                  result.rss_kb, result.peak_queue);
    return std::string(line);
}

/**
 * @brief 把一条结果追加为 TSV
 * @param[in] path 目标文件；空字符串时打到 stdout
 * @param[in] result 结果
 * @return 写入成功时为 true；打不开或写失败为 false
 * @note 目标文件为空或不存在时先写一行以 # 开头的表头。
 */
inline bool append_tsv(const std::string& path, const Result& result)
{
    const std::string line = result_tsv_line(result);
    if (path.empty()) {
        if (std::fputs(line.c_str(), stdout) < 0 || std::fflush(stdout) != 0) {
            std::fprintf(stderr, "写入 TSV 到 stdout 失败\n");
            return false;
        }
        return true;
    }

    bool need_header = true;
    {
        std::ifstream check(path, std::ios::binary | std::ios::ate);
        if (check.is_open()) {
            const std::streamoff size = check.tellg();
            need_header               = size <= 0;
        }
    }

    std::ofstream out(path, std::ios::binary | std::ios::app);
    if (!out.is_open()) {
        std::fprintf(stderr, "无法写入 TSV 文件 %s\n", path.c_str());
        return false;
    }
    if (need_header) {
        out << "#TSV\tstage\tconfig\trate\tseconds\tevents\tevents_per_s"
               "\tus_per_event\tproducer_us_per_event\tdrops\trss_kb"
               "\tpeak_queue\n";
    }
    out << line;
    out.flush();
    if (!out.good()) {
        std::fprintf(stderr, "写入 TSV 文件 %s 失败\n", path.c_str());
        return false;
    }
    return true;
}

}  // namespace bench

#endif  // HNG_TEST_BENCH_SUPPORT_HPP_
