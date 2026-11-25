/**
 * @file bench_syscalls.cc
 * @brief syscalls 探针的吞吐压测工具
 * @details
 * 加载 syscalls.bpf.o，挂载全部可用探针，由独立线程消费 ringbuf，同时派生
 * 若干子进程按 profile 循环制造系统调用，统计消费到的记录数与字节数。
 *
 * 记录长度取自 ringbuf 回调的 size（头 + 该 subtype 的定长载荷），不按
 * sizeof(syscall_event) 判断。普通事件默认全部采集，统计口径为全量事件；
 * 进程生命周期事件与 exec 事件绕过名单判定。
 *
 * 需 root 与 BPF 权限，故不注册为 ctest 用例。从仓库根手动执行：
 *   sudo build-agent/test/bench_syscalls --profile mixed --seconds 10
 *
 * --dump PATH 把统计窗口内的 ringbuf 记录原样写成语料文件，格式见
 * bench_trace.hpp。
 */

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/types.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
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
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "agent/util/include/tracefs.hpp"
#include "kernel/include/syscall_event_head.h"
#include "test/bench/bench_trace.hpp"

namespace {

using Clock                              = std::chrono::steady_clock;

/// @brief 默认 BPF 对象路径
constexpr const char* kDefaultObjectPath = "kernel/build/syscalls.bpf.o";

/// @brief 退出码：运行期失败
constexpr int kExitRuntimeFailure        = 1;
/// @brief 退出码：加载或挂载失败
constexpr int kExitBpfFailure            = 2;
/// @brief 退出码：参数错误
constexpr int kExitUsage                 = 3;

/// @brief 工作子进程在 fork/exec 失败时使用的退出码
constexpr int kWorkerFailureExitCode     = 1;

/// @brief 压测负载类型
enum class Profile {
    kFile,
    kProcess,
    kExec,
    kMemory,
    kNetwork,
    kMixed,
};

/// @brief profile 的名字与枚举值
struct ProfileOption {
    const char* name;
    Profile profile;
};

/// @brief 命令行可选的 profile 表
constexpr ProfileOption kProfileOptions[] = {
    {"file", Profile::kFile},       {"process", Profile::kProcess},
    {"exec", Profile::kExec},       {"memory", Profile::kMemory},
    {"network", Profile::kNetwork}, {"mixed", Profile::kMixed},
};

/// @brief 需要按 subtype 分桶并打印的事件类别
struct SubtypeLabel {
    int subtype;
    const char* name;
};

/// @brief subtype 的打印顺序；缺的类别不打印
constexpr SubtypeLabel kSubtypeLabels[] = {
    {FILE_EVENT, "file"},
    {PROCESS_EVENT, "process"},
    {EXEC_EVENT, "exec"},
    {MEMORY_EVENT, "memory"},
    {NETWORK_EVENT, "network"},
    {KERNEL_EVENT, "kernel"},
    {CREDENTIAL_EVENT, "credential"},
    {NAMESPACE_EVENT, "namespace"},
    {SIGNAL_EVENT, "signal"},
};

/// @brief subtype 计数槽数，覆盖 UNKNOWN_EVENT..SIGNAL_EVENT
constexpr std::size_t kSubtypeSlotCount = SIGNAL_EVENT + 1;

// 事件头尺寸决定 subtype 的偏移；内核与用户态共用该布局
static_assert(sizeof(struct syscall_event_head) == 80,
              "changing the size of syscall_event_head breaks subtype bucketing");

/// @brief 命令行选项
struct Options {
    std::string object_path = kDefaultObjectPath;
    Profile profile         = Profile::kMixed;
    int seconds             = 10;
    int warmup_seconds      = 1;
    int workers             = 1;
    bool quiet              = false;
    std::string dump_path;
};

/// @brief 默认 worker 数：在线 CPU 数的一半，至少 1
int default_worker_count()
{
    const long cpus = ::sysconf(_SC_NPROCESSORS_ONLN);
    if (cpus <= 1) {
        return 1;
    }
    const long half = cpus / 2;
    return static_cast<int>(half < 1 ? 1 : half);
}

/// @brief 打印用法
void print_usage(std::FILE* out)
{
    std::fprintf(
        out,
        "Usage: bench_syscalls [options]\n"
        "  --obj PATH        syscalls.bpf.o path (default %s)\n"
        "  --profile NAME    file/process/exec/memory/network/mixed"
        " (default mixed)\n"
        "  --seconds N       benchmark duration in seconds (default 10)\n"
        "  --warmup N        warmup seconds, not counted (default 1)\n"
        "  --workers N       worker child processes (default half the CPU count, "
        "at least 1)\n"
        "  --dump PATH       export records in the measurement window to a trace "
        "file\n"
        "  --quiet           print only the result lines\n"
        "  --help            show this help\n"
        "\n"
        "Requires root and BPF privileges. Exit codes: 0 success; 1 runtime "
        "failure;\n"
        "2 failed to load or attach; 3 parameter error.\n"
        "TSV columns: profile workers seconds records bytes rec_per_s mib_per_s\n"
        "        us_per_event reserve_failures pending_lost\n",
        kDefaultObjectPath);
}

/// @brief 解析严格十进制整数
bool parse_integer(const char* text, int minimum, int maximum, int& value)
{
    if (!text || *text == '\0') {
        return false;
    }
    errno             = 0;
    char* end         = nullptr;
    const long parsed = std::strtol(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || parsed < minimum ||
        parsed > maximum) {
        return false;
    }
    value = static_cast<int>(parsed);
    return true;
}

/// @brief 按名字查 profile
bool find_profile(std::string_view name, Profile& profile)
{
    for (const ProfileOption& option : kProfileOptions) {
        if (name == option.name) {
            profile = option.profile;
            return true;
        }
    }
    return false;
}

/// @brief profile 的显示名
const char* profile_name(Profile profile)
{
    for (const ProfileOption& option : kProfileOptions) {
        if (option.profile == profile) {
            return option.name;
        }
    }
    return "unknown";
}

/**
 * @brief 解析命令行
 * @param[in] argc 参数个数
 * @param[in] argv 参数表
 * @param[out] options 解析结果
 * @param[out] help 是否请求了 --help
 * @return 参数合法时为 true；否则已向 stderr 打印原因
 * @note 数值参数只接受十进制全串；位置参数一律拒绝。
 */
bool parse_options(int argc, char** argv, Options& options, bool& help)
{
    int index = 1;
    while (index < argc) {
        const std::string_view argument(argv[index]);
        const std::string_view::size_type equal = argument.find('=');
        const std::string_view name             = equal == std::string_view::npos
                                                      ? argument
                                                      : argument.substr(0, equal);
        const char* inline_value =
            equal == std::string_view::npos ? nullptr : argv[index] + equal + 1;

        auto take_value = [&](const char*& value) -> bool {
            if (inline_value != nullptr) {
                value = inline_value;
                return true;
            }
            if (index + 1 >= argc) {
                return false;
            }
            value = argv[++index];
            return true;
        };

        if (name == "--help") {
            help = true;
            return true;
        }

        const char* value = nullptr;
        if (name == "--obj") {
            if (!take_value(value)) {
                std::fprintf(stderr,
                             "parameter error: --obj is missing a path\n");
                return false;
            }
            options.object_path = value;
        }
        else if (name == "--profile") {
            if (!take_value(value)) {
                std::fprintf(stderr,
                             "parameter error: --profile is missing a name\n");
                return false;
            }
            if (!find_profile(value, options.profile)) {
                std::fprintf(stderr, "parameter error: unknown profile: %s\n",
                             value);
                print_usage(stderr);
                return false;
            }
        }
        else if (name == "--seconds") {
            if (!take_value(value) ||
                !parse_integer(value, 1, 86400, options.seconds)) {
                std::fprintf(stderr,
                             "parameter error: --seconds must be an integer in "
                             "1..86400\n");
                return false;
            }
        }
        else if (name == "--warmup") {
            if (!take_value(value) ||
                !parse_integer(value, 0, 86400, options.warmup_seconds)) {
                std::fprintf(
                    stderr,
                    "parameter error: --warmup must be an integer in 0..86400\n");
                return false;
            }
        }
        else if (name == "--workers") {
            if (!take_value(value) ||
                !parse_integer(value, 1, 4096, options.workers)) {
                std::fprintf(
                    stderr,
                    "parameter error: --workers must be an integer in 1..4096\n");
                return false;
            }
        }
        else if (name == "--dump") {
            if (!take_value(value) || *value == '\0') {
                std::fprintf(stderr,
                             "parameter error: --dump is missing a path\n");
                return false;
            }
            options.dump_path = value;
        }
        else if (name == "--quiet") {
            if (inline_value != nullptr) {
                std::fprintf(stderr,
                             "parameter error: --quiet does not take a value\n");
                return false;
            }
            options.quiet = true;
        }
        else {
            std::fprintf(stderr, "parameter error: unknown option %s\n",
                         argv[index]);
            print_usage(stderr);
            return false;
        }
        ++index;
    }
    return true;
}

/// @brief bpf_object 的删除器
struct ObjectDeleter {
    void operator()(bpf_object* object) const noexcept
    {
        ::bpf_object__close(object);
    }
};

/// @brief bpf_link 的删除器
struct LinkDeleter {
    void operator()(bpf_link* link) const noexcept { ::bpf_link__destroy(link); }
};

/// @brief ring_buffer 的删除器
struct RingBufferDeleter {
    void operator()(ring_buffer* buffer) const noexcept
    {
        ::ring_buffer__free(buffer);
    }
};

using ObjectPtr     = std::unique_ptr<bpf_object, ObjectDeleter>;
using LinkPtr       = std::unique_ptr<bpf_link, LinkDeleter>;
using RingBufferPtr = std::unique_ptr<ring_buffer, RingBufferDeleter>;

/// @brief 显式丢弃系统调用返回值，避免 warn_unused_result 告警
template <typename T>
void ignore_result(T)
{
}

/// @brief 格式化 libbpf 错误码
std::string libbpf_error_text(int error)
{
    char text[256] = {};
    if (::libbpf_strerror(error, text, sizeof(text)) != 0) {
        std::snprintf(text, sizeof(text), "%s", std::strerror(-error));
    }
    return std::string(text);
}

/**
 * @brief 拆分 tracepoint 程序的 section
 * @param[in] section 程序 section 名
 * @param[out] group tracepoint 组名
 * @param[out] event tracepoint 事件名
 * @return section 形如 tracepoint/<group>/<event> 时为 true
 */
bool split_tracepoint_section(std::string_view section, std::string_view& group,
                              std::string_view& event)
{
    constexpr std::string_view kPrefix = "tracepoint/";
    if (section.size() <= kPrefix.size() ||
        section.substr(0, kPrefix.size()) != kPrefix) {
        return false;
    }
    section.remove_prefix(kPrefix.size());
    const std::string_view::size_type separator = section.find('/');
    if (separator == std::string_view::npos) {
        return false;
    }
    group = section.substr(0, separator);
    event = section.substr(separator + 1);
    return !group.empty() && !event.empty() &&
           event.find('/') == std::string_view::npos;
}

/**
 * @brief 关闭 tracefs 中不存在的 tracepoint 程序的 autoload
 * @param[in] object 已打开、尚未加载的 BPF 对象
 * @param[in] tracefs_root tracefs 根；为空表示无法判定
 * @param[in] quiet 为 true 时不打印跳过信息
 * @return 被关闭 autoload 的程序数
 * @note 必须在 bpf_object__load 之前调用，否则缺失的 tracepoint 会让整个
 *       对象加载失败，而不是只让对应探针不可用。
 */
int skip_missing_tracepoints(bpf_object* object,
                             const std::filesystem::path& tracefs_root,
                             bool quiet)
{
    if (tracefs_root.empty()) {
        if (!quiet) {
            std::fprintf(
                stderr,
                "hint: tracefs not found, cannot skip missing tracepoints\n");
        }
        return 0;
    }

    int skipped          = 0;
    bpf_program* program = nullptr;
    bpf_object__for_each_program(program, object)
    {
        const char* section = ::bpf_program__section_name(program);
        if (!section) {
            continue;
        }
        std::string_view group;
        std::string_view event;
        if (!split_tracepoint_section(section, group, event)) {
            continue;
        }
        if (::hng::detail::tracepoint_present(tracefs_root, group, event)) {
            continue;
        }
        if (::bpf_program__set_autoload(program, false) != 0) {
            std::fprintf(stderr, "failed to disable autoload for probe %s: %s\n",
                         section, std::strerror(errno));
            continue;
        }
        ++skipped;
    }
    if (skipped > 0 && !quiet) {
        std::fprintf(stderr,
                     "skipped %d tracepoint probes not present in tracefs\n",
                     skipped);
    }
    return skipped;
}

/**
 * @brief 逐个挂载已 autoload 的程序
 * @param[in] object 已加载的 BPF 对象
 * @param[out] links 成功挂载的链接
 * @return 挂载失败的程序数
 * @note 单个程序失败不中止后续程序；失败原因打印到 stderr。
 */
int attach_programs(bpf_object* object, std::vector<LinkPtr>& links)
{
    int failures         = 0;
    bpf_program* program = nullptr;
    bpf_object__for_each_program(program, object)
    {
        if (!::bpf_program__autoload(program)) {
            continue;
        }
        const char* section = ::bpf_program__section_name(program);
        bpf_link* link      = ::bpf_program__attach(program);
        if (!link) {
            ++failures;
            std::fprintf(stderr, "failed to attach probe %s: %s\n",
                         section ? section : "<unknown>", std::strerror(errno));
            continue;
        }
        links.emplace_back(link);
    }
    return failures;
}

/**
 * @brief 读取每 CPU 计数器并求和
 * @param[in] map PERCPU_ARRAY 计数器；值类型为 u64
 * @param[out] sum 所有 CPU、所有 key 的和
 * @param[out] error 失败原因
 * @return 成功时为 true
 * @note 每 CPU 值按 round_up(value_size, 8) 为步长排列，CPU 数取
 *       libbpf_num_possible_cpus()；bpf_map__max_entries 是 key 数而非 CPU 数。
 */
bool read_percpu_counter(bpf_map* map, std::uint64_t& sum, std::string& error)
{
    if (!map) {
        error = "the object is missing the counter map";
        return false;
    }
    if (::bpf_map__type(map) != BPF_MAP_TYPE_PERCPU_ARRAY) {
        error = "the counter map is not PERCPU_ARRAY";
        return false;
    }
    const __u32 value_size = ::bpf_map__value_size(map);
    if (value_size != sizeof(std::uint64_t)) {
        error = "the counter map value is not u64";
        return false;
    }
    const int cpu_count = ::libbpf_num_possible_cpus();
    if (cpu_count < 1) {
        error = "failed to read the possible CPU count";
        return false;
    }

    const int fd               = ::bpf_map__fd(map);
    const std::size_t stride   = (value_size + 7U) & ~std::size_t{7};
    const std::size_t capacity = stride * static_cast<std::size_t>(cpu_count);
    std::vector<unsigned char> values(capacity);
    std::uint64_t total   = 0;
    const __u32 key_count = ::bpf_map__max_entries(map);
    for (__u32 key = 0; key < key_count; ++key) {
        std::memset(values.data(), 0, values.size());
        if (::bpf_map_lookup_elem(fd, &key, values.data()) != 0) {
            error =
                std::string("failed to read counter: ") + std::strerror(errno);
            return false;
        }
        for (int cpu = 0; cpu < cpu_count; ++cpu) {
            std::uint64_t value = 0;
            std::memcpy(&value,
                        values.data() + static_cast<std::size_t>(cpu) * stride,
                        sizeof(value));
            total += value;
        }
    }
    sum = total;
    return true;
}

/// @brief ringbuf 消费侧的统计
struct Stats {
    std::uint64_t records                     = 0;      ///< 记录数
    std::uint64_t bytes                       = 0;      ///< 记录字节数
    std::uint64_t subtypes[kSubtypeSlotCount] = {};     ///< 按 subtype 分桶
    bool counting                             = false;  ///< 是否处于统计窗口
    int attach_failed                         = 0;      ///< 挂载失败的探针数
    bench::TraceWriter* trace = nullptr;  ///< 语料写入器；nullptr 表示不导出
    std::string trace_error;              ///< 语料写入的首个错误
};

/**
 * @brief ringbuf 回调：只做计数，不解析载荷
 * @param[in,out] context Stats
 * @param[in] data 记录起始地址
 * @param[in] size 记录长度，由 ringbuf 给出
 * @return 0
 * @note 统计窗口内的记录同时写入 --dump 语料；写入失败只停止导出，不影响计数。
 */
int on_record(void* context, void* data, std::size_t size)
{
    Stats* stats = static_cast<Stats*>(context);
    if (!stats->counting) {
        return 0;
    }
    ++stats->records;
    stats->bytes += size;
    if (stats->trace != nullptr) {
        if (!stats->trace->write(data, size)) {
            stats->trace_error = stats->trace->error();
            stats->trace       = nullptr;
        }
    }
    if (size >= sizeof(struct syscall_event_head)) {
        const auto* head  = static_cast<const struct syscall_event_head*>(data);
        const int subtype = static_cast<int>(head->subtype);
        if (subtype >= 0 &&
            static_cast<std::size_t>(subtype) < kSubtypeSlotCount) {
            ++stats->subtypes[subtype];
        }
    }
    return 0;
}

/// @brief 取线程自身的 CPU 时间
bool thread_cpu_time(struct rusage& usage)
{
    return ::getrusage(RUSAGE_THREAD, &usage) == 0;
}

/// @brief timeval 换算为秒
double timeval_seconds(const struct timeval& value)
{
    return static_cast<double>(value.tv_sec) +
           static_cast<double>(value.tv_usec) / 1e6;
}

/// @brief ringbuf 消费线程的结果
struct DrainResult {
    double cpu_seconds = 0.0;  ///< 统计窗口内的线程 CPU 时间
    int poll_error     = 0;    ///< ring_buffer__poll 的错误码；0 表示正常
};

/**
 * @brief 持续消费 ringbuf，统计窗口内计数
 * @param[in] buffer ringbuf 读取器
 * @param[in,out] stats 统计
 * @param[in] run_start 预热与压测共同的起点
 * @param[in] warmup 预热时长
 * @param[in] stop 父线程置位后结束
 * @param[out] result CPU 时间与错误码
 * @note 预热期照常消费但不计数；停止后把 ringbuf 中剩余记录排空，仍计入
 *       统计窗口（它们产生于压测期内）。排空最多 200 ms，避免系统噪声
 *       让循环无法结束。
 */
void drain_records(ring_buffer* buffer, Stats& stats, Clock::time_point run_start,
                   std::chrono::seconds warmup, const std::atomic<bool>& stop,
                   DrainResult& result)
{
    const Clock::time_point measure_start = run_start + warmup;
    bool measuring                        = false;
    struct rusage cpu_start{};
    bool have_cpu_start = false;

    while (!stop.load(std::memory_order_relaxed)) {
        int timeout_ms = 10;
        if (!measuring) {
            const Clock::time_point now = Clock::now();
            if (now >= measure_start) {
                measuring      = true;
                stats.counting = true;
                have_cpu_start = thread_cpu_time(cpu_start);
            }
            else if (measure_start - now < std::chrono::milliseconds(10)) {
                // 临近统计窗口时缩短轮询，降低窗口起点的事件归属误差。
                timeout_ms = 1;
            }
        }
        const int polled = ::ring_buffer__poll(buffer, timeout_ms);
        if (polled < 0) {
            result.poll_error = -polled;
            break;
        }
    }

    if (measuring) {
        const Clock::time_point drain_deadline =
            Clock::now() + std::chrono::milliseconds(200);
        while (Clock::now() < drain_deadline) {
            const int polled = ::ring_buffer__poll(buffer, 0);
            if (polled < 0) {
                result.poll_error = -polled;
                break;
            }
            if (polled == 0) {
                break;
            }
        }
        struct rusage cpu_end{};
        if (have_cpu_start && thread_cpu_time(cpu_end)) {
            result.cpu_seconds = timeval_seconds(cpu_end.ru_utime) +
                                 timeval_seconds(cpu_end.ru_stime) -
                                 timeval_seconds(cpu_start.ru_utime) -
                                 timeval_seconds(cpu_start.ru_stime);
        }
    }
}

/// @brief 工作子进程的停止标志；仅由信号处理函数与工作循环读写
volatile sig_atomic_t g_stop = 0;

/// @brief SIGTERM 处理函数：只置停止标志
void handle_stop(int signal_number)
{
    static_cast<void>(signal_number);
    g_stop = 1;
}

/// @brief 安装 SIGTERM 处理函数
void install_stop_handler()
{
    struct sigaction action{};
    action.sa_handler = handle_stop;
    ::sigemptyset(&action.sa_mask);
    action.sa_flags = 0;
    ignore_result(::sigaction(SIGTERM, &action, nullptr));
}

/// @brief 一个 worker 的预计算负载参数
struct WorkloadContext {
    char file_path[64] = {};       ///< file profile 的路径
    struct sockaddr_un address{};  ///< network profile 的抽象地址
    socklen_t address_length = 0;  ///< 抽象地址长度
};

/**
 * @brief 预计算一个 worker 的路径与地址
 * @param[out] context 负载参数
 * @param[in] worker_index worker 序号
 * @note 循环里不再构造字符串、不再分配内存。
 */
void init_workload(WorkloadContext& context, int worker_index)
{
    std::snprintf(context.file_path, sizeof(context.file_path),
                  "/tmp/hng_bench_%d", worker_index);

    std::memset(&context.address, 0, sizeof(context.address));
    context.address.sun_family   = AF_UNIX;
    const int name_length        = std::snprintf(context.address.sun_path + 1,
                                                 sizeof(context.address.sun_path) - 1,
                                                 "hng_bench_%d", worker_index);
    const std::size_t name_limit = sizeof(context.address.sun_path) - 1;
    if (name_length <= 0 || static_cast<std::size_t>(name_length) >= name_limit) {
        context.address_length = 0;
        return;
    }
    context.address_length = static_cast<socklen_t>(
        offsetof(struct sockaddr_un, sun_path) + 1 + name_length);
}

/// @brief file profile：创建、关闭、删除
void run_file_cycle(const WorkloadContext& context)
{
    const int fd = ::openat(AT_FDCWD, context.file_path, O_CREAT | O_RDWR, 0600);
    if (fd >= 0) {
        ignore_result(::close(fd));
    }
    ignore_result(::unlinkat(AT_FDCWD, context.file_path, 0));
}

/// @brief process profile：fork 后子进程立即退出，父进程回收
void run_process_cycle()
{
    const pid_t child = ::fork();
    if (child < 0) {
        ::_exit(kWorkerFailureExitCode);
    }
    if (child == 0) {
        ::_exit(0);
    }
    int status   = 0;
    pid_t reaped = -1;
    do {
        reaped = ::waitpid(child, &status, 0);
    } while (reaped < 0 && errno == EINTR);
}

/// @brief exec profile：fork 后子进程执行 /bin/true，父进程回收
void run_exec_cycle()
{
    const pid_t child = ::fork();
    if (child < 0) {
        ::_exit(kWorkerFailureExitCode);
    }
    if (child == 0) {
        ignore_result(::execl("/bin/true", "true", static_cast<char*>(nullptr)));
        ::_exit(kWorkerFailureExitCode);
    }
    int status   = 0;
    pid_t reaped = -1;
    do {
        reaped = ::waitpid(child, &status, 0);
    } while (reaped < 0 && errno == EINTR);
}

/// @brief memory profile：mmap、mprotect、munmap
void run_memory_cycle()
{
    constexpr std::size_t kPageSize = 4096;
    void* const address = ::mmap(nullptr, kPageSize, PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (address == MAP_FAILED) {
        return;
    }
    ignore_result(::mprotect(address, kPageSize, PROT_READ | PROT_EXEC));
    ignore_result(::munmap(address, kPageSize));
}

/// @brief network profile：socket、bind、connect、close
void run_network_cycle(const WorkloadContext& context)
{
    const int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        return;
    }
    const auto* address =
        reinterpret_cast<const struct sockaddr*>(&context.address);
    ignore_result(::bind(fd, address, context.address_length));
    ignore_result(::connect(fd, address, context.address_length));
    ignore_result(::close(fd));
}

/**
 * @brief 执行一轮指定 profile 的系统调用
 * @param[in] profile 负载类型
 * @param[in] context 预计算参数
 * @param[in] round 轮次；mixed 按它对 5 取模轮转
 */
void run_cycle(Profile profile, const WorkloadContext& context,
               std::uint64_t round)
{
    switch (profile) {
        case Profile::kFile:
            run_file_cycle(context);
            break;
        case Profile::kProcess:
            run_process_cycle();
            break;
        case Profile::kExec:
            run_exec_cycle();
            break;
        case Profile::kMemory:
            run_memory_cycle();
            break;
        case Profile::kNetwork:
            run_network_cycle(context);
            break;
        case Profile::kMixed:
            switch (round % 5U) {
                case 0:
                    run_file_cycle(context);
                    break;
                case 1:
                    run_process_cycle();
                    break;
                case 2:
                    run_exec_cycle();
                    break;
                case 3:
                    run_memory_cycle();
                    break;
                default:
                    run_network_cycle(context);
                    break;
            }
            break;
    }
}

/**
 * @brief 工作子进程入口：等待放行，然后循环制造系统调用
 * @param[in] worker_index worker 序号
 * @param[in] profile 负载类型
 * @param[in] gate_read 放行管道读端
 * @param[in] parent_pid 父进程 pid，用于父进程提前退出的判定
 * @return 不返回；正常停止用 _exit(0)
 * @note fork/exec 失败用 _exit(1)，让父进程识别异常。
 */
[[noreturn]] void worker_main(int worker_index, Profile profile, int gate_read,
                              pid_t parent_pid)
{
    install_stop_handler();
    ignore_result(::prctl(PR_SET_PDEATHSIG, SIGTERM));
    if (::getppid() != parent_pid) {
        ::_exit(kWorkerFailureExitCode);
    }

    char token         = 0;
    ssize_t read_count = -1;
    do {
        read_count = ::read(gate_read, &token, 1);
    } while (read_count < 0 && errno == EINTR && g_stop == 0);
    ignore_result(::close(gate_read));
    if (read_count != 1) {
        ::_exit(kWorkerFailureExitCode);
    }

    WorkloadContext context;
    init_workload(context, worker_index);
    std::uint64_t round = 0;
    while (g_stop == 0) {
        run_cycle(profile, context, round);
        ++round;
    }
    ::_exit(0);
}

/// @brief 启动失败时终止尚未放行的 worker
void abort_workers(int& gate_write, std::vector<pid_t>& workers)
{
    if (gate_write >= 0) {
        ignore_result(::close(gate_write));
        gate_write = -1;
    }
    for (const pid_t pid : workers) {
        ignore_result(::kill(pid, SIGKILL));
    }
    for (const pid_t pid : workers) {
        int status   = 0;
        pid_t reaped = -1;
        do {
            reaped = ::waitpid(pid, &status, 0);
        } while (reaped < 0 && errno == EINTR);
    }
    workers.clear();
}

/**
 * @brief 打印结果（人类可读 + 一行 TSV）
 * @param[in] options 选项
 * @param[in] stats 统计
 * @param[in] drain 消费线程结果
 * @param[in] reserve_failures reserve_failures 增量
 * @param[in] pending_lost pending_lost 增量
 * @param[in] trace 非空时打印语料汇总（路径、条数、字节数）
 */
void print_results(const Options& options, const Stats& stats,
                   const DrainResult& drain, std::uint64_t reserve_failures,
                   std::uint64_t pending_lost, const bench::TraceWriter* trace)
{
    const double seconds = static_cast<double>(options.seconds);
    const double mib     = static_cast<double>(stats.bytes) / (1024.0 * 1024.0);
    const std::uint64_t records_per_second =
        stats.records / static_cast<std::uint64_t>(options.seconds);
    const double mib_per_second = mib / seconds;
    const double us_per_event =
        stats.records == 0
            ? 0.0
            : drain.cpu_seconds * 1e6 / static_cast<double>(stats.records);

    std::printf("profile=%s workers=%d seconds=%d\n",
                profile_name(options.profile), options.workers, options.seconds);
    std::printf("records=%" PRIu64 " bytes=%" PRIu64 " (%.1f MiB)\n",
                stats.records, stats.bytes, mib);
    std::printf("throughput=%" PRIu64 " rec/s  %.1f MiB/s\n", records_per_second,
                mib_per_second);

    std::printf("subtypes:");
    for (const SubtypeLabel& label : kSubtypeLabels) {
        const std::uint64_t count =
            stats.subtypes[static_cast<std::size_t>(label.subtype)];
        if (count > 0) {
            std::printf(" %s=%" PRIu64, label.name, count);
        }
    }
    std::printf("\n");

    std::printf("kernel: reserve_failures=%" PRIu64 " pending_lost=%" PRIu64
                " attach_failed=%d\n",
                reserve_failures, pending_lost, stats.attach_failed);
    std::printf("drain: cpu=%.3fs  us_per_event=%.2f  events=%" PRIu64 "\n",
                drain.cpu_seconds, us_per_event, stats.records);
    if (trace != nullptr) {
        std::printf("trace: path=%s records=%" PRIu64 " bytes=%" PRIu64 "\n",
                    options.dump_path.c_str(), trace->records(),
                    trace->payload_bytes());
    }
    std::printf("TSV\t%s\t%d\t%d\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64
                "\t%.1f\t%.2f\t%" PRIu64 "\t%" PRIu64 "\t%d\n",
                profile_name(options.profile), options.workers, options.seconds,
                stats.records, stats.bytes, records_per_second, mib_per_second,
                us_per_event, reserve_failures, pending_lost,
                stats.attach_failed);
}

/**
 * @brief 压测主流程
 * @param[in] options 选项
 * @return 进程退出码
 */
int run(const Options& options)
{
    if (::geteuid() != 0 && !options.quiet) {
        std::fprintf(stderr,
                     "hint: not running as root; loading the BPF object usually "
                     "needs CAP_BPF or "
                     "CAP_SYS_ADMIN\n");
    }
    // 放行管道在 worker 全部提前退出时会触发 SIGPIPE，这里按可处理错误对待。
    ignore_result(::signal(SIGPIPE, SIG_IGN));

    bpf_object* opened =
        ::bpf_object__open_file(options.object_path.c_str(), nullptr);
    if (!opened) {
        const int error = errno == 0 ? EINVAL : errno;
        std::fprintf(stderr, "failed to open BPF object: %s: %s\n",
                     options.object_path.c_str(),
                     libbpf_error_text(error).c_str());
        return kExitBpfFailure;
    }
    ObjectPtr object(opened);

    const std::filesystem::path tracefs_root =
        ::hng::detail::find_tracefs_root("/proc/mounts");
    skip_missing_tracepoints(object.get(), tracefs_root, options.quiet);

    const int load_error = ::bpf_object__load(object.get());
    if (load_error != 0) {
        std::fprintf(stderr, "failed to load BPF object: %s\n",
                     libbpf_error_text(load_error).c_str());
        std::fprintf(
            stderr,
            "hint: loading usually needs root and CAP_BPF/CAP_SYS_ADMIN, "
            "run it with sudo\n");
        return kExitBpfFailure;
    }

    bpf_map* ring_map =
        ::bpf_object__find_map_by_name(object.get(), "syscall_events");
    bpf_map* reserve_map =
        ::bpf_object__find_map_by_name(object.get(), "reserve_failures");
    bpf_map* pending_map =
        ::bpf_object__find_map_by_name(object.get(), "pending_lost");
    if (!ring_map || !reserve_map || !pending_map) {
        std::fprintf(stderr,
                     "the object is missing the ringbuf or counter map; "
                     "it may not be syscalls.bpf.o\n");
        return kExitBpfFailure;
    }
    if (::bpf_map__type(ring_map) != BPF_MAP_TYPE_RINGBUF) {
        std::fprintf(stderr, "syscall_events map is not RINGBUF\n");
        return kExitBpfFailure;
    }

    std::uint64_t reserve_before = 0;
    std::uint64_t pending_before = 0;
    std::string counter_error;
    if (!read_percpu_counter(reserve_map, reserve_before, counter_error) ||
        !read_percpu_counter(pending_map, pending_before, counter_error)) {
        std::fprintf(stderr, "failed to read kernel counters: %s\n",
                     counter_error.c_str());
        return kExitBpfFailure;
    }

    std::vector<LinkPtr> links;
    //! @note 单个探针挂载失败不中止压测：宿主上可能存在个别 tracepoint
    //!       不可挂载（例如被内核配置或权限策略挡住），其余探针的数据仍然有效。
    const int attach_failures = attach_programs(object.get(), links);
    if (links.empty()) {
        std::fprintf(
            stderr, "no probe attached successfully, cannot run the benchmark\n");
        return kExitBpfFailure;
    }
    if (attach_failures != 0) {
        std::fprintf(stderr,
                     "partially failed to attach probes: %d unavailable, %zu "
                     "attached (continuing the benchmark)\n",
                     attach_failures, links.size());
    }

    Stats stats;
    stats.attach_failed = attach_failures;
    ring_buffer* raw_buffer =
        ::ring_buffer__new(::bpf_map__fd(ring_map), on_record, &stats, nullptr);
    if (!raw_buffer) {
        std::fprintf(stderr, "failed to create the ringbuf reader: %s\n",
                     std::strerror(errno));
        return kExitBpfFailure;
    }
    RingBufferPtr buffer(raw_buffer);

    const bool trace_enabled = !options.dump_path.empty();
    bench::TraceWriter trace_writer;
    if (trace_enabled) {
        std::string trace_open_error;
        if (!trace_writer.open(options.dump_path, trace_open_error)) {
            std::fprintf(stderr, "failed to open trace file %s: %s\n",
                         options.dump_path.c_str(), trace_open_error.c_str());
            return kExitRuntimeFailure;
        }
        stats.trace = &trace_writer;
    }

    int gate[2] = {-1, -1};
    if (::pipe2(gate, O_CLOEXEC) != 0) {
        std::fprintf(stderr, "failed to create the release pipe: %s\n",
                     std::strerror(errno));
        return kExitRuntimeFailure;
    }
    int gate_read  = gate[0];
    int gate_write = gate[1];

    std::vector<pid_t> workers;
    workers.reserve(static_cast<std::size_t>(options.workers));
    const pid_t parent_pid = ::getpid();
    bool spawn_ok          = true;
    for (int index = 0; index < options.workers; ++index) {
        const pid_t child = ::fork();
        if (child == 0) {
            ignore_result(::close(gate_write));
            worker_main(index, options.profile, gate_read, parent_pid);
        }
        if (child < 0) {
            std::fprintf(stderr, "failed to create worker: %s\n",
                         std::strerror(errno));
            spawn_ok = false;
            break;
        }
        workers.push_back(child);
    }
    ignore_result(::close(gate_read));

    if (!spawn_ok) {
        abort_workers(gate_write, workers);
        return kExitRuntimeFailure;
    }

    const Clock::time_point run_start = Clock::now();
    std::atomic<bool> stop{false};
    DrainResult drain;
    std::thread consumer([&] {
        drain_records(buffer.get(), stats, run_start,
                      std::chrono::seconds(options.warmup_seconds), stop, drain);
    });

    const std::string release(static_cast<std::size_t>(options.workers), 'x');
    std::size_t released = 0;
    while (released < release.size()) {
        const ssize_t written = ::write(gate_write, release.data() + released,
                                        release.size() - released);
        if (written > 0) {
            released += static_cast<std::size_t>(written);
            continue;
        }
        if (written < 0 && errno == EINTR) {
            continue;
        }
        std::fprintf(stderr, "failed to release workers: %s\n",
                     std::strerror(errno));
        ignore_result(::close(gate_write));
        gate_write = -1;
        for (const pid_t pid : workers) {
            ignore_result(::kill(pid, SIGKILL));
        }
        for (const pid_t pid : workers) {
            int status   = 0;
            pid_t reaped = -1;
            do {
                reaped = ::waitpid(pid, &status, 0);
            } while (reaped < 0 && errno == EINTR);
        }
        stop.store(true);
        consumer.join();
        return kExitRuntimeFailure;
    }
    ignore_result(::close(gate_write));
    gate_write = -1;

    const Clock::time_point measure_end =
        run_start +
        std::chrono::seconds(options.warmup_seconds + options.seconds);
    std::this_thread::sleep_until(measure_end);

    for (const pid_t pid : workers) {
        ignore_result(::kill(pid, SIGTERM));
    }

    int failed_workers = 0;
    for (const pid_t pid : workers) {
        int status   = 0;
        pid_t reaped = -1;
        do {
            reaped = ::waitpid(pid, &status, 0);
        } while (reaped < 0 && errno == EINTR);
        if (reaped < 0) {
            ++failed_workers;
            continue;
        }
        if (WIFSIGNALED(status)) {
            const int signal_number = WTERMSIG(status);
            if (signal_number != SIGTERM) {
                ++failed_workers;
            }
            continue;
        }
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            ++failed_workers;
        }
    }

    stop.store(true);
    consumer.join();
    if (trace_enabled) {
        trace_writer.close();
    }

    std::uint64_t reserve_after = 0;
    std::uint64_t pending_after = 0;
    if (!read_percpu_counter(reserve_map, reserve_after, counter_error) ||
        !read_percpu_counter(pending_map, pending_after, counter_error)) {
        std::fprintf(stderr, "failed to read kernel counters: %s\n",
                     counter_error.c_str());
        return kExitRuntimeFailure;
    }
    const std::uint64_t reserve_failures =
        reserve_after >= reserve_before ? reserve_after - reserve_before : 0;
    const std::uint64_t pending_lost =
        pending_after >= pending_before ? pending_after - pending_before : 0;

    print_results(options, stats, drain, reserve_failures, pending_lost,
                  trace_enabled && !options.quiet ? &trace_writer : nullptr);

    bool trace_failed = false;
    if (trace_enabled) {
        const std::string& trace_error =
            stats.trace_error.empty() ? trace_writer.error() : stats.trace_error;
        if (!trace_error.empty()) {
            trace_failed = true;
            std::fprintf(stderr, "failed to write trace file %s: %s\n",
                         options.dump_path.c_str(), trace_error.c_str());
        }
    }

    if (drain.poll_error != 0) {
        std::fprintf(stderr, "failed to consume ringbuf: %s\n",
                     std::strerror(drain.poll_error));
    }
    if (failed_workers > 0) {
        std::fprintf(
            stderr, "%d workers exited abnormally (common cause: fork failure)\n",
            failed_workers);
    }
    if (stats.records == 0 && !options.quiet) {
        std::fprintf(stderr,
                     "hint: no events collected; check the tracefs mount, "
                     "tracepoints, and "
                     "the role filter map\n");
    }
    if (drain.poll_error != 0 || failed_workers > 0 || trace_failed) {
        return kExitRuntimeFailure;
    }
    return 0;
}

}  // namespace

int main(int argc, char** argv)
{
    Options options;
    options.workers = default_worker_count();

    bool help       = false;
    if (!parse_options(argc, argv, options, help)) {
        return kExitUsage;
    }
    if (help) {
        print_usage(stdout);
        return 0;
    }
    return run(options);
}
