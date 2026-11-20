/**
 * @file bench_syscalls.cc
 * @brief syscalls 探针的吞吐压测工具
 * @details
 * 加载 syscalls.bpf.o，挂载全部可用探针，由独立线程消费 ringbuf，同时派生
 * 若干子进程按 profile 循环制造系统调用，统计消费到的记录数与字节数。
 *
 * 记录长度取自 ringbuf 回调的 size（头 + 该 subtype 的定长载荷），不按
 * sizeof(syscall_event) 判断。普通事件受内核侧角色过滤约束，故压测前把每个
 * 工作子进程的 (tgid, 启动时间) 写入 hng_role_filter；进程生命周期事件与
 * exec 事件不受该过滤限制。
 *
 * 需 root 与 BPF 权限，故不注册为 ctest 用例。从仓库根手动执行：
 *   sudo build-agent/test/bench_syscalls --profile mixed --seconds 10
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
#include "kernel/include/role_filter_types.h"
#include "kernel/include/syscall_event_head.h"

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
              "syscall_event_head 尺寸变化会破坏按 subtype 分桶");

/// @brief 命令行选项
struct Options {
    std::string object_path = kDefaultObjectPath;
    Profile profile         = Profile::kMixed;
    int seconds             = 10;
    int warmup_seconds      = 1;
    int workers             = 1;
    bool quiet              = false;
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
        "用法: bench_syscalls [选项]\n"
        "  --obj PATH        syscalls.bpf.o 路径（默认 %s）\n"
        "  --profile NAME    file/process/exec/memory/network/mixed"
        "（默认 mixed）\n"
        "  --seconds N       压测时长，秒（默认 10）\n"
        "  --warmup N        预热秒数，不计入统计（默认 1）\n"
        "  --workers N       工作子进程数（默认 CPU 数的一半，至少 1）\n"
        "  --quiet           只输出结果行\n"
        "  --help            显示本帮助\n"
        "\n"
        "需要 root 与 BPF 权限。退出码：0 成功；1 运行期失败；\n"
        "2 加载或挂载失败；3 参数错误。\n"
        "TSV 列：profile workers seconds records bytes rec_per_s mib_per_s\n"
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
                std::fprintf(stderr, "参数错误：--obj 缺少路径\n");
                return false;
            }
            options.object_path = value;
        }
        else if (name == "--profile") {
            if (!take_value(value)) {
                std::fprintf(stderr, "参数错误：--profile 缺少名字\n");
                return false;
            }
            if (!find_profile(value, options.profile)) {
                std::fprintf(stderr, "参数错误：未知 profile：%s\n", value);
                print_usage(stderr);
                return false;
            }
        }
        else if (name == "--seconds") {
            if (!take_value(value) ||
                !parse_integer(value, 1, 86400, options.seconds)) {
                std::fprintf(stderr,
                             "参数错误：--seconds 需为 1..86400 的整数\n");
                return false;
            }
        }
        else if (name == "--warmup") {
            if (!take_value(value) ||
                !parse_integer(value, 0, 86400, options.warmup_seconds)) {
                std::fprintf(stderr, "参数错误：--warmup 需为 0..86400 的整数\n");
                return false;
            }
        }
        else if (name == "--workers") {
            if (!take_value(value) ||
                !parse_integer(value, 1, 4096, options.workers)) {
                std::fprintf(stderr, "参数错误：--workers 需为 1..4096 的整数\n");
                return false;
            }
        }
        else if (name == "--quiet") {
            if (inline_value != nullptr) {
                std::fprintf(stderr, "参数错误：--quiet 不接受取值\n");
                return false;
            }
            options.quiet = true;
        }
        else {
            std::fprintf(stderr, "参数错误：未知选项 %s\n", argv[index]);
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
            std::fprintf(stderr,
                         "提示：未找到 tracefs，无法跳过缺失的 tracepoint\n");
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
            std::fprintf(stderr, "关闭探针 %s 的 autoload 失败：%s\n", section,
                         std::strerror(errno));
            continue;
        }
        ++skipped;
    }
    if (skipped > 0 && !quiet) {
        std::fprintf(stderr, "跳过 %d 个 tracefs 中不存在的 tracepoint 探针\n",
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
            std::fprintf(stderr, "挂载探针 %s 失败：%s\n",
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
        error = "对象内缺少计数器 map";
        return false;
    }
    if (::bpf_map__type(map) != BPF_MAP_TYPE_PERCPU_ARRAY) {
        error = "计数器 map 不是 PERCPU_ARRAY";
        return false;
    }
    const __u32 value_size = ::bpf_map__value_size(map);
    if (value_size != sizeof(std::uint64_t)) {
        error = "计数器 map 的值不是 u64";
        return false;
    }
    const int cpu_count = ::libbpf_num_possible_cpus();
    if (cpu_count < 1) {
        error = "读取 possible CPU 数失败";
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
            error = std::string("读取计数器失败：") + std::strerror(errno);
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
};

/// @brief 校准 PID 命名空间偏移时使用的探查状态
struct PidProbe {
    const std::vector<std::uint64_t>* starts = nullptr;  ///< 待匹配的启动时间
    std::vector<__u32>* globals              = nullptr;  ///< 命中的全局 TGID
    std::size_t matched                      = 0;        ///< 已匹配个数
};

/// @brief 非空时 ringbuf 回调走 PID 探查，而不是吞吐统计
PidProbe* g_pid_probe = nullptr;

/**
 * @brief ringbuf 回调：只做计数，不解析载荷
 * @param[in,out] context Stats
 * @param[in] data 记录起始地址
 * @param[in] size 记录长度，由 ringbuf 给出
 * @return 0
 * @note 校准阶段（g_pid_probe 非空）改按进程诞生事件把启动时间映射到全局 TGID：
 *       嵌套 PID 命名空间里用户态 pid 与内核全局 TGID 不同，而角色过滤键用的是
 *       后者；启动时间与命名空间无关，可作匹配键。
 */
int on_record(void* context, void* data, std::size_t size)
{
    if (g_pid_probe != nullptr) {
        if (size < sizeof(struct syscall_event_head)) {
            return 0;
        }
        const auto* head = static_cast<const struct syscall_event_head*>(data);
        if (head->name != SYSCALL_EVENT_FORK || g_pid_probe->starts == nullptr ||
            g_pid_probe->globals == nullptr) {
            return 0;
        }
        const std::vector<std::uint64_t>& starts = *g_pid_probe->starts;
        std::vector<__u32>& globals              = *g_pid_probe->globals;
        for (std::size_t i = 0; i < starts.size() && i < globals.size(); ++i) {
            if (globals[i] == 0 && starts[i] == head->head.pid_start_time) {
                globals[i] = head->head.pid;
                ++g_pid_probe->matched;
            }
        }
        return 0;
    }
    Stats* stats = static_cast<Stats*>(context);
    if (!stats->counting) {
        return 0;
    }
    ++stats->records;
    stats->bytes += size;
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

/**
 * @brief 读取 /proc/<pid>/stat 字段 22（USER_HZ 对齐的启动时间）
 * @param[in] pid 目标进程
 * @param[out] start_time 启动时间
 * @return 读取并解析成功时为 true
 * @note 该值与内核 start_boottime / NSEC_PER_USER_HZ 相同，是角色过滤键的
 *       第二分量。
 */
bool read_process_start_time(pid_t pid, std::uint64_t& start_time)
{
    char path[64]         = {};
    const int path_length = std::snprintf(path, sizeof(path), "/proc/%ld/stat",
                                          static_cast<long>(pid));
    if (path_length <= 0 ||
        static_cast<std::size_t>(path_length) >= sizeof(path)) {
        return false;
    }
    const int fd = ::open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return false;
    }
    char buffer[512]     = {};
    const ssize_t length = ::read(fd, buffer, sizeof(buffer) - 1);
    ignore_result(::close(fd));
    if (length <= 0) {
        return false;
    }
    buffer[length] = '\0';

    char* cursor   = std::strrchr(buffer, ')');
    if (!cursor) {
        return false;
    }
    ++cursor;
    for (int field = 3; field <= 22; ++field) {
        while (*cursor == ' ') {
            ++cursor;
        }
        if (*cursor == '\0') {
            return false;
        }
        if (field == 3) {
            ++cursor;
            continue;
        }
        char* end                       = nullptr;
        const unsigned long long parsed = std::strtoull(cursor, &end, 10);
        if (end == cursor) {
            return false;
        }
        if (field == 22) {
            start_time = static_cast<std::uint64_t>(parsed);
            return true;
        }
        cursor = end;
    }
    return false;
}

/**
 * @brief 把 worker 加入角色过滤白名单
 * @param[in] filter_fd hng_role_filter map fd
 * @param[in] tgid worker 的内核全局 TGID
 * @param[in] start_time worker 的启动时间（USER_HZ 滴答，取自 /proc）
 * @param[out] error 失败原因
 * @return 成功时为 true
 * @note 过滤键必须用内核全局 TGID：嵌套 PID 命名空间里它与用户态 pid 不同，
 *       由进程诞生事件的 pid_start_time 反查得到（见 PidProbe）。
 */
bool allow_worker(int filter_fd, __u32 tgid, std::uint64_t start_time,
                  std::string& error)
{
    hng_role_filter_key key{};
    key.tgid            = tgid;
    key.reserved        = 0;
    key.start_time      = start_time;
    const __u32 allowed = 1;
    if (::bpf_map_update_elem(filter_fd, &key, &allowed, BPF_ANY) != 0) {
        error = std::string("写入角色过滤 map 失败：") + std::strerror(errno);
        return false;
    }
    __u32 readback = 0;
    const int rc   = ::bpf_map_lookup_elem(filter_fd, &key, &readback);
    if (readback != 1 || rc != 0) {
        error = "角色过滤 map 回读失败";
        return false;
    }
    return true;
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
 */
void print_results(const Options& options, const Stats& stats,
                   const DrainResult& drain, std::uint64_t reserve_failures,
                   std::uint64_t pending_lost)
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
                     "提示：当前不是 root，加载 BPF 对象通常需要 CAP_BPF 或 "
                     "CAP_SYS_ADMIN\n");
    }
    // 放行管道在 worker 全部提前退出时会触发 SIGPIPE，这里按可处理错误对待。
    ignore_result(::signal(SIGPIPE, SIG_IGN));

    bpf_object* opened =
        ::bpf_object__open_file(options.object_path.c_str(), nullptr);
    if (!opened) {
        const int error = errno == 0 ? EINVAL : errno;
        std::fprintf(stderr, "打开 BPF 对象失败：%s：%s\n",
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
        std::fprintf(stderr, "加载 BPF 对象失败：%s\n",
                     libbpf_error_text(load_error).c_str());
        std::fprintf(stderr,
                     "提示：加载通常需要 root 与 CAP_BPF/CAP_SYS_ADMIN，"
                     "可用 sudo 运行\n");
        return kExitBpfFailure;
    }

    bpf_map* ring_map =
        ::bpf_object__find_map_by_name(object.get(), "syscall_events");
    bpf_map* reserve_map =
        ::bpf_object__find_map_by_name(object.get(), "reserve_failures");
    bpf_map* pending_map =
        ::bpf_object__find_map_by_name(object.get(), "pending_lost");
    bpf_map* filter_map =
        ::bpf_object__find_map_by_name(object.get(), HNG_ROLE_FILTER_MAP_NAME);
    if (!ring_map || !reserve_map || !pending_map || !filter_map) {
        std::fprintf(stderr,
                     "对象内缺少 ringbuf、计数器或角色过滤 map，"
                     "可能不是 syscalls.bpf.o\n");
        return kExitBpfFailure;
    }
    if (::bpf_map__type(ring_map) != BPF_MAP_TYPE_RINGBUF) {
        std::fprintf(stderr, "syscall_events map 不是 RINGBUF\n");
        return kExitBpfFailure;
    }

    std::uint64_t reserve_before = 0;
    std::uint64_t pending_before = 0;
    std::string counter_error;
    if (!read_percpu_counter(reserve_map, reserve_before, counter_error) ||
        !read_percpu_counter(pending_map, pending_before, counter_error)) {
        std::fprintf(stderr, "读取内核计数器失败：%s\n", counter_error.c_str());
        return kExitBpfFailure;
    }

    std::vector<LinkPtr> links;
    //! @note 单个探针挂载失败不中止压测：宿主上可能存在个别 tracepoint
    //!       不可挂载（例如被内核配置或权限策略挡住），其余探针的数据仍然有效。
    const int attach_failures = attach_programs(object.get(), links);
    if (links.empty()) {
        std::fprintf(stderr, "没有探针成功挂载，无法压测\n");
        return kExitBpfFailure;
    }
    if (attach_failures != 0) {
        std::fprintf(stderr,
                     "挂载探针部分失败：%d 个不可用，%zu 个已挂载（继续压测）\n",
                     attach_failures, links.size());
    }

    Stats stats;
    stats.attach_failed = attach_failures;
    ring_buffer* raw_buffer =
        ::ring_buffer__new(::bpf_map__fd(ring_map), on_record, &stats, nullptr);
    if (!raw_buffer) {
        std::fprintf(stderr, "创建 ringbuf 读取器失败：%s\n",
                     std::strerror(errno));
        return kExitBpfFailure;
    }
    RingBufferPtr buffer(raw_buffer);

    int gate[2] = {-1, -1};
    if (::pipe2(gate, O_CLOEXEC) != 0) {
        std::fprintf(stderr, "创建放行管道失败：%s\n", std::strerror(errno));
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
            std::fprintf(stderr, "创建 worker 失败：%s\n", std::strerror(errno));
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

    //! @note 角色过滤键用的是内核全局 TGID。嵌套 PID 命名空间里它与 getpid()
    //!       不同，只能用进程诞生事件反查：pid_start_time 与命名空间无关。
    std::vector<std::uint64_t> starts(workers.size(), 0);
    for (std::size_t i = 0; i < workers.size(); ++i) {
        if (!read_process_start_time(workers[i], starts[i])) {
            std::fprintf(stderr, "读取 worker %d 启动时间失败\n",
                         static_cast<int>(workers[i]));
            abort_workers(gate_write, workers);
            return kExitRuntimeFailure;
        }
    }
    std::vector<__u32> globals(workers.size(), 0);
    PidProbe probe;
    probe.starts  = &starts;
    probe.globals = &globals;
    g_pid_probe   = &probe;
    for (int waited  = 0; probe.matched < workers.size() && waited < 2000;
         waited     += 10) {
        if (::ring_buffer__poll(raw_buffer, 10) < 0) {
            break;
        }
    }
    g_pid_probe         = nullptr;

    const int filter_fd = ::bpf_map__fd(filter_map);
    for (std::size_t i = 0; i < workers.size(); ++i) {
        const __u32 tgid =
            globals[i] != 0 ? globals[i] : static_cast<__u32>(workers[i]);
        std::string error;
        if (!allow_worker(filter_fd, tgid, starts[i], error)) {
            std::fprintf(stderr, "登记 worker %d（全局 TGID %u）失败：%s\n",
                         static_cast<int>(workers[i]), tgid, error.c_str());
            abort_workers(gate_write, workers);
            return kExitRuntimeFailure;
        }
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
        std::fprintf(stderr, "放行 worker 失败：%s\n", std::strerror(errno));
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

    std::uint64_t reserve_after = 0;
    std::uint64_t pending_after = 0;
    if (!read_percpu_counter(reserve_map, reserve_after, counter_error) ||
        !read_percpu_counter(pending_map, pending_after, counter_error)) {
        std::fprintf(stderr, "读取内核计数器失败：%s\n", counter_error.c_str());
        return kExitRuntimeFailure;
    }
    const std::uint64_t reserve_failures =
        reserve_after >= reserve_before ? reserve_after - reserve_before : 0;
    const std::uint64_t pending_lost =
        pending_after >= pending_before ? pending_after - pending_before : 0;

    print_results(options, stats, drain, reserve_failures, pending_lost);

    if (drain.poll_error != 0) {
        std::fprintf(stderr, "消费 ringbuf 失败：%s\n",
                     std::strerror(drain.poll_error));
    }
    if (failed_workers > 0) {
        std::fprintf(stderr, "%d 个 worker 异常退出（常见原因：fork 失败）\n",
                     failed_workers);
    }
    if (stats.records == 0 && !options.quiet) {
        std::fprintf(stderr,
                     "提示：未采集到事件，检查 tracefs 挂载、tracepoint 与"
                     "角色过滤 map\n");
    }
    if (drain.poll_error != 0 || failed_workers > 0) {
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
