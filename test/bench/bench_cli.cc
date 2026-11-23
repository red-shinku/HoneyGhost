/**
 * @file bench_cli.cc
 * @brief CLI 段压测：CLIRuntimeService::ReceiveEvent 的事件流
 */

#include "test/bench/stages.hpp"

#include "agent/cli_server/include/cli_server.hpp"
#include "agent/cli_server/include/cli_server_runner.hpp"
#include "agent/control_plane/include/context_service.hpp"
#include "agent/control_plane/include/process_service.hpp"
#include "agent/control_plane/include/role_service.hpp"
#include "agent/event_data/include/runtime_event.hpp"
#include "agent/runtime_engine/include/subscriber_reg_service.hpp"
#include "agent/util/include/pipeline_stats.hpp"
#include "kernel/include/syscall_event_type.h"

#include <grpcpp/grpcpp.h>
#include <proto/cli_service.grpc.pb.h>

#include <signal.h>
#include <sys/prctl.h>
#include <sys/types.h>
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
#include <fstream>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace {

/// @brief 退出码：运行期失败
constexpr int kExitRuntimeFailure = 1;
/// @brief 退出码：参数错误
constexpr int kExitUsage          = 3;

/// @brief 客户端流数的解析上限；超过服务端并发配额（64）用于触发配额错误
constexpr long kMaxStreams        = 1024;
/// @brief 服务端生成的临时配置里的并发流上限
constexpr long kServerMaxStreams  = 64;
/// @brief 单批事件数的上界，与服务端钳制一致
constexpr long kMaxBatch          = 256;
/// @brief 等待服务端就绪的上限
constexpr std::chrono::seconds kReadyLimit(20);
/// @brief 等待子进程退出的上限；超过后 SIGKILL
constexpr std::chrono::seconds kShutdownLimit(20);
/// @brief 等待客户端流线程发布 tid 的上限
constexpr std::chrono::milliseconds kTidWaitLimit(2000);
/// @brief 服务端 cli-tp 线程的 comm 前缀
constexpr char kCliTaskProcessor[]         = "cli-tp";
/// @brief 合成事件的进程镜像路径，长度约 30 字符
constexpr char kEventExe[]                 = "/usr/lib/honeyghost/bench-evt";
/// @brief CLONE_NEWNS，命名空间载荷的一个 CLONE_* 位
constexpr std::uint64_t kCloneNewNs        = 0x00020000ull;
/// @brief AT_FDCWD，文件载荷的 dirfd 取值
constexpr std::int32_t kAtFdcwd            = -100;
/// @brief 报文尺寸的采样间隔：每 64 条 batch 消息调一次 ByteSizeLong
constexpr std::uint64_t kBytesSampleStride = 64;

/// @brief CLI 段私有选项的多行用法
constexpr const char* kExtraHelp =
    "  --streams N       并发订阅流数，1..1024（服务端默认配额 64，超出会收到 "
    "RESOURCE_EXHAUSTED）（默认 1）\n"
    "  --batch N         每条响应最多携带的事件数，1..256（默认 64）\n"
    "  --socket PATH     Unix socket 绝对路径；空则 "
    "/tmp/hng-bench-cli-<pid>.sock\n"
    "  --server-config PATH  交给子进程的 CLI 配置文件；空则生成临时文件"
    "（含 64 流上限与 --queue 容量）\n"
    "  --queue N         每流队列容量，沿用公共选项 --queue（默认 8192）\n"
    "  本段忽略 --trace、--pin-consumer 与 --pin-producer。\n";

/// @brief CLI 段私有选项
struct CliOptions {
    int streams = 1;            ///< 并发订阅流数
    int batch   = 64;           ///< 单条响应的事件数上限
    std::string socket_path;    ///< Unix socket 路径；空表示用临时路径
    std::string server_config;  ///< 交给子进程的 CLI 配置文件；空表示生成
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

/**
 * @brief 解析 CLI 段私有选项
 * @param[in] rest 入口未识别的参数，保持原序
 * @param[out] options 解析结果
 * @param[out] error 失败原因
 * @return 解析成功时为 true
 * @note 支持 --name value 与 --name=value 两种写法。
 */
bool parse_rest(const std::vector<std::string>& rest, CliOptions& options,
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

        if (name == "--streams") {
            std::string text;
            if (!take_value(text) ||
                !parse_integer(text, 1, kMaxStreams, options.streams)) {
                error = "--streams 需为 1.." + std::to_string(kMaxStreams) +
                        " 的整数";
                return false;
            }
            continue;
        }
        if (name == "--batch") {
            std::string text;
            if (!take_value(text) ||
                !parse_integer(text, 1, kMaxBatch, options.batch)) {
                error =
                    "--batch 需为 1.." + std::to_string(kMaxBatch) + " 的整数";
                return false;
            }
            continue;
        }
        if (name == "--socket") {
            if (!take_value(options.socket_path) || options.socket_path.empty() ||
                options.socket_path.front() != '/') {
                error = "--socket 需为绝对路径";
                return false;
            }
            continue;
        }
        if (name == "--server-config") {
            if (!take_value(options.server_config) ||
                options.server_config.empty()) {
                error = "--server-config 缺少路径";
                return false;
            }
            continue;
        }
        error = "未知选项 " + name;
        return false;
    }
    return true;
}

// ============================================================
// 子进程：粗糙装配（全部替身，非真实业务）
// ============================================================

/// @brief 角色查询替身：不认识任何进程
class RoleStub final : public RoleLookupService {
   public:
    std::optional<std::uint32_t> lookup(hng::Process) const override
    {
        return std::nullopt;
    }

    std::optional<hng::Role> role(std::uint32_t) const override
    {
        return std::nullopt;
    }

    std::optional<hng::Process> main_process(std::uint32_t) const override
    {
        return std::nullopt;
    }

    std::vector<hng::Role> roles() const override { return {}; }

    std::vector<hng::Role> supervised_roles() const override { return {}; }

    std::optional<hng::role::RoleIdentity> identity(std::uint32_t) const override
    {
        return std::nullopt;
    }

    std::vector<hng::Process> members(std::uint32_t) const override { return {}; }

    RoleManagerStats stats() const override { return {}; }
};

/// @brief 上下文查询替身：不认识任何进程
class ContextStub final : public ContextLookupService {
   public:
    std::optional<std::uint32_t> lookup(hng::Process) const override
    {
        return std::nullopt;
    }

    std::optional<std::uint32_t> lookup_extra(hng::Process) const override
    {
        return std::nullopt;
    }

    std::vector<std::uint32_t> contexts_by_attr(hng::contextattr) const override
    {
        return {};
    }

    std::optional<ContextProcessSet> members(std::uint32_t) const override
    {
        return std::nullopt;
    }

    ContextManagerStats stats() const override { return {}; }
};

/// @brief 进程查询替身：不认识任何进程
class ProcessStub final : public ProcessLookupService {
   public:
    std::optional<hng::ProcessMessage> lookup(hng::Process) const override
    {
        return std::nullopt;
    }

    std::optional<hng::Process> resolve(std::uint32_t) const override
    {
        return std::nullopt;
    }

    ProcessManagerStats stats() const override { return {}; }
};

/// @brief 流水线统计替身：全零；cli 段由服务端按流表覆盖
class StatsStub final : public hng::PipelineStatsService {
   public:
    hng::PipelineStats snapshot() const override { return {}; }
};

/**
 * @brief 合成一条能通过默认过滤器的系统调用运行时事件
 * @param[in] seq 事件序号，用于轮换身份字段与语义子类型
 * @return 事件；etype 恒为 SYSCALL_EVENT，subtype 在 3..5 之间轮换
 * @note 载荷变体索引与子类型一一对应：3=CREDENTIAL（索引 2）、
 *       4=NAMESPACE（索引 3）、5=FILE（索引 4），head.subtype 与变体必须同指
 *       一类，否则报文头的子类型与载荷不一致。
 */
hng::RuntimeEvent make_event(std::uint64_t seq)
{
    hng::RuntimeEvent event{};
    const std::uint32_t pid        = 1000 + static_cast<std::uint32_t>(seq % 5);

    event.runtimeInfo.process      = hng::Process{pid, pid * 10ull};
    event.runtimeInfo.parent       = hng::Process{1, 0};
    event.runtimeInfo.etype        = hng::EventType::SYSCALL_EVENT;
    event.runtimeInfo.roleID       = 3 + static_cast<std::uint32_t>(seq % 3);
    event.runtimeInfo.contextID    = 7 + static_cast<std::uint32_t>(seq % 4);
    event.runtimeInfo.exe          = kEventExe;

    event.data.head.pid            = pid;
    event.data.head.pid_start_time = pid * 10ull;
    event.data.head.ppid           = 1;
    event.data.head.uid            = 1000;
    event.data.head.euid           = 1000;
    event.data.head.mnt_ns         = 4026531840u;
    event.data.head.comm           = "hng-bench";
    event.data.head.type           = hng::EventType::SYSCALL_EVENT;

    switch (seq % 3) {
        case 0: {
            event.data.head.subtype                = CREDENTIAL_EVENT;
            hng::credential_semantic_data& payload = event.data.data.emplace<2>();
            payload.set_syscall_name("setuid");
            payload.set_kind(static_cast<std::uint32_t>(CREDENTIAL_UID));
            payload.add_requested(1000);
            break;
        }
        case 1: {
            event.data.head.subtype               = NAMESPACE_EVENT;
            hng::namespace_semantic_data& payload = event.data.data.emplace<3>();
            payload.set_syscall_name("unshare");
            payload.set_flags(kCloneNewNs);
            payload.set_ns_mask(static_cast<std::uint32_t>(kCloneNewNs));
            payload.set_fd(-1);
            break;
        }
        default: {
            event.data.head.subtype = FILE_EVENT;
            hng::file_syscall_semantic_data& payload =
                event.data.data.emplace<4>();
            payload.set_syscall_name("openat");
            payload.set_path1("/etc/honeyghost/bench.conf");
            payload.set_flags(0);  // O_RDONLY
            payload.set_mode(0644);
            payload.set_dirfd(kAtFdcwd);
            break;
        }
    }
    event.runtimeInfo.subtype = event.data.head.subtype;
    return event;
}

/**
 * @brief 可调速替身引擎：每条订阅流一条生产者线程
 * @details 登记表由 mutex 保护，但推送全程不持锁：每条流的生产者只持有本流的
 *          sink 与 ack，锁只在订阅、注销与停机时使用。合成事件不调用
 *          RuntimeInfoFilter::should_take——过滤成本已在 engine 段测过，
 *          本段只压事件流接收与序列化路径。
 * @note 每条生产者按 rate_per_stream 独立节拍，0 表示全速；注销与停机在 join
 *       生产者之后才回执，故回执返回后不会再 on_event。
 */
class RateLimitedEngine final : public SubscriberRegService {
   public:
    /// @param[in] rate_per_stream 每流目标事件率 Hz；0 表示全速
    explicit RateLimitedEngine(double rate_per_stream)
        : rate_per_stream_(rate_per_stream)
    {
    }

    ~RateLimitedEngine() override { stop(); }

    RateLimitedEngine(const RateLimitedEngine&)            = delete;
    RateLimitedEngine& operator=(const RateLimitedEngine&) = delete;

    bool subscribe(RuntimeEventSink* sink, RuntimeInfoFilter filter,
                   UnsubscribeAck* ack) override
    {
        (void)filter;  // 本段不执行过滤，见类注释
        std::lock_guard<std::mutex> lock(mu_);
        if (stopping_.load(std::memory_order_acquire)) {
            return false;
        }
        std::unique_ptr<Entry> entry = std::make_unique<Entry>();
        entry->sink                  = sink;
        entry->ack                   = ack;
        Entry* raw                   = entry.get();
        entries_.push_back(std::move(entry));
        raw->thread = std::thread([this, raw] { produce(*raw); });
        return true;
    }

    void unsubscribe(RuntimeEventSink* sink) override
    {
        std::unique_ptr<Entry> entry;
        {
            std::lock_guard<std::mutex> lock(mu_);
            for (auto it = entries_.begin(); it != entries_.end(); ++it) {
                if ((*it)->sink == sink) {
                    entry = std::move(*it);
                    entries_.erase(it);
                    break;
                }
            }
        }
        if (!entry) {
            return;
        }
        entry->stopped.store(true, std::memory_order_release);
        if (entry->thread.joinable()) {
            entry->thread.join();
        }
        if (entry->ack != nullptr) {
            entry->ack->on_unsubscribed();
        }
    }

    /// @brief 停机：停掉全部生产者并回执；重复调用无操作
    void stop()
    {
        if (stopping_.exchange(true, std::memory_order_acq_rel)) {
            return;
        }
        std::vector<std::unique_ptr<Entry>> entries;
        {
            std::lock_guard<std::mutex> lock(mu_);
            entries.swap(entries_);
        }
        for (const std::unique_ptr<Entry>& entry : entries) {
            entry->stopped.store(true, std::memory_order_release);
        }
        for (const std::unique_ptr<Entry>& entry : entries) {
            if (entry->thread.joinable()) {
                entry->thread.join();
            }
        }
        for (const std::unique_ptr<Entry>& entry : entries) {
            if (entry->ack != nullptr) {
                entry->ack->on_unsubscribed();
            }
        }
    }

   private:
    struct Entry {
        RuntimeEventSink* sink = nullptr;
        UnsubscribeAck* ack    = nullptr;
        std::atomic<bool> stopped{false};
        std::thread thread;
    };

    void produce(Entry& entry)
    {
        // 线程由 cli-tp 任务线程创建，comm 会被继承；改名以免被计入 cli-tp 的
        // CPU 统计（read_tasks_cpu 按 comm 前缀匹配）
        (void)::prctl(PR_SET_NAME, "hng-bench-prod");
        bench::Pacer pacer(rate_per_stream_);
        std::uint64_t index = 0;
        while (!entry.stopped.load(std::memory_order_acquire) &&
               !stopping_.load(std::memory_order_acquire)) {
            if (rate_per_stream_ > 0.0) {
                (void)pacer.wait(index);
            }
            ++index;
            // 事件按值交给 sink：拷贝成本落在生产者线程，与真实引擎一致
            entry.sink->on_event(make_event(index));
        }
    }

    std::mutex mu_;
    std::vector<std::unique_ptr<Entry>> entries_;
    std::atomic<bool> stopping_{false};
    double rate_per_stream_;
};

/**
 * @brief 子进程入口：写临时配置、装配替身并跑 CLI 服务端
 * @param[in] options CLI 段私有选项
 * @param[in] socket_path 最终生效的 Unix socket 路径
 * @param[in] queue_capacity 每流队列容量，写进临时配置
 * @param[in] per_stream_rate 每条订阅流的目标事件率 Hz；0 表示全速
 * @note 调用点必须已 fork 且尚未创建任何线程：替身引擎与 userver 都会建线程。
 */
[[noreturn]] void run_server_child(const CliOptions& options,
                                   const std::string& socket_path,
                                   int queue_capacity, double per_stream_rate)
{
    // 父进程异常退出时由内核补发 SIGTERM，子进程不会成为孤儿常驻
    if (::prctl(PR_SET_PDEATHSIG, SIGTERM) != 0) {
        std::fprintf(stderr, "设置 PR_SET_PDEATHSIG 失败：%s\n",
                     std::strerror(errno));
    }

    std::string temporary_config;
    try {
        RoleStub role;
        ContextStub context;
        ProcessStub process;
        StatsStub stats;
        RateLimitedEngine engine(per_stream_rate);

        CLIServerDeps deps;
        deps.role    = &role;
        deps.context = &context;
        deps.process = &process;
        deps.subs    = &engine;
        deps.stats   = &stats;

        CLIServerOptions server_options;
        server_options.unix_socket_path = socket_path;
        if (options.server_config.empty()) {
            temporary_config = "/tmp/hng-bench-cli-" +
                               std::to_string(static_cast<long>(::getpid())) +
                               ".conf";
            std::ofstream file(temporary_config);
            if (!file.is_open()) {
                std::fprintf(stderr, "写临时配置 %s 失败：%s\n",
                             temporary_config.c_str(), std::strerror(errno));
                ::_exit(kExitRuntimeFailure);
            }
            file << "[cli_server]\n"
                 << "max_concurrent_streams = " << kServerMaxStreams << "\n"
                 << "queue_capacity = " << queue_capacity << "\n"
                 << "drain_timeout = 5s\n"
                 << "socket_path = " << socket_path << "\n";
            file.close();
            if (!file.good()) {
                std::fprintf(stderr, "写临时配置 %s 失败\n",
                             temporary_config.c_str());
                ::_exit(kExitRuntimeFailure);
            }
            server_options.config_path = temporary_config;
        }
        else {
            server_options.config_path = options.server_config;
        }

        const PreparedCliServerConfig prepared =
            prepare_cli_server_config(server_options);
        if (!temporary_config.empty()) {
            ::unlink(temporary_config.c_str());
            temporary_config.clear();
        }
        RunCliServer(deps, prepared);
    }
    catch (const std::exception& failure) {
        if (!temporary_config.empty()) {
            ::unlink(temporary_config.c_str());
        }
        std::fprintf(stderr, "cli 服务端子进程失败：%s\n", failure.what());
        ::_exit(kExitRuntimeFailure);
    }
    ::_exit(0);
}

// ============================================================
// 父进程：客户端
// ============================================================

/// @brief 子进程退出码/信号的可读描述
std::string describe_exit(int code)
{
    if (code >= 0) {
        return "退出码 " + std::to_string(code);
    }
    return "信号 " + std::to_string(-code);
}

/// @brief gRPC 状态码的可读名字
const char* status_code_name(grpc::StatusCode code)
{
    switch (code) {
        case grpc::StatusCode::OK:
            return "OK";
        case grpc::StatusCode::CANCELLED:
            return "CANCELLED";
        case grpc::StatusCode::UNKNOWN:
            return "UNKNOWN";
        case grpc::StatusCode::INVALID_ARGUMENT:
            return "INVALID_ARGUMENT";
        case grpc::StatusCode::DEADLINE_EXCEEDED:
            return "DEADLINE_EXCEEDED";
        case grpc::StatusCode::NOT_FOUND:
            return "NOT_FOUND";
        case grpc::StatusCode::ALREADY_EXISTS:
            return "ALREADY_EXISTS";
        case grpc::StatusCode::PERMISSION_DENIED:
            return "PERMISSION_DENIED";
        case grpc::StatusCode::RESOURCE_EXHAUSTED:
            return "RESOURCE_EXHAUSTED";
        case grpc::StatusCode::FAILED_PRECONDITION:
            return "FAILED_PRECONDITION";
        case grpc::StatusCode::ABORTED:
            return "ABORTED";
        case grpc::StatusCode::OUT_OF_RANGE:
            return "OUT_OF_RANGE";
        case grpc::StatusCode::UNIMPLEMENTED:
            return "UNIMPLEMENTED";
        case grpc::StatusCode::INTERNAL:
            return "INTERNAL";
        case grpc::StatusCode::UNAVAILABLE:
            return "UNAVAILABLE";
        case grpc::StatusCode::DATA_LOSS:
            return "DATA_LOSS";
        case grpc::StatusCode::UNAUTHENTICATED:
            return "UNAUTHENTICATED";
        case grpc::StatusCode::DO_NOT_USE:
            break;
    }
    return "UNKNOWN_CODE";
}

/**
 * @brief 子进程句柄：析构时保证 SIGTERM 并 waitpid
 * @note 拒绝拷贝；父进程任何退出路径都不会留下常驻子进程。
 */
class ServerProcess final {
   public:
    explicit ServerProcess(pid_t pid) : pid_(pid) {}

    ~ServerProcess()
    {
        std::string ignored;
        (void)shutdown(ignored);
    }

    ServerProcess(const ServerProcess&)            = delete;
    ServerProcess& operator=(const ServerProcess&) = delete;

    pid_t pid() const { return pid_; }

    /**
     * @brief 子进程是否仍在运行
     * @param[out] code 已退出时给出退出码（非负）或终止信号（为负）
     * @return 仍在运行时为 true
     */
    bool alive(int& code)
    {
        if (reaped_) {
            code = code_;
            return false;
        }
        int status         = 0;
        const pid_t reaped = ::waitpid(pid_, &status, WNOHANG);
        if (reaped == pid_) {
            reaped_ = true;
            code_   = exit_code_of(status);
            code    = code_;
            return false;
        }
        if (reaped < 0 && errno != EINTR) {
            reaped_ = true;
            code_   = -1;
            code    = -1;
            return false;
        }
        code = -1;
        return true;
    }

    /**
     * @brief SIGTERM 并等待退出；超时 SIGKILL
     * @param[out] error 失败原因；成功时清空
     * @return 在期限内正常退出时为 true
     */
    bool shutdown(std::string& error)
    {
        error.clear();
        if (reaped_) {
            return true;
        }
        if (::kill(pid_, SIGTERM) != 0 && errno != ESRCH) {
            error =
                "向子进程发 SIGTERM 失败：" + std::string(std::strerror(errno));
        }

        const bench::Clock::time_point deadline =
            bench::Clock::now() + kShutdownLimit;
        int status = 0;
        for (;;) {
            const pid_t reaped = ::waitpid(pid_, &status, WNOHANG);
            if (reaped == pid_) {
                reaped_ = true;
                code_   = exit_code_of(status);
                return error.empty();
            }
            if (reaped < 0 && errno != EINTR) {
                reaped_ = true;
                code_   = -1;
                if (error.empty()) {
                    error =
                        "等待子进程失败：" + std::string(std::strerror(errno));
                }
                return false;
            }
            if (bench::Clock::now() >= deadline) {
                (void)::kill(pid_, SIGKILL);
                (void)::waitpid(pid_, &status, 0);
                reaped_ = true;
                code_   = exit_code_of(status);
                error   = "子进程未在 20s 内退出，已 SIGKILL";
                return false;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }

    /// @brief 已退出时的退出码（非负）或终止信号（为负）；未退出时为 -1
    int exit_code() const { return code_; }

   private:
    /// @brief waitpid 状态字 → 退出码 / 终止信号
    static int exit_code_of(int status)
    {
        if (WIFEXITED(status)) {
            return WEXITSTATUS(status);
        }
        if (WIFSIGNALED(status)) {
            return -WTERMSIG(status);
        }
        return -1;
    }

    pid_t pid_;
    bool reaped_ = false;
    int code_    = -1;
};

/// @brief GetPipelineStats 的 CLI 段快照
struct CliStatsSnapshot {
    bool valid            = false;  ///< 成功取到 cli 段
    std::uint64_t dropped = 0;      ///< 所有流累计的队列拒收
    std::uint64_t active  = 0;      ///< 当前活跃流数
    std::uint64_t peak    = 0;      ///< 历史活跃流峰值
};

/**
 * @brief 取一次 GetPipelineStats 的 cli 段
 * @param[in,out] stub 客户端 stub
 * @param[out] snapshot 快照
 * @param[out] error 失败原因
 * @return 成功时为 true
 */
bool fetch_cli_stats(hng::clisv::RuntimeService::Stub& stub,
                     CliStatsSnapshot& snapshot, std::string& error)
{
    snapshot = CliStatsSnapshot{};
    grpc::ClientContext context;
    context.set_deadline(std::chrono::system_clock::now() +
                         std::chrono::seconds(10));
    hng::clisv::GetPipelineStatsRequest request;
    hng::clisv::GetPipelineStatsResponse response;
    const grpc::Status status =
        stub.GetPipelineStats(&context, request, &response);
    if (!status.ok()) {
        error = status.error_message();
        return false;
    }
    if (!response.has_stats()) {
        error = "响应缺少 stats";
        return false;
    }
    if (!response.stats().has_cli()) {
        error = "响应缺少 cli 段";
        return false;
    }
    snapshot.dropped = response.stats().cli().dropped();
    snapshot.active  = response.stats().cli().active();
    snapshot.peak    = response.stats().cli().peak();
    snapshot.valid   = true;
    error.clear();
    return true;
}

/**
 * @brief 轮询 GetPipelineStats 直到服务端应答
 * @param[in,out] stub 客户端 stub
 * @param[in,out] server 子进程句柄，用于在服务端早退时立即失败
 * @param[in] socket_path 便于报错的 socket 路径
 * @param[out] error 失败原因
 * @return 在 20s 内应答时为 true
 */
bool wait_for_server(hng::clisv::RuntimeService::Stub& stub,
                     ServerProcess& server, const std::string& socket_path,
                     std::string& error)
{
    const bench::Clock::time_point deadline = bench::Clock::now() + kReadyLimit;
    std::string last_error                  = "尚未应答";
    while (bench::Clock::now() < deadline) {
        int code = 0;
        if (!server.alive(code)) {
            error = "服务端子进程在就绪前退出（" + describe_exit(code) + "）";
            return false;
        }
        grpc::ClientContext context;
        context.set_deadline(std::chrono::system_clock::now() +
                             std::chrono::seconds(1));
        hng::clisv::GetPipelineStatsRequest request;
        hng::clisv::GetPipelineStatsResponse response;
        const grpc::Status status =
            stub.GetPipelineStats(&context, request, &response);
        if (status.ok() && response.has_stats()) {
            error.clear();
            return true;
        }
        last_error = status.ok() ? "响应缺少 stats" : status.error_message();
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    error = "服务端未在 20s 内就绪（socket=" + socket_path + "）：" + last_error;
    return false;
}

/// @brief 读取指定进程的常驻内存，单位 KiB；读取失败返回 0
std::uint64_t read_process_rss_kb(pid_t pid)
{
    std::ifstream status("/proc/" + std::to_string(pid) + "/status");
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

/// @brief 一条客户端订阅流的累计计数
struct StreamCounts {
    std::uint64_t records        = 0;  ///< 事件记录数
    std::uint64_t batch_messages = 0;  ///< batch 消息数
    std::uint64_t stats_messages = 0;  ///< stats 消息数
    std::uint64_t bytes          = 0;  ///< 响应报文的 ByteSizeLong 之和
    std::uint64_t drops          = 0;  ///< 最近一条 streamstats 的累计丢弃
};

/// @brief 一条客户端订阅流的运行状态
struct StreamState {
    std::unique_ptr<grpc::ClientContext> context;  ///< 本流独立上下文
    std::thread thread;                            ///< 收包线程
    std::atomic<pid_t> tid{0};                     ///< 收包线程的 tid
    std::atomic<bool> finished{false};             ///< 线程已退出
    std::atomic<std::uint64_t> records{0};
    std::atomic<std::uint64_t> batch_messages{0};
    std::atomic<std::uint64_t> stats_messages{0};
    std::atomic<std::uint64_t> bytes{0};
    std::atomic<std::uint64_t> drops{0};
    grpc::StatusCode code = grpc::StatusCode::OK;  ///< Finish 的状态码
    std::string message;                           ///< Finish 的错误消息
};

/// @brief 读一条客户端流的计数快照
StreamCounts read_counts(const StreamState& state)
{
    StreamCounts counts;
    counts.records        = state.records.load(std::memory_order_relaxed);
    counts.batch_messages = state.batch_messages.load(std::memory_order_relaxed);
    counts.stats_messages = state.stats_messages.load(std::memory_order_relaxed);
    counts.bytes          = state.bytes.load(std::memory_order_relaxed);
    counts.drops          = state.drops.load(std::memory_order_relaxed);
    return counts;
}

/**
 * @brief 一条客户端流的收包循环
 * @param[in,out] stub 客户端 stub
 * @param[in,out] state 本流状态；counter 字段只由本线程写
 * @param[in] batch_size 请求的批大小
 * @note 读到流结束（含被 TryCancel 取消）为止；Finish 的状态留给调用方判断。
 */
void run_stream(hng::clisv::RuntimeService::Stub& stub, StreamState& state,
                std::uint32_t batch_size)
{
    state.tid.store(::gettid(), std::memory_order_release);
    hng::clisv::ReceiveEventRequest request;
    request.set_batch_size(batch_size);
    std::unique_ptr<grpc::ClientReader<hng::clisv::ReceiveEventResponse>> reader =
        stub.ReceiveEvent(state.context.get(), request);

    hng::clisv::ReceiveEventResponse message;
    while (reader->Read(&message)) {
        if (message.has_batch()) {
            const std::uint64_t index =
                state.batch_messages.fetch_add(1, std::memory_order_relaxed);
            state.records.fetch_add(
                static_cast<std::uint64_t>(message.batch().records_size()),
                std::memory_order_relaxed);
            // ByteSizeLong 会遍历整条报文；按 1/64 采样再折算，避免压测器的
            // 字节统计本身把客户端 CPU 抬高到掩盖真实瓶颈
            if (index % kBytesSampleStride == 0) {
                state.bytes.fetch_add(
                    static_cast<std::uint64_t>(message.ByteSizeLong()) *
                        kBytesSampleStride,
                    std::memory_order_relaxed);
            }
        }
        else if (message.has_stats()) {
            state.stats_messages.fetch_add(1, std::memory_order_relaxed);
            state.drops.store(message.stats().dropped_events(),
                              std::memory_order_relaxed);
        }
        message.Clear();
    }
    const grpc::Status status = reader->Finish();
    state.code                = status.error_code();
    state.message             = status.error_message();
    state.finished.store(true, std::memory_order_release);
}

/// @brief 服务端 CPU 快照
struct ServerCpuSnapshot {
    double process = 0.0;  ///< 进程总 CPU（含 gRPC 与其他线程）
    double cli_tp  = 0.0;  ///< comm 前缀 cli-tp 的线程 CPU 之和
};

/// @brief CLI 段实现
int run_cli(const bench::CommonOptions& options,
            const std::vector<std::string>& rest)
{
    CliOptions cli_options;
    std::string error;
    if (!parse_rest(rest, cli_options, error)) {
        std::fprintf(stderr, "参数错误：%s\n", error.c_str());
        std::fprintf(stderr, "cli 段选项：\n%s", kExtraHelp);
        return kExitUsage;
    }
    if (cli_options.streams > kServerMaxStreams) {
        std::fprintf(stderr,
                     "提示：--streams %d 超过服务端并发配额 %ld，"
                     "多出的流预期收到 RESOURCE_EXHAUSTED\n",
                     cli_options.streams, kServerMaxStreams);
    }
    if (options.pin_consumer >= 0 || options.pin_producer >= 0) {
        std::printf(
            "cli 段忽略 --pin-consumer/--pin-producer："
            "两侧的工作线程不在本进程内\n");
    }

    const std::string socket_path =
        cli_options.socket_path.empty()
            ? "/tmp/hng-bench-cli-" +
                  std::to_string(static_cast<long>(::getpid())) + ".sock"
            : cli_options.socket_path;
    const bool owns_socket = cli_options.socket_path.empty();
    if (owns_socket) {
        (void)::unlink(socket_path.c_str());
    }

    const std::uint32_t batch = static_cast<std::uint32_t>(cli_options.batch);
    const double stream_count = static_cast<double>(cli_options.streams);
    const double per_stream_rate =
        options.rate > 0.0 ? options.rate / stream_count : 0.0;
    const int queue_capacity = options.queue;

    // 子进程必须在任何线程创建之前 fork；替身引擎与 userver 都会建线程
    std::fflush(stdout);
    std::fflush(stderr);
    const pid_t child = ::fork();
    if (child < 0) {
        std::fprintf(stderr, "fork 失败：%s\n", std::strerror(errno));
        return kExitRuntimeFailure;
    }
    if (child == 0) {
        run_server_child(cli_options, socket_path, queue_capacity,
                         per_stream_rate);
    }

    // 声明顺序：server 先析构（SIGTERM + waitpid），再清理由本进程创建的 socket
    ServerProcess server(child);
    struct SocketFile {
        std::string path;
        bool owned;
        ~SocketFile()
        {
            if (owned) {
                (void)::unlink(path.c_str());
            }
        }
    } socket_file{socket_path, owns_socket};

    const std::shared_ptr<grpc::Channel> channel = grpc::CreateChannel(
        "unix:" + socket_path, grpc::InsecureChannelCredentials());
    const std::unique_ptr<hng::clisv::RuntimeService::Stub> stub =
        hng::clisv::RuntimeService::NewStub(channel);

    if (!wait_for_server(*stub, server, socket_path, error)) {
        std::fprintf(stderr, "运行期失败：%s\n", error.c_str());
        return kExitRuntimeFailure;
    }

    // cli-tp 线程必须已在：本段的 us/event 用它而不是进程总 CPU
    double probe_cpu = 0.0;
    if (!bench::read_tasks_cpu(server.pid(), kCliTaskProcessor, probe_cpu,
                               error)) {
        std::fprintf(stderr, "运行期失败：%s\n", error.c_str());
        return kExitRuntimeFailure;
    }

    std::vector<std::unique_ptr<StreamState>> streams;
    streams.reserve(static_cast<std::size_t>(cli_options.streams));
    for (int index = 0; index < cli_options.streams; ++index) {
        std::unique_ptr<StreamState> state = std::make_unique<StreamState>();
        state->context = std::make_unique<grpc::ClientContext>();
        streams.push_back(std::move(state));
    }

    bool streams_stopped    = false;
    const auto stop_streams = [&streams, &streams_stopped] {
        if (streams_stopped) {
            return;
        }
        streams_stopped = true;
        for (const std::unique_ptr<StreamState>& state : streams) {
            if (state->context) {
                state->context->TryCancel();
            }
        }
        for (const std::unique_ptr<StreamState>& state : streams) {
            if (state->thread.joinable()) {
                state->thread.join();
            }
        }
    };
    const auto fail = [&stop_streams](const std::string& message) {
        stop_streams();
        std::fprintf(stderr, "运行期失败：%s\n", message.c_str());
        return kExitRuntimeFailure;
    };

    const bench::Clock::time_point run_start = bench::Clock::now();
    const bench::Clock::time_point measure_start =
        run_start + std::chrono::seconds(options.warmup_seconds);
    const bench::Clock::time_point measure_end =
        measure_start + std::chrono::seconds(options.seconds);

    hng::clisv::RuntimeService::Stub* const stub_ptr = stub.get();
    try {
        for (const std::unique_ptr<StreamState>& state : streams) {
            state->thread =
                std::thread([stub_ptr, state_ptr = state.get(), batch] {
                    run_stream(*stub_ptr, *state_ptr, batch);
                });
        }
    }
    catch (const std::exception& failure) {
        stop_streams();
        throw std::runtime_error(std::string("创建客户端流线程失败：") +
                                 failure.what());
    }

    const bench::Clock::time_point tid_deadline =
        bench::Clock::now() + kTidWaitLimit;
    for (const std::unique_ptr<StreamState>& state : streams) {
        while (state->tid.load(std::memory_order_acquire) == 0) {
            if (bench::Clock::now() >= tid_deadline) {
                return fail("等待客户端流线程发布 tid 超时");
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }

    const auto sample_client_cpu = [&streams](double& total,
                                              std::string& sample_error) -> bool {
        total = 0.0;
        for (std::size_t index = 0; index < streams.size(); ++index) {
            if (streams[index]->finished.load(std::memory_order_acquire)) {
                continue;  // 线程已退出：其 CPU 已计入更早的采样点
            }
            double seconds          = 0.0;
            const std::uint64_t tid = static_cast<std::uint64_t>(
                streams[index]->tid.load(std::memory_order_acquire));
            if (!bench::read_thread_cpu(tid, seconds, sample_error)) {
                sample_error = "读取客户端流 " + std::to_string(index) +
                               " 线程 CPU 失败：" + sample_error;
                return false;
            }
            total += seconds;
        }
        return true;
    };

    const auto sample_server_cpu = [&server](ServerCpuSnapshot& snapshot,
                                             std::string& sample_error) -> bool {
        if (!bench::read_process_cpu(server.pid(), snapshot.process,
                                     sample_error)) {
            sample_error = "读取服务端进程 CPU 失败：" + sample_error;
            return false;
        }
        if (!bench::read_tasks_cpu(server.pid(), kCliTaskProcessor,
                                   snapshot.cli_tp, sample_error)) {
            sample_error = "读取服务端 cli-tp CPU 失败：" + sample_error;
            return false;
        }
        return true;
    };

    std::this_thread::sleep_until(measure_start);
    double client_cpu_start = 0.0;
    ServerCpuSnapshot server_start;
    std::vector<StreamCounts> counts_start(streams.size());
    if (!sample_client_cpu(client_cpu_start, error) ||
        !sample_server_cpu(server_start, error)) {
        return fail(error);
    }
    for (std::size_t index = 0; index < streams.size(); ++index) {
        counts_start[index] = read_counts(*streams[index]);
    }

    CliStatsSnapshot stats_pre;
    if (!fetch_cli_stats(*stub, stats_pre, error)) {
        return fail("窗口起点 GetPipelineStats 失败：" + error);
    }

    std::this_thread::sleep_until(measure_end);
    double client_cpu_end = 0.0;
    ServerCpuSnapshot server_end;
    std::vector<StreamCounts> counts_end(streams.size());
    if (!sample_client_cpu(client_cpu_end, error) ||
        !sample_server_cpu(server_end, error)) {
        return fail(error);
    }
    for (std::size_t index = 0; index < streams.size(); ++index) {
        counts_end[index] = read_counts(*streams[index]);
    }
    const std::uint64_t child_rss_kb = read_process_rss_kb(server.pid());

    CliStatsSnapshot stats_post;
    std::string stats_post_error;
    const bool stats_post_ok =
        fetch_cli_stats(*stub, stats_post, stats_post_error);

    // drops 以服务端流水线计数器为准：streamstats 在持续过载时不上报（服务端
    // 只在队列取空的分支检查并发送丢弃计数），不能作为容量判据
    std::uint64_t stats_drops = 0;
    if (stats_post_ok && stats_post.dropped >= stats_pre.dropped) {
        stats_drops = stats_post.dropped - stats_pre.dropped;
    }

    stop_streams();

    // 逐流状态：正常结束只有取消（CANCELLED）与 OK；其余按失败上报
    std::vector<std::string> stream_failures;
    for (std::size_t index = 0; index < streams.size(); ++index) {
        const grpc::StatusCode code = streams[index]->code;
        if (code == grpc::StatusCode::OK || code == grpc::StatusCode::CANCELLED) {
            continue;
        }
        stream_failures.push_back("流 " + std::to_string(index) + "：" +
                                  status_code_name(code) + "(" +
                                  std::to_string(static_cast<int>(code)) + ") " +
                                  streams[index]->message);
    }

    std::string shutdown_error;
    const bool clean_shutdown = server.shutdown(shutdown_error);
    const int child_code      = server.exit_code();

    const auto delta          = [](std::uint64_t end, std::uint64_t start) {
        return end >= start ? end - start : 0;
    };
    const auto cpu_delta = [](double end, double start) {
        return end >= start ? end - start : 0.0;
    };

    std::uint64_t records            = 0;
    std::uint64_t batch_messages     = 0;
    std::uint64_t stats_messages     = 0;
    std::uint64_t bytes              = 0;
    std::uint64_t drops              = 0;
    std::uint64_t streams_with_drops = 0;
    for (std::size_t index = 0; index < streams.size(); ++index) {
        records += delta(counts_end[index].records, counts_start[index].records);
        batch_messages += delta(counts_end[index].batch_messages,
                                counts_start[index].batch_messages);
        stats_messages += delta(counts_end[index].stats_messages,
                                counts_start[index].stats_messages);
        bytes += delta(counts_end[index].bytes, counts_start[index].bytes);
        const std::uint64_t stream_drops =
            delta(counts_end[index].drops, counts_start[index].drops);
        drops += stream_drops;
        if (stream_drops != 0) {
            ++streams_with_drops;
        }
    }

    const double window_seconds = static_cast<double>(options.seconds);
    const double events_per_s =
        window_seconds > 0.0 ? static_cast<double>(records) / window_seconds
                             : 0.0;
    const double messages_per_s =
        window_seconds > 0.0
            ? static_cast<double>(batch_messages) / window_seconds
            : 0.0;
    const double bytes_per_s =
        window_seconds > 0.0 ? static_cast<double>(bytes) / window_seconds : 0.0;
    const double events_per_message =
        batch_messages > 0
            ? static_cast<double>(records) / static_cast<double>(batch_messages)
            : 0.0;
    const double client_cpu = cpu_delta(client_cpu_end, client_cpu_start);
    const double cli_tp_cpu = cpu_delta(server_end.cli_tp, server_start.cli_tp);
    const double server_total_cpu =
        cpu_delta(server_end.process, server_start.process);
    const double client_us_per_event =
        records > 0 ? client_cpu * 1e6 / static_cast<double>(records) : 0.0;
    const double cli_tp_us_per_event =
        records > 0 ? cli_tp_cpu * 1e6 / static_cast<double>(records) : 0.0;
    const double total_us_per_event =
        records > 0 ? server_total_cpu * 1e6 / static_cast<double>(records) : 0.0;

    bench::Result result;
    result.stage  = "cli";
    result.config = "streams=" + std::to_string(cli_options.streams) +
                    ",batch=" + std::to_string(cli_options.batch) +
                    ",queue=" + std::to_string(queue_capacity);
    result.rate                    = options.rate;
    result.seconds                 = window_seconds;
    result.events                  = records;
    result.events_per_s            = events_per_s;
    result.us_per_event            = cli_tp_us_per_event;
    result.producer_us_per_event   = 0.0;
    result.producer_us_per_success = 0.0;
    // TSV 的 drops 取服务端 GetPipelineStats 增量；取不到时退回 streamstats
    result.drops                   = stats_post_ok ? stats_drops : drops;
    result.raw_drops               = result.drops;
    result.out_drops               = 0;
    result.rss_kb                  = bench::rss_kb();
    result.peak_queue              = 0;

    bench::print_human(result, options);
    std::printf("config: streams=%d batch=%u queue=%d\n", cli_options.streams,
                batch, queue_capacity);
    std::printf(
        "events/s=%.1f per-stream=%.1f messages/s=%.1f "
        "events/message=%.2f bytes/s=%.1f (1/64 采样折算)\n",
        events_per_s, events_per_s / stream_count, messages_per_s,
        events_per_message, bytes_per_s);
    if (options.rate > 0.0) {
        const double target_per_stream = options.rate / stream_count;
        const double ratio =
            target_per_stream > 0.0
                ? events_per_s / stream_count / target_per_stream * 100.0
                : 0.0;
        std::printf(
            "rate: target total=%g per-stream=%.1f actual total=%.1f "
            "per-stream=%.1f (%.2f%%)\n",
            options.rate, target_per_stream, events_per_s,
            events_per_s / stream_count, ratio);
    }
    std::printf(
        "cpu: client=%.3fs(%.2fus/event) server_cli_tp=%.3fs(%.2fus/event) "
        "server_total=%.3fs(%.2fus/event)\n",
        client_cpu, client_us_per_event, cli_tp_cpu, cli_tp_us_per_event,
        server_total_cpu, total_us_per_event);
    std::printf("rss: parent=%" PRIu64 "kB child=%" PRIu64 "kB\n", result.rss_kb,
                child_rss_kb);
    if (stats_post_ok) {
        std::printf("drops: streamstats=+%" PRIu64 " GetPipelineStats=+%" PRIu64
                    " (TSV 取服务端; cli active=%" PRIu64 "->%" PRIu64
                    " peak=%" PRIu64 ")\n",
                    drops, stats_drops, stats_pre.active, stats_post.active,
                    stats_post.peak);
        if (stats_drops != drops) {
            std::printf(
                "提示：streamstats 与 GetPipelineStats 的 drops 口径不一致"
                "（流上的 stats 可能尚未送达，或含已摘除流的计数）\n");
        }
    }
    else {
        std::printf("drops: streamstats=+%" PRIu64
                    " GetPipelineStats 不可用（%s），TSV 退回流上计数\n",
                    drops, stats_post_error.c_str());
    }
    const char* zero_drop_server =
        stats_post_ok ? (stats_drops == 0 ? "yes" : "no") : "未知";
    std::printf("per-stream drops: %" PRIu64
                "/%d 条流有丢弃；零丢: 流上=%s 服务端=%s（容量只认服务端）\n",
                streams_with_drops, cli_options.streams,
                drops == 0 ? "yes" : "no", zero_drop_server);
    if (server_total_cpu > 0.0) {
        std::printf("cpu 归属: cli-tp 占进程总 CPU 的 %.1f%%\n",
                    cli_tp_cpu / server_total_cpu * 100.0);
    }
    if (cli_tp_cpu > 0.0 && client_cpu >= cli_tp_cpu * 0.8) {
        std::printf(
            "提示：客户端 CPU %.3fs 已接近服务端 cli-tp CPU %.3fs，"
            "压测器可能成为瓶颈\n",
            client_cpu, cli_tp_cpu);
    }
    if (options.rate == 0.0) {
        std::printf(
            "提示：rate=0 为饱和模式，替身引擎全速推事件，队列必然大量拒收；"
            "容量取 0 丢的最高限速（用 --rate 扫描）\n");
    }
    if (!clean_shutdown) {
        std::printf("提示：%s\n", shutdown_error.c_str());
    }
    if (child_code != 0) {
        std::printf("警告：服务端子进程%s\n", describe_exit(child_code).c_str());
    }
    if (!stream_failures.empty()) {
        std::fprintf(stderr, "运行期失败：%zu 条流未正常结束\n",
                     stream_failures.size());
        for (const std::string& failure : stream_failures) {
            std::fprintf(stderr, "  %s\n", failure.c_str());
        }
        return kExitRuntimeFailure;
    }
    if (!clean_shutdown) {
        return kExitRuntimeFailure;
    }
    if (!bench::append_tsv(options.out_path, result)) {
        std::fprintf(
            stderr, "写 TSV 失败：%s\n",
            options.out_path.empty() ? "stdout" : options.out_path.c_str());
        return kExitRuntimeFailure;
    }
    return 0;
}

bench::StageSpec make_cli_stage()
{
    bench::StageSpec stage;
    stage.name           = "cli";
    stage.extra_help     = kExtraHelp;
    stage.requires_trace = false;
    stage.run            = &run_cli;
    return stage;
}

}  // namespace

namespace bench {

#ifdef HNG_BENCH_CLI_STAGE
const StageSpec& cli_stage()
{
    static const StageSpec stage = make_cli_stage();
    return stage;
}
#endif

}  // namespace bench
