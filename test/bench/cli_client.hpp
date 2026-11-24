/**
 * @file cli_client.hpp
 * @brief CLI 压测的客户端、服务端进程与线程 CPU 骨架
 * @details
 * 供 cli 段与后续 chain 段共用的四组组件，按用途分节：
 * - ClientStreams：Unix socket 上的 gRPC 通道/Stub、订阅流状态与收包循环、
 *   客户端线程 CPU 汇总、流取消与回收。
 * - ServerProcess：临时 socket/CLI 配置、fork 与 PR_SET_PDEATHSIG、子进程
 *   异常退出、SIGTERM/SIGKILL 收尾与 socket 清理。
 * - PipelineStatsFetch：GetPipelineStats 的拉取与 cli/engine 段解析，以及
 *   服务端就绪轮询。
 * - ThreadCpuByComm：按 comm 前缀汇总线程 CPU，缺失按 0。
 * 全部 header-only、无全局状态，所操作对象由调用方持有。
 */

#ifndef HNG_TEST_BENCH_CLI_CLIENT_HPP_
#define HNG_TEST_BENCH_CLI_CLIENT_HPP_

#include "agent/cli_server/include/cli_server_runner.hpp"
#include "test/bench/support.hpp"

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
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace bench {
namespace cli {

// ============================================================
// ClientStreams：订阅流与客户端 CPU
// ============================================================

/// @brief 等待客户端流线程发布 tid 的上限
constexpr std::chrono::milliseconds kTidWaitLimit(2000);
/// @brief 报文尺寸的采样间隔：每 64 条 batch 消息调一次 ByteSizeLong
constexpr std::uint64_t kBytesSampleStride = 64;

/// @brief Unix socket 上的 gRPC 通道与 RuntimeService stub
struct Client {
    std::shared_ptr<grpc::Channel> channel;  ///< unix:<socket> 通道
    std::unique_ptr<hng::clisv::RuntimeService::Stub> stub;  ///< 通道上的 stub
};

/**
 * @brief 建立到 Unix socket 的 gRPC 通道与 RuntimeService stub
 * @param[in] socket_path 服务端监听的 Unix socket 绝对路径
 * @return 通道与 stub；创建通道不拨号，首个 RPC 才建立连接
 * @note 返回值须存活到所有订阅流结束；stub 持有通道的引用。
 */
inline Client make_client(const std::string& socket_path)
{
    Client client;
    client.channel = grpc::CreateChannel("unix:" + socket_path,
                                         grpc::InsecureChannelCredentials());
    client.stub    = hng::clisv::RuntimeService::NewStub(client.channel);
    return client;
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

/// @brief 一组订阅流；元素地址稳定，收包线程按元素地址取状态
using StreamList = std::vector<std::unique_ptr<StreamState>>;

/// @brief 取消全部订阅流并 join 收包线程
inline void stop_streams(StreamList& streams);

/**
 * @brief 创建 count 条订阅流状态，每条流带独立的 ClientContext
 * @param[in] count 流数，须为非负
 * @return 尚未启动线程的流集合
 */
inline StreamList make_streams(int count)
{
    StreamList streams;
    streams.reserve(static_cast<std::size_t>(count));
    for (int index = 0; index < count; ++index) {
        std::unique_ptr<StreamState> state = std::make_unique<StreamState>();
        state->context = std::make_unique<grpc::ClientContext>();
        streams.push_back(std::move(state));
    }
    return streams;
}

/**
 * @brief 读一条客户端流的计数快照
 * @param[in] state 流状态；可与收包线程并发读取
 * @return 各计数的原子快照
 */
inline StreamCounts read_counts(const StreamState& state)
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
 * @param[in,out] state 本流状态；计数字段只由本线程写
 * @param[in] batch_size 请求的批大小
 * @param[in] role_ids 订阅的角色集合；空表示不下发角色过滤
 * @note 读到流结束（含被 TryCancel 取消）为止；Finish 的状态留给调用方判断。
 *       state.context 须已创建，且在返回前不得销毁。
 */
inline void run_stream(hng::clisv::RuntimeService::Stub& stub, StreamState& state,
                       std::uint32_t batch_size,
                       const std::vector<std::uint32_t>& role_ids)
{
    state.tid.store(::gettid(), std::memory_order_release);
    hng::clisv::ReceiveEventRequest request;
    request.set_batch_size(batch_size);
    if (!role_ids.empty()) {
        hng::clisv::runtimeinfo* info = request.mutable_info();
        for (const std::uint32_t role_id : role_ids) {
            info->add_roleid(role_id);
        }
    }
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

/**
 * @brief 为每条流创建一个收包线程
 * @param[in] stub 客户端 stub，须活到线程结束
 * @param[in,out] streams 由 make_streams 创建、尚未启动线程的流集合
 * @param[in] batch_size 请求的批大小
 * @param[in] role_ids 订阅的角色集合；空表示不下发角色过滤，须活到线程结束
 * @throws std::runtime_error 线程创建失败；抛出前已取消并回收已建的流
 * @note 各线程运行到流结束或 stop_streams 取消为止。
 */
inline void start_streams(hng::clisv::RuntimeService::Stub& stub,
                          StreamList& streams, std::uint32_t batch_size,
                          const std::vector<std::uint32_t>& role_ids)
{
    try {
        for (const std::unique_ptr<StreamState>& state : streams) {
            state->thread = std::thread(
                [&stub, state_ptr = state.get(), batch_size, &role_ids] {
                    run_stream(stub, *state_ptr, batch_size, role_ids);
                });
        }
    }
    catch (const std::exception& failure) {
        stop_streams(streams);
        throw std::runtime_error(std::string("创建客户端流线程失败：") +
                                 failure.what());
    }
}

/**
 * @brief 等待每条流发布其收包线程 tid
 * @param[in] streams 已启动线程的流集合
 * @return 在 kTidWaitLimit 内全部发布时为 true
 */
inline bool wait_stream_tids(const StreamList& streams)
{
    const bench::Clock::time_point deadline = bench::Clock::now() + kTidWaitLimit;
    for (const std::unique_ptr<StreamState>& state : streams) {
        while (state->tid.load(std::memory_order_acquire) == 0) {
            if (bench::Clock::now() >= deadline) {
                return false;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }
    return true;
}

/**
 * @brief 汇总仍存活的收包线程的累计 CPU 时间
 * @param[in] streams 已启动线程的流集合
 * @param[out] total 各存活线程 utime+stime 之和，单位秒；失败时只含已读到的
 *             部分
 * @param[out] error 失败原因；失败时带流序号
 * @return 全部读取成功时为 true
 * @note 已结束的线程跳过：其 CPU 已计入更早的采样点，重复计入会重复计算。
 */
inline bool sample_client_cpu(const StreamList& streams, double& total,
                              std::string& error)
{
    total = 0.0;
    for (std::size_t index = 0; index < streams.size(); ++index) {
        if (streams[index]->finished.load(std::memory_order_acquire)) {
            continue;
        }
        double seconds          = 0.0;
        const std::uint64_t tid = static_cast<std::uint64_t>(
            streams[index]->tid.load(std::memory_order_acquire));
        if (!bench::read_thread_cpu(tid, seconds, error)) {
            error = "读取客户端流 " + std::to_string(index) + " 线程 CPU 失败：" +
                    error;
            return false;
        }
        total += seconds;
    }
    return true;
}

/**
 * @brief 取消全部订阅流并 join 收包线程
 * @param[in,out] streams 流集合
 * @note 可重复调用；调用返回后各流的 code 与 message 可读。Context 与状态
 *       对象仍由 streams 持有，最后一次采样应在调用前完成。
 */
inline void stop_streams(StreamList& streams)
{
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
}

/**
 * @brief gRPC 状态码的可读名字
 * @param[in] code 状态码
 * @return 与 grpc::StatusCode 枚举同名的常量；未知值返回 UNKNOWN_CODE
 */
inline const char* status_code_name(grpc::StatusCode code)
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

// ============================================================
// ServerProcess：子进程、临时文件与收尾
// ============================================================

/// @brief 等待子进程退出的上限；超过后 SIGKILL
constexpr std::chrono::seconds kShutdownLimit(20);
/// @brief 子进程内的运行期失败退出码
constexpr int kChildFailureExitCode = 1;

/**
 * @brief 子进程退出码/信号的可读描述
 * @param[in] code 非负为退出码，负数为终止信号
 * @return "退出码 N" 或 "信号 N"
 */
inline std::string describe_exit(int code)
{
    if (code >= 0) {
        return "退出码 " + std::to_string(code);
    }
    return "信号 " + std::to_string(-code);
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
     * @note 可重复调用；已收尸时直接返回 true。等待超时后 SIGKILL 并收尸，
     *       error 留作提示。
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

/**
 * @brief /tmp 下的临时文件路径：<prefix>-<当前进程 pid><suffix>
 * @param[in] prefix 文件名前缀，通常按用途区分
 * @param[in] suffix 后缀，含点号（如 ".sock"）
 * @return 绝对路径；不创建文件
 */
inline std::string temporary_path(const std::string& prefix, const char* suffix)
{
    return "/tmp/" + prefix + "-" +
           std::to_string(static_cast<long>(::getpid())) + suffix;
}

/**
 * @brief 默认的临时 Unix socket 路径
 * @param[in] prefix 文件名前缀
 * @return /tmp/<prefix>-<pid>.sock
 */
inline std::string temporary_socket_path(const std::string& prefix)
{
    return temporary_path(prefix, ".sock");
}

/**
 * @brief 独占的 socket 文件：析构时按 owned 决定是否删除
 * @note 不改动路径；非 owned 的 socket 由用户负责清理。
 */
class SocketFile final {
   public:
    SocketFile(std::string path, bool owned)
        : path_(std::move(path)), owned_(owned)
    {
    }

    ~SocketFile()
    {
        if (owned_) {
            (void)::unlink(path_.c_str());
        }
    }

    SocketFile(const SocketFile&)            = delete;
    SocketFile& operator=(const SocketFile&) = delete;

   private:
    std::string path_;
    bool owned_;
};

/// @brief 子进程侧的 CLI 服务端配置
struct ServerConfigSpec {
    std::string socket_path;  ///< 最终生效的 Unix socket 绝对路径
    std::string config_path;  ///< 用户提供的 CLI 配置；空表示生成临时配置
    std::string temp_prefix     = "hng-bench-cli";  ///< 临时配置的文件名前缀
    int queue_capacity          = 8192;  ///< 每流队列容量，写进临时配置
    long max_concurrent_streams = 64;    ///< 服务端并发流上限，写进临时配置
};

/**
 * @brief 准备子进程的 CLI 配置
 * @param[in] spec socket、配置来源与写进临时配置的取值
 * @return 交给 RunCliServer 的配置文本与最终 socket
 * @throws std::runtime_error 配置不可读、语法错误或取值非法（同
 *         prepare_cli_server_config）
 * @note 只能在 fork 之后、创建任何线程之前调用。config_path 为空时写
 *       /tmp 临时配置（drain_timeout 固定 5s），交给 prepare 后立即删除；
 *       prepare 抛异常时也删除。写临时文件失败会打印原因并以
 *       kChildFailureExitCode 结束进程。
 */
inline PreparedCliServerConfig prepare_child_config(const ServerConfigSpec& spec)
{
    CLIServerOptions options;
    options.unix_socket_path = spec.socket_path;
    std::string temporary_config;
    if (spec.config_path.empty()) {
        temporary_config = temporary_path(spec.temp_prefix, ".conf");
        std::ofstream file(temporary_config);
        if (!file.is_open()) {
            std::fprintf(stderr, "写临时配置 %s 失败：%s\n",
                         temporary_config.c_str(), std::strerror(errno));
            ::_exit(kChildFailureExitCode);
        }
        file << "[cli_server]\n"
             << "max_concurrent_streams = " << spec.max_concurrent_streams << "\n"
             << "queue_capacity = " << spec.queue_capacity << "\n"
             << "drain_timeout = 5s\n"
             << "socket_path = " << spec.socket_path << "\n";
        file.close();
        if (!file.good()) {
            std::fprintf(stderr, "写临时配置 %s 失败\n",
                         temporary_config.c_str());
            ::_exit(kChildFailureExitCode);
        }
        options.config_path = temporary_config;
    }
    else {
        options.config_path = spec.config_path;
    }

    PreparedCliServerConfig prepared;
    try {
        prepared = prepare_cli_server_config(options);
    }
    catch (...) {
        if (!temporary_config.empty()) {
            (void)::unlink(temporary_config.c_str());
        }
        throw;
    }
    if (!temporary_config.empty()) {
        (void)::unlink(temporary_config.c_str());
    }
    return prepared;
}

/**
 * @brief 设置父进程死亡信号 PR_SET_PDEATHSIG(SIGTERM)
 * @note 失败只向 stderr 报错，不终止子进程。
 */
inline void arm_parent_death_signal()
{
    if (::prctl(PR_SET_PDEATHSIG, SIGTERM) != 0) {
        std::fprintf(stderr, "设置 PR_SET_PDEATHSIG 失败：%s\n",
                     std::strerror(errno));
    }
}

/**
 * @brief fork 一个服务端子进程
 * @return 子进程 pid；失败时打印原因并返回 -1
 * @note 必须在创建任何线程之前调用；fork 前刷新 stdout/stderr，避免缓冲区
 *       在父子进程中重复落盘。子进程须立即走 run_cli_server_child。
 */
inline pid_t fork_server_process()
{
    std::fflush(stdout);
    std::fflush(stderr);
    const pid_t child = ::fork();
    if (child < 0) {
        std::fprintf(stderr, "fork 失败：%s\n", std::strerror(errno));
    }
    return child;
}

/**
 * @brief 子进程入口框架：设置 PDEATHSIG、准备配置、运行服务并退出
 * @param[in] spec 子进程的服务端配置
 * @param[in] run_service 接收已准备的配置并阻塞到服务收尾的可调用对象；
 *            抛异常表示失败
 * @note 只从 fork 之后的子进程调用，且调用时还没有其他线程。正常收尾以
 *       _exit(0) 结束；std::exception 会打印 "cli 服务端子进程失败" 并以
 *       kChildFailureExitCode 结束。本函数不返回。
 */
template <class RunService>
[[noreturn]] inline void run_cli_server_child(const ServerConfigSpec& spec,
                                              RunService&& run_service)
{
    arm_parent_death_signal();
    try {
        const PreparedCliServerConfig prepared = prepare_child_config(spec);
        run_service(prepared);
    }
    catch (const std::exception& failure) {
        std::fprintf(stderr, "cli 服务端子进程失败：%s\n", failure.what());
        ::_exit(kChildFailureExitCode);
    }
    ::_exit(0);
}

// ============================================================
// PipelineStatsFetch：GetPipelineStats 拉取与就绪轮询
// ============================================================

/// @brief 等待服务端就绪的上限
constexpr std::chrono::seconds kReadyLimit(20);

/// @brief GetPipelineStats 的 CLI 段与引擎段快照
struct PipelineStatsSnapshot {
    bool valid                    = false;  ///< 成功取到 cli 段
    std::uint64_t dropped         = 0;      ///< 所有流累计的队列拒收
    std::uint64_t active          = 0;      ///< 当前活跃流数
    std::uint64_t peak            = 0;      ///< 历史活跃流峰值

    bool engine_valid             = false;  ///< 成功取到 engine 段
    std::uint64_t unsettled       = 0;      ///< 累计未落定事件数
    std::uint64_t peak_streams    = 0;      ///< 峰值 CLI 订阅流数
    std::uint64_t queue_rejected  = 0;      ///< 累计命令入队被拒
    std::uint64_t idle_waits      = 0;      ///< 累计空闲等待
    std::uint64_t syscall_dropped = 0;      ///< 累计语义通道丢弃
};

/**
 * @brief 取一次 GetPipelineStats 的 cli 段与 engine 段
 * @param[in,out] stub 客户端 stub
 * @param[out] snapshot 快照；失败时重置为空
 * @param[out] error 失败原因；成功时清空
 * @return 成功时为 true
 * @note cli 段缺失视为失败；engine 段缺失时 engine_valid 为 false，仍算
 *       成功（L1 替身没有引擎统计）。
 */
inline bool fetch_pipeline_stats(hng::clisv::RuntimeService::Stub& stub,
                                 PipelineStatsSnapshot& snapshot,
                                 std::string& error)
{
    snapshot = PipelineStatsSnapshot{};
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
    if (response.stats().has_engine()) {
        const hng::clisv::engine_stats& engine = response.stats().engine();
        snapshot.unsettled                     = engine.unsettled_events();
        snapshot.peak_streams                  = engine.peak_cli_streams();
        snapshot.queue_rejected                = engine.queue_rejected();
        snapshot.idle_waits                    = engine.idle_waits();
        snapshot.syscall_dropped               = engine.syscall_dropped();
        snapshot.engine_valid                  = true;
    }
    error.clear();
    return true;
}

/**
 * @brief 轮询 GetPipelineStats 直到服务端应答
 * @param[in,out] stub 客户端 stub
 * @param[in,out] server 子进程句柄，用于在服务端早退时立即失败
 * @param[in] socket_path 便于报错的 socket 路径
 * @param[out] error 失败原因
 * @return 在 kReadyLimit 内应答时为 true
 * @note server 须已由 fork 得到且尚未 shutdown；早退时立即返回，不空等到
 *       上限。
 */
inline bool wait_for_server(hng::clisv::RuntimeService::Stub& stub,
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

// ============================================================
// ThreadCpuByComm：按 comm 前缀汇总线程 CPU
// ============================================================

/**
 * @brief 汇总一个进程内 comm 以给定前缀开头的线程的 CPU 时间
 * @param[in] pid 进程号
 * @param[in] comm_prefix 线程名前缀；PR_SET_NAME 只保留前 15 字节
 * @return 命中线程 utime+stime 之和，单位秒；无命中或读取失败为 0
 * @note 缺失不是错误：L1 没有引擎/源线程，chain 的某些段也可能没有某类
 *       线程，调用方无需区分"没有"与"0"。
 * @see bench::read_tasks_cpu
 */
inline double thread_cpu_by_comm(pid_t pid, const std::string& comm_prefix)
{
    double seconds = 0.0;
    std::string ignored;
    if (!bench::read_tasks_cpu(pid, comm_prefix, seconds, ignored)) {
        seconds = 0.0;
    }
    return seconds;
}

}  // namespace cli
}  // namespace bench

#endif  // HNG_TEST_BENCH_CLI_CLIENT_HPP_
