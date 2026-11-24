/**
 * @file bench_cli.cc
 * @brief CLI 段压测：CLIRuntimeService::ReceiveEvent 的事件流
 * @details
 * 子进程运行 userver CLI 服务端，父进程用裸 grpc++ 客户端收流。--fidelity l1
 * 用按流生产的替身引擎，跳过 RuntimeInfoFilter::should_take；--fidelity l2 在
 * 子进程内装配真实 RuntimeEngineComponent 与真实 ContextMaintainer（控制面其余
 * 维度为 L1 替身），源线程按 --rate/流数 的聚合节拍推入语义通道，过滤在
 * 引擎线程上生效。
 * 父进程按线程 comm 前缀归属窗口 CPU，并同时读取 GetPipelineStats 的 engine
 * 与 cli 段。
 */

#include "test/bench/stages.hpp"
#include "test/bench/bench_trace.hpp"
#include "test/bench/l1_control_plane.hpp"

#include "agent/cli_server/include/cli_server.hpp"
#include "agent/cli_server/include/cli_server_runner.hpp"
#include "agent/context_maintainer/include/context_maintainer.hpp"
#include "agent/control_plane/include/context_service.hpp"
#include "agent/control_plane/include/process_service.hpp"
#include "agent/control_plane/include/role_service.hpp"
#include "agent/event_data/include/runtime_event.hpp"
#include "agent/runtime_engine/include/runtime_engine_component.hpp"
#include "agent/runtime_engine/include/runtime_engine_factory.hpp"
#include "agent/runtime_engine/include/subscriber_reg_service.hpp"
#include "agent/semantic/src/semantic.hpp"
#include "agent/util/include/event_channel.hpp"
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

/// @brief 引擎语义通道容量的默认值与合法区间
constexpr int kEngineQueueDefault          = 8192;
constexpr long kEngineQueueMin             = 2;
constexpr long kEngineQueueMax             = 1048576;
/// @brief 合成语料的事件条数
constexpr std::size_t kSyntheticEvents     = 4096;
/// @brief 引擎线程名；PR_SET_NAME 只保留前 15 字节，归因时用截断后的前缀
constexpr char kBenchEngineThread[]        = "hng-bench-engine";
constexpr char kBenchEngineComm[]          = "hng-bench-engin";
/// @brief 源线程名；同样按 15 字节前的窗口归因
constexpr char kBenchSourceThread[]        = "hng-bench-source";
constexpr char kBenchSourceComm[]          = "hng-bench-sourc";
/// @brief --filter role 的 roleID 集合，落在合成语料的 roleID 1..8 内
constexpr std::uint32_t kRoleFilterFirst   = 1;
constexpr std::uint32_t kRoleFilterLast    = 4;
/// @brief --filter miss 的 roleID 集合，与合成语料无交集
constexpr std::uint32_t kMissFilterFirst   = 9;
constexpr std::uint32_t kMissFilterLast    = 12;

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
    "  --engine-queue N  引擎语义通道容量，2..1048576（默认 8192；仅 L2）\n"
    "  --filter MODE     订阅过滤器 none|role|miss：role 收 roleID 1..4，"
    "miss 收 9..12；仅 L2 生效（默认 none）\n"
    "  --trace PATH      L2 生产者改用 P0 语料回放（与 engine 段同法）；"
    "可选\n"
    "  本段忽略 --pin-consumer 与 --pin-producer；L1 下忽略 --trace 与 "
    "--filter。\n";

/// @brief 订阅过滤器模式；只在 L2 下随订阅请求下发
enum class CliFilter : std::uint8_t { NONE, ROLE, MISS };

/// @brief 过滤器模式的命令行名字
const char* cli_filter_name(CliFilter filter)
{
    switch (filter) {
        case CliFilter::ROLE:
            return "role";
        case CliFilter::MISS:
            return "miss";
        case CliFilter::NONE:
            break;
    }
    return "none";
}

/// @brief CLI 段私有选项
struct CliOptions {
    int streams = 1;            ///< 并发订阅流数
    int batch   = 64;           ///< 单条响应的事件数上限
    std::string socket_path;    ///< Unix socket 路径；空表示用临时路径
    std::string server_config;  ///< 交给子进程的 CLI 配置文件；空表示生成
    int engine_queue = kEngineQueueDefault;  ///< L2 引擎语义通道容量
    CliFilter filter = CliFilter::NONE;      ///< L2 订阅过滤器
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
 * @note 支持 --name value 与 --name=value 两种写法。--trace 由入口的公共
 *       选项解析，不会出现在 rest 里。
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
        if (name == "--engine-queue") {
            std::string text;
            if (!take_value(text) ||
                !parse_integer(text, kEngineQueueMin, kEngineQueueMax,
                               options.engine_queue)) {
                error = "--engine-queue 需为 " + std::to_string(kEngineQueueMin) +
                        ".." + std::to_string(kEngineQueueMax) + " 的整数";
                return false;
            }
            continue;
        }
        if (name == "--filter") {
            std::string text;
            if (!take_value(text)) {
                error = "--filter 缺少取值";
                return false;
            }
            if (text == "none") {
                options.filter = CliFilter::NONE;
            }
            else if (text == "role") {
                options.filter = CliFilter::ROLE;
            }
            else if (text == "miss") {
                options.filter = CliFilter::MISS;
            }
            else {
                error = "--filter 需为 none|role|miss";
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

/// @brief 按过滤器模式给出下发给服务端的 roleID 集合
std::vector<std::uint32_t> filter_role_ids(CliFilter filter)
{
    std::uint32_t first = 0;
    std::uint32_t last  = 0;
    switch (filter) {
        case CliFilter::ROLE:
            first = kRoleFilterFirst;
            last  = kRoleFilterLast;
            break;
        case CliFilter::MISS:
            first = kMissFilterFirst;
            last  = kMissFilterLast;
            break;
        case CliFilter::NONE:
            return {};
    }
    std::vector<std::uint32_t> roles;
    roles.reserve(static_cast<std::size_t>(last - first + 1));
    for (std::uint32_t role = first; role <= last; ++role) {
        roles.push_back(role);
    }
    return roles;
}

// ============================================================
// 子进程：L1 粗糙装配（替身引擎）
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

// ============================================================
// 子进程：L2 装配（真实引擎 + L1 控制面替身）
// ============================================================

/// @brief 按 head + payload 两段把语料记录拷进原始事件
void rebuild_raw(const std::vector<char>& record, struct syscall_event& raw)
{
    std::memcpy(&raw.hdr, record.data(), sizeof(raw.hdr));
    std::memcpy(reinterpret_cast<char*>(&raw) + sizeof(raw.hdr),
                record.data() + sizeof(raw.hdr), record.size() - sizeof(raw.hdr));
}

/// @brief 读入并离线语义化后的 P0 语料
struct TraceCorpus {
    std::vector<hng::syscall_semantic_data> events;  ///< 逐条语义事件
    std::uint64_t skipped = 0;                       ///< 尺寸不合法而跳过的条数
};

/**
 * @brief 读入并校验 P0 语料，逐条离线语义化
 * @param[in] path 语料路径
 * @param[out] corpus 读入结果
 * @param[out] error 失败原因
 * @return 成功时为 true
 * @note 记录尺寸须不小于 syscall_event_head 且不大于 syscall_event；不合法的
 *       记录跳过并计数，全部不合法等同空语料。
 */
bool load_trace_corpus(const std::string& path, TraceCorpus& corpus,
                       std::string& error)
{
    bench::TraceReader reader;
    std::string reader_error;
    if (!reader.open(path, reader_error)) {
        error = "打开语料 " + path + " 失败：" + reader_error;
        return false;
    }

    Semantic_syscall semantic;
    std::vector<char> record;
    while (reader.next(record, reader_error)) {
        if (record.size() < sizeof(struct syscall_event_head) ||
            record.size() > sizeof(struct syscall_event)) {
            ++corpus.skipped;
            continue;
        }
        struct syscall_event raw{};
        rebuild_raw(record, raw);
        hng::syscall_semantic_data event;
        semantic.transform_one(raw, event);
        corpus.events.push_back(std::move(event));
    }
    if (!reader_error.empty()) {
        error = "读取语料 " + path + " 失败：" + reader_error;
        return false;
    }
    if (corpus.events.empty()) {
        error = "语料 " + path + " 没有可用记录（跳过 " +
                std::to_string(corpus.skipped) + " 条）";
        return false;
    }
    return true;
}

/**
 * @brief 构造合成语义事件语料
 * @return 4096 条事件；子类型在 FILE/MEMORY/NETWORK/PROCESS/EXEC 间循环
 * @note 进程身份压成 8 个固定 pid，父进程压成 1 与 900；角色与 context 由
 *       调用方按语料播种。PROCESS 载荷以 "clone" 表示诞生，EXEC 的镜像与
 *       L1 播种写入的镜像同名。
 */
std::vector<hng::syscall_semantic_data> make_synthetic_corpus()
{
    std::vector<hng::syscall_semantic_data> events;
    events.reserve(kSyntheticEvents);
    for (std::size_t index = 0; index < kSyntheticEvents; ++index) {
        const std::uint32_t pid  = 1000 + static_cast<std::uint32_t>(index % 8);
        const std::uint32_t ppid = index % 2 == 0 ? 1 : 900;
        hng::syscall_semantic_data event;
        event.head.pid             = pid;
        event.head.pid_start_time  = pid * 10ull;
        event.head.ppid            = ppid;
        event.head.ppid_start_time = ppid * 10ull;
        event.head.uid             = 1000;
        event.head.euid            = 1000;
        event.head.mnt_ns          = 4026531840u;
        event.head.comm            = "hng-bench";
        event.head.type            = hng::EventType::SYSCALL_EVENT;
        switch (index % 5) {
            case 0: {
                event.head.subtype = FILE_EVENT;
                hng::file_syscall_semantic_data& payload =
                    event.data.emplace<4>();
                payload.set_syscall_name("openat");
                payload.set_path1("/etc/honeyghost/bench.conf");
                payload.set_flags(0);
                payload.set_mode(0644);
                payload.set_dirfd(kAtFdcwd);
                break;
            }
            case 1: {
                event.head.subtype                 = MEMORY_EVENT;
                hng::memory_semantic_data& payload = event.data.emplace<5>();
                payload.set_syscall_name("mmap");
                payload.set_prot(0x3);    // PROT_READ | PROT_WRITE
                payload.set_flags(0x22);  // MAP_PRIVATE | MAP_ANONYMOUS
                payload.set_length(4096);
                payload.set_fd(-1);
                payload.set_anonymous(true);
                break;
            }
            case 2: {
                event.head.subtype = NETWORK_EVENT;
                hng::network_syscall_semantic_data& payload =
                    event.data.emplace<6>();
                payload.set_syscall_name("connect");
                payload.set_family(2);    // AF_INET
                payload.set_type(1);      // SOCK_STREAM
                payload.set_protocol(6);  // IPPROTO_TCP
                payload.add_dst_ip(0x0100007fu);
                payload.set_dst_port(8080);
                payload.set_sockfd(3);
                break;
            }
            case 3: {
                event.head.subtype                  = PROCESS_EVENT;
                hng::process_semantic_data& payload = event.data.emplace<0>();
                payload.set_syscall_name("clone");
                break;
            }
            default: {
                event.head.subtype               = EXEC_EVENT;
                hng::exec_semantic_data& payload = event.data.emplace<1>();
                payload.set_syscall_name("execve");
                payload.set_invoked(kEventExe);
                payload.set_image("/usr/bin/proc-" + std::to_string(pid));
                payload.set_semantic_filename(payload.image());
                payload.set_argv0("bench-evt");
                break;
            }
        }
        events.push_back(std::move(event));
    }
    return events;
}

/**
 * @brief 流水线统计服务：engine 段取真实引擎快照
 * @details collector 与 semantic 留空；cli 段由 CLI 服务端按流表覆盖。
 */
class EngineStatsService final : public hng::PipelineStatsService {
   public:
    /// @brief 绑定引擎；引擎须活到本服务的每次 snapshot() 返回
    void bind(const hng::RuntimeEngineComponent& engine) noexcept
    {
        engine_ = &engine;
    }

    hng::PipelineStats snapshot() const override
    {
        hng::PipelineStats stats;
        if (engine_ == nullptr) {
            return stats;
        }
        const hng::RuntimeEngineStats raw = engine_->stats();
        hng::PipelineEngineStats engine;
        engine.unsettled_events = raw.unsettled_events;
        engine.peak_cli_streams = raw.peak_cli_streams;
        engine.queue_rejected   = raw.queue_rejected;
        engine.idle_waits       = raw.idle_waits;
        engine.syscall_dropped  = raw.syscall_dropped;
        stats.engine            = engine;
        return stats;
    }

   private:
    const hng::RuntimeEngineComponent* engine_ = nullptr;
};

/**
 * @brief 子进程内的真实引擎生产者
 * @details 持有语义通道、L1 控制面替身、真实 ContextMaintainer 与真实引擎；
 *          源线程按 --rate/流数 推入语义通道（每个输入事件扇出到全部流，故
 *          按此节拍时 --rate 表示全部流合计的交付率，与 L1 口径一致），引擎
 *          线程消费后分发给 CLI 订阅流。stop() 先停源线程再停引擎，保证订阅
 *          流的注销回执在引擎存活时落地；析构在 stop() 之后才回收替身与维护器。
 * @note 构造与 start() 必须在 fork 之后、任何线程创建之前调用。
 */
class EngineProducer final {
   public:
    /**
     * @param[in] rate 源线程的推入速率 Hz；0 表示全速。全部流合计的交付率
     *                 约为 rate 乘以流数，调用方按 --rate/流数 传入
     * @param[in] corpus 回放语料，由本对象接管
     * @param[in] engine_queue 语义通道容量
     * @throws std::exception 引擎构造失败
     */
    EngineProducer(double rate, std::vector<hng::syscall_semantic_data> corpus,
                   int engine_queue)
        : rate_(rate),
          corpus_(std::move(corpus)),
          channel_(static_cast<std::size_t>(engine_queue))
    {
        bench::l1::SeedCounts seeds;
        bench::l1::seed_services(corpus_, 1.0, process_lookup_, role_lookup_,
                                 context_service_, seeds);
        maintainer_.set_context_service(&context_service_, &context_service_,
                                        &context_service_);

        hng::RuntimeEngineOptions settings;
        settings.syscall_input  = &channel_.reader();
        settings.ctx_maintainer = &maintainer_;
        settings.process_join   = &process_join_;
        settings.process_update = &process_update_;
        settings.process_lookup = &process_lookup_;
        settings.role_join      = &role_join_;
        settings.role_lookup    = &role_lookup_;
        engine_                 = hng::RuntimeEngineFactory::create(settings);
        stats_.bind(*engine_);
    }

    ~EngineProducer() { stop(); }

    EngineProducer(const EngineProducer&)            = delete;
    EngineProducer& operator=(const EngineProducer&) = delete;

    /// @brief 启动引擎线程与源线程；任一线程创建失败时收尸后重新抛出
    void start()
    {
        try {
            engine_thread_ = std::thread([this] {
                (void)::prctl(PR_SET_NAME, kBenchEngineThread);
                try {
                    engine_->run();
                }
                catch (const std::exception& failure) {
                    std::fprintf(stderr, "引擎线程失败：%s\n", failure.what());
                    engine_failed_.store(true, std::memory_order_release);
                }
                catch (...) {
                    std::fprintf(stderr, "引擎线程失败：未知异常\n");
                    engine_failed_.store(true, std::memory_order_release);
                }
            });
            source_thread_ = std::thread([this] { produce(); });
        }
        catch (...) {
            stop();
            throw;
        }
    }

    /// @brief 停机：先停源线程，再停引擎；重复调用无操作
    void stop()
    {
        if (stopped_.exchange(true, std::memory_order_acq_rel)) {
            return;
        }
        source_stop_.store(true, std::memory_order_release);
        if (source_thread_.joinable()) {
            source_thread_.join();
        }
        if (engine_ != nullptr) {
            engine_->stop();
        }
        if (engine_thread_.joinable()) {
            engine_thread_.join();
        }
    }

    /// @brief 引擎的订阅登记入口
    SubscriberRegService& subscriber_service()
    {
        return engine_->subscriber_service();
    }

    /// @brief 把真实引擎统计暴露给 GetPipelineStats
    const hng::PipelineStatsService& stats_service() const { return stats_; }

    RoleLookupService& role_lookup_service() { return role_lookup_; }

    ContextLookupService& context_lookup_service() { return context_service_; }

    ProcessLookupService& process_lookup_service() { return process_lookup_; }

    /// @brief 引擎线程是否曾抛出异常
    bool engine_failed() const
    {
        return engine_failed_.load(std::memory_order_acquire);
    }

   private:
    /// @brief 源线程：按 rate_ 把语料循环推入语义通道
    void produce()
    {
        (void)::prctl(PR_SET_NAME, kBenchSourceThread);
        bench::Pacer pacer(rate_);
        std::uint64_t index = 0;
        while (!source_stop_.load(std::memory_order_acquire)) {
            for (const hng::syscall_semantic_data& event : corpus_) {
                if (source_stop_.load(std::memory_order_relaxed)) {
                    return;
                }
                if (rate_ > 0.0) {
                    (void)pacer.wait(index);
                }
                ++index;
                (void)channel_.writer().push(event);
            }
        }
    }

    double rate_;
    std::vector<hng::syscall_semantic_data> corpus_;
    hng::EventChannel<hng::syscall_semantic_data> channel_;
    bench::l1::FakeProcessJoin process_join_;
    bench::l1::FakeProcessUpdate process_update_;
    bench::l1::FakeProcessLookup process_lookup_;
    bench::l1::FakeRoleJoin role_join_;
    bench::l1::FakeRoleLookup role_lookup_;
    bench::l1::FakeContextService context_service_;
    ContextMaintainer maintainer_;
    std::unique_ptr<hng::RuntimeEngineComponent> engine_;
    EngineStatsService stats_;
    std::thread engine_thread_;
    std::thread source_thread_;
    std::atomic<bool> source_stop_{false};
    std::atomic<bool> engine_failed_{false};
    std::atomic<bool> stopped_{false};
};

/**
 * @brief 子进程入口：写临时配置、装配 L1 或 L2 生产者并跑 CLI 服务端
 * @param[in] options 公共选项（fidelity、rate、trace）
 * @param[in] cli_options CLI 段私有选项
 * @param[in] socket_path 最终生效的 Unix socket 路径
 * @param[in] queue_capacity 每流队列容量，写进临时配置
 * @param[in] per_stream_rate L1 每条订阅流的目标事件率 Hz；0 表示全速
 * @note 调用点必须已 fork 且尚未创建任何线程：引擎、替身与 userver 都会建
 *       线程。L2 的收尾顺序是先源线程、再引擎，最后才析构替身与维护器。
 */
[[noreturn]] void run_server_child(const bench::CommonOptions& options,
                                   const CliOptions& cli_options,
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
        CLIServerOptions server_options;
        server_options.unix_socket_path = socket_path;
        if (cli_options.server_config.empty()) {
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
            server_options.config_path = cli_options.server_config;
        }

        const PreparedCliServerConfig prepared =
            prepare_cli_server_config(server_options);
        if (!temporary_config.empty()) {
            ::unlink(temporary_config.c_str());
            temporary_config.clear();
        }

        if (options.fidelity == bench::Fidelity::L2) {
            std::vector<hng::syscall_semantic_data> corpus;
            if (options.trace_path.empty()) {
                corpus = make_synthetic_corpus();
            }
            else {
                TraceCorpus trace;
                std::string trace_error;
                if (!load_trace_corpus(options.trace_path, trace, trace_error)) {
                    std::fprintf(stderr, "%s\n", trace_error.c_str());
                    ::_exit(kExitRuntimeFailure);
                }
                corpus = std::move(trace.events);
            }

            EngineProducer producer(per_stream_rate, std::move(corpus),
                                    cli_options.engine_queue);
            CLIServerDeps deps;
            deps.role    = &producer.role_lookup_service();
            deps.context = &producer.context_lookup_service();
            deps.process = &producer.process_lookup_service();
            deps.subs    = &producer.subscriber_service();
            deps.stats   = &producer.stats_service();

            producer.start();
            RunCliServer(deps, prepared);
            producer.stop();  // 注销命令已在 RunCliServer 内落地
            if (producer.engine_failed()) {
                std::fprintf(stderr, "引擎线程失败，未正常收尾\n");
                ::_exit(kExitRuntimeFailure);
            }
        }
        else {
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

            RunCliServer(deps, prepared);
            engine.stop();
        }
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

/// @brief GetPipelineStats 的 CLI 段与引擎段快照
struct CliStatsSnapshot {
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
 * @param[in] role_ids 订阅的角色集合；空表示不下发角色过滤
 * @note 读到流结束（含被 TryCancel 取消）为止；Finish 的状态留给调用方判断。
 */
void run_stream(hng::clisv::RuntimeService::Stub& stub, StreamState& state,
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

/// @brief 服务端 CPU 快照
struct ServerCpuSnapshot {
    double process = 0.0;  ///< 进程总 CPU（含 gRPC 与其他线程）
    double cli_tp  = 0.0;  ///< comm 前缀 cli-tp 的线程 CPU 之和
    double engine  = 0.0;  ///< comm 前缀 hng-bench-engine 的线程 CPU 之和
    double source  = 0.0;  ///< comm 前缀 hng-bench-source 的线程 CPU 之和
};

/**
 * @brief 读一个 comm 前缀的线程 CPU；没有命中时按 0 计
 * @param[in] pid 进程号
 * @param[in] comm_prefix 已按 PR_SET_NAME 的 15 字节截断后的前缀
 * @param[out] seconds 命中线程的 CPU 时间之和
 * @note L1 没有引擎与源线程，缺失是预期状态，不报错。
 */
void read_optional_tasks_cpu(pid_t pid, const char* comm_prefix, double& seconds)
{
    std::string ignored;
    seconds = 0.0;
    if (!bench::read_tasks_cpu(pid, comm_prefix, seconds, ignored)) {
        seconds = 0.0;
    }
}

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
    const bool l2 = options.fidelity == bench::Fidelity::L2;
    if (cli_options.streams > kServerMaxStreams) {
        std::fprintf(stderr,
                     "提示：--streams %d 超过服务端并发配额 %ld，"
                     "多出的流预期收到 RESOURCE_EXHAUSTED\n",
                     cli_options.streams, kServerMaxStreams);
    }
    if (options.pin_consumer >= 0 || options.pin_producer >= 0) {
        std::printf(
            "cli 段忽略 --pin-consumer/--pin-producer："
            "工作线程在服务端子进程内\n");
    }
    if (!l2) {
        if (!options.trace_path.empty()) {
            std::printf("提示：L1 忽略 --trace，只有 L2 生产者回放语料\n");
        }
        if (cli_options.filter != CliFilter::NONE) {
            std::printf("提示：L1 的替身引擎跳过 should_take，--filter 不生效\n");
        }
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
    const std::vector<std::uint32_t> role_ids =
        l2 ? filter_role_ids(cli_options.filter) : std::vector<std::uint32_t>{};

    // 子进程必须在任何线程创建之前 fork；引擎、替身与 userver 都会建线程
    std::fflush(stdout);
    std::fflush(stderr);
    const pid_t child = ::fork();
    if (child < 0) {
        std::fprintf(stderr, "fork 失败：%s\n", std::strerror(errno));
        return kExitRuntimeFailure;
    }
    if (child == 0) {
        run_server_child(options, cli_options, socket_path, queue_capacity,
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
            state->thread = std::thread(
                [stub_ptr, state_ptr = state.get(), batch, &role_ids] {
                    run_stream(*stub_ptr, *state_ptr, batch, role_ids);
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
        read_optional_tasks_cpu(server.pid(), kBenchEngineComm, snapshot.engine);
        read_optional_tasks_cpu(server.pid(), kBenchSourceComm, snapshot.source);
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
    const double engine_cpu = cpu_delta(server_end.engine, server_start.engine);
    const double source_cpu = cpu_delta(server_end.source, server_start.source);
    const double server_total_cpu =
        cpu_delta(server_end.process, server_start.process);
    const double client_us_per_event =
        records > 0 ? client_cpu * 1e6 / static_cast<double>(records) : 0.0;
    const double cli_tp_us_per_event =
        records > 0 ? cli_tp_cpu * 1e6 / static_cast<double>(records) : 0.0;
    const double engine_us_per_event =
        records > 0 ? engine_cpu * 1e6 / static_cast<double>(records) : 0.0;
    const double total_us_per_event =
        records > 0 ? server_total_cpu * 1e6 / static_cast<double>(records) : 0.0;
    const std::uint64_t engine_drops =
        stats_post_ok && stats_post.engine_valid &&
                stats_post.syscall_dropped >= stats_pre.syscall_dropped
            ? stats_post.syscall_dropped - stats_pre.syscall_dropped
            : 0;

    std::string config = std::string("fidelity=") +
                         bench::fidelity_name(options.fidelity) +
                         ",streams=" + std::to_string(cli_options.streams) +
                         ",batch=" + std::to_string(cli_options.batch) +
                         ",queue=" + std::to_string(queue_capacity);
    if (l2) {
        config += ",engine_queue=" + std::to_string(cli_options.engine_queue) +
                  ",filter=" + cli_filter_name(cli_options.filter) + ",source=" +
                  (options.trace_path.empty() ? "synthetic" : "trace");
    }

    bench::Result result;
    result.stage                   = "cli";
    result.config                  = config;
    result.rate                    = options.rate;
    result.seconds                 = window_seconds;
    result.events                  = records;
    result.events_per_s            = events_per_s;
    result.us_per_event            = cli_tp_us_per_event;
    result.producer_us_per_event   = 0.0;
    result.producer_us_per_success = 0.0;
    // TSV 的 drops 取服务端 GetPipelineStats 的 cli 段增量；取不到时退回
    // streamstats
    result.drops                   = stats_post_ok ? stats_drops : drops;
    result.raw_drops               = result.drops;
    result.out_drops               = 0;
    result.rss_kb                  = bench::rss_kb();
    result.peak_queue              = 0;

    bench::print_human(result, options);
    std::string human_config = std::string("fidelity=") +
                               bench::fidelity_name(options.fidelity) +
                               " streams=" + std::to_string(cli_options.streams) +
                               " batch=" + std::to_string(cli_options.batch) +
                               " queue=" + std::to_string(queue_capacity);
    if (l2) {
        human_config +=
            " engine_queue=" + std::to_string(cli_options.engine_queue) +
            " filter=" + cli_filter_name(cli_options.filter) +
            " source=" + (options.trace_path.empty() ? "synthetic" : "trace");
    }
    std::printf("config: %s\n", human_config.c_str());
    if (l2) {
        std::printf(
            "source: 单源按 --rate/%.0f=%.1fHz 推入（每事件扇出到全部流，"
            "--rate 为全部流合计交付率）\n",
            stream_count, per_stream_rate);
    }
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
        "server_engine=%.3fs server_source=%.3fs server_total=%.3fs "
        "(%.2fus/event)\n",
        client_cpu, client_us_per_event, cli_tp_cpu, cli_tp_us_per_event,
        engine_cpu, source_cpu, server_total_cpu, total_us_per_event);
    std::printf("engine cpu=%.3fs(%.2fus/event) source cpu=%.3fs%s\n", engine_cpu,
                engine_us_per_event, source_cpu,
                l2 ? "" : "（L1 无引擎/源线程，按 0 计）");
    if (l2 && cli_options.filter == CliFilter::NONE) {
        // 无过滤时每个输入事件扇出到全部流，输入数 = 交付数 / 流数
        std::printf(
            "engine us/input≈%.2f（输入 = 交付 / streams，扇出到全部流）\n",
            engine_us_per_event * stream_count);
    }
    else if (l2) {
        std::printf(
            "提示：engine 的 us/event 分母是交付事件；过滤器改变了交付比例，"
            "不能直接当引擎单事件成本\n");
    }
    if (l2) {
        std::printf(
            "fidelity: L2（真实引擎线程消费语义通道；控制面 Role/Context/"
            "Process 为 L1 替身，ContextMaintainer 为真实件）\n");
    }
    else {
        std::printf(
            "fidelity: L1（替身引擎逐流生产，跳过 should_take；"
            "engine/source 线程不存在）\n");
    }
    std::printf("rss: parent=%" PRIu64 "kB child=%" PRIu64 "kB\n", result.rss_kb,
                child_rss_kb);
    if (stats_post_ok) {
        std::printf("drops: streamstats=+%" PRIu64
                    " GetPipelineStats cli=+%" PRIu64
                    " (TSV 取服务端; cli active=%" PRIu64 "->%" PRIu64
                    " peak=%" PRIu64 ")\n",
                    drops, stats_drops, stats_pre.active, stats_post.active,
                    stats_post.peak);
        if (stats_post.engine_valid) {
            std::printf(
                "engine stats: syscall_dropped=+%" PRIu64 "(now %" PRIu64
                ") queue_rejected=+%" PRIu64 " unsettled_events=+%" PRIu64
                " idle_waits=+%" PRIu64 " peak_cli_streams=%" PRIu64 "\n",
                engine_drops, stats_post.syscall_dropped,
                delta(stats_post.queue_rejected, stats_pre.queue_rejected),
                delta(stats_post.unsettled, stats_pre.unsettled),
                delta(stats_post.idle_waits, stats_pre.idle_waits),
                stats_post.peak_streams);
        }
        else {
            std::printf(
                "engine stats: GetPipelineStats 无 engine 段"
                "（L1 替身为空）\n");
        }
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
    if (server_total_cpu > 0.0 && l2) {
        std::printf(
            "cpu 归属: cli-tp=%.1f%% engine=%.1f%% source=%.1f%%"
            "（占子进程总 CPU）\n",
            cli_tp_cpu / server_total_cpu * 100.0,
            engine_cpu / server_total_cpu * 100.0,
            source_cpu / server_total_cpu * 100.0);
    }
    else if (server_total_cpu > 0.0) {
        std::printf("cpu 归属: cli-tp 占进程总 CPU 的 %.1f%%\n",
                    cli_tp_cpu / server_total_cpu * 100.0);
    }
    if (cli_tp_cpu > 0.0 && client_cpu >= cli_tp_cpu * 0.8) {
        std::printf(
            "提示：客户端 CPU %.3fs 已接近服务端 cli-tp CPU %.3fs，"
            "压测器可能成为瓶颈\n",
            client_cpu, cli_tp_cpu);
    }
    if (l2 && cli_options.filter != CliFilter::NONE && records == 0) {
        std::printf(
            "提示：过滤器未放行任何事件；引擎侧仍按每事件计费，"
            "us/event 只在有交付记录时有意义\n");
    }
    if (options.rate == 0.0) {
        std::printf(
            "提示：rate=0 为饱和模式，生产者全速推事件，队列必然大量拒收；"
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
    stage.supports_l2    = true;
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
