/**
 * @file bench_cli.cc
 * @brief CLI 段压测：CLIRuntimeService::ReceiveEvent 的事件流
 * @details
 * 子进程运行 userver CLI 服务端，父进程用裸 grpc++ 客户端收流
 */

#include "test/bench/stages.hpp"
#include "test/bench/bench_trace.hpp"
#include "test/bench/cli_client.hpp"
#include "test/bench/l1_control_plane.hpp"

// #include "agent/cli_server/include/cli_server_runner.hpp"
#include "agent/context_maintainer/include/context_maintainer.hpp"
#include "agent/control_plane/include/context_service.hpp"
#include "agent/control_plane/include/process_service.hpp"
#include "agent/control_plane/include/role_service.hpp"
#include "agent/event_data/include/runtime_event.hpp"
#include "agent/runtime_engine/include/runtime_engine_component.hpp"
// this file is actually used, dont remove
#include "agent/runtime_engine/include/runtime_engine_factory.hpp"
#include "agent/runtime_engine/include/subscriber_reg_service.hpp"
#include "agent/semantic/src/semantic.hpp"
#include "agent/util/include/event_channel.hpp"
#include "agent/util/include/pipeline_stats.hpp"
#include "kernel/include/syscall_event_type.h"

#include <grpcpp/grpcpp.h>
#include <proto/cli_service.grpc.pb.h>

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
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace {

/// @brief 退出码：运行期失败
constexpr int kExitRuntimeFailure        = 1;
/// @brief 退出码：参数错误
constexpr int kExitUsage                 = 3;

/// @brief 客户端流数的解析上限；超过服务端并发配额（64）用于触发配额错误
constexpr long kMaxStreams               = 1024;
/// @brief 服务端生成的临时配置里的并发流上限
constexpr long kServerMaxStreams         = 64;
/// @brief 单批事件数的上界，与服务端钳制一致
constexpr long kMaxBatch                 = 256;
/// @brief 服务端 cli-tp 线程的 comm 前缀
constexpr char kCliTaskProcessor[]       = "cli-tp";
/// @brief 合成事件的进程镜像路径，长度约 30 字符
constexpr char kEventExe[]               = "/usr/lib/honeyghost/bench-evt";
/// @brief CLONE_NEWNS，命名空间载荷的一个 CLONE_* 位
constexpr std::uint64_t kCloneNewNs      = 0x00020000ull;
/// @brief AT_FDCWD，文件载荷的 dirfd 取值
constexpr std::int32_t kAtFdcwd          = -100;

/// @brief 引擎语义通道容量的默认值与合法区间
constexpr int kEngineQueueDefault        = 8192;
constexpr long kEngineQueueMin           = 2;
constexpr long kEngineQueueMax           = 1048576;
/// @brief 合成语料的事件条数
constexpr std::size_t kSyntheticEvents   = 4096;
/// @brief 引擎线程名；PR_SET_NAME 只保留前 15 字节，归因时用截断后的前缀
constexpr char kBenchEngineThread[]      = "hng-bench-engine";
constexpr char kBenchEngineComm[]        = "hng-bench-engin";
/// @brief 源线程名；同样按 15 字节前的窗口归因
constexpr char kBenchSourceThread[]      = "hng-bench-source";
constexpr char kBenchSourceComm[]        = "hng-bench-sourc";
/// @brief --filter role 的 roleID 集合，落在合成语料的 roleID 1..8 内
constexpr std::uint32_t kRoleFilterFirst = 1;
constexpr std::uint32_t kRoleFilterLast  = 4;
/// @brief --filter miss 的 roleID 集合，与合成语料无交集
constexpr std::uint32_t kMissFilterFirst = 9;
constexpr std::uint32_t kMissFilterLast  = 12;

/// @brief CLI 段私有选项的多行用法
constexpr const char* kExtraHelp =
    "  --streams N       number of concurrent subscription streams, 1..1024 "
    "(server default quota 64; beyond it "
    "RESOURCE_EXHAUSTED is returned) (default 1)\n"
    "  --batch N         max events per response, 1..256 (default 64)\n"
    "  --socket PATH     absolute path of the Unix socket; empty uses "
    "/tmp/hng-bench-cli-<pid>.sock\n"
    "  --server-config PATH  CLI config file handed to the child process; empty "
    "generates a temporary file"
    " (with a 64-stream limit and the --queue capacity)\n"
    "  --queue N         per-stream queue capacity, shares the common option "
    "--queue (default 8192)\n"
    "  --engine-queue N  capacity of the engine semantic channel, 2..1048576 "
    "(default 8192; L2 only)\n"
    "  --filter MODE     subscription filter none|role|miss: role takes roleID "
    "1..4, "
    "miss takes 9..12; effective under L2 only (default none)\n"
    "  --trace PATH      L2 producer replays the P0 trace instead (same as the "
    "engine stage);"
    " optional\n"
    "  this stage ignores --pin-consumer and --pin-producer; under L1 it ignores "
    "--trace and "
    "--filter.\n";

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

        if (name == "--streams") {
            std::string text;
            if (!take_value(text) ||
                !parse_integer(text, 1, kMaxStreams, options.streams)) {
                error = "--streams must be an integer in 1.." +
                        std::to_string(kMaxStreams) + ".";
                return false;
            }
            continue;
        }
        if (name == "--batch") {
            std::string text;
            if (!take_value(text) ||
                !parse_integer(text, 1, kMaxBatch, options.batch)) {
                error = "--batch must be an integer in 1.." +
                        std::to_string(kMaxBatch) + ".";
                return false;
            }
            continue;
        }
        if (name == "--engine-queue") {
            std::string text;
            if (!take_value(text) ||
                !parse_integer(text, kEngineQueueMin, kEngineQueueMax,
                               options.engine_queue)) {
                error = "--engine-queue must be an integer in " +
                        std::to_string(kEngineQueueMin) + ".." +
                        std::to_string(kEngineQueueMax) + ".";
                return false;
            }
            continue;
        }
        if (name == "--filter") {
            std::string text;
            if (!take_value(text)) {
                error = "--filter is missing a value";
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
                error = "--filter must be none|role|miss";
                return false;
            }
            continue;
        }
        if (name == "--socket") {
            if (!take_value(options.socket_path) || options.socket_path.empty() ||
                options.socket_path.front() != '/') {
                error = "--socket must be an absolute path";
                return false;
            }
            continue;
        }
        if (name == "--server-config") {
            if (!take_value(options.server_config) ||
                options.server_config.empty()) {
                error = "--server-config is missing a path";
                return false;
            }
            continue;
        }
        error = "unknown option " + name;
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
        error = "failed to open trace " + path + ": " + reader_error;
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
        error = "failed to read trace " + path + ": " + reader_error;
        return false;
    }
    if (corpus.events.empty()) {
        error = "trace " + path + " has no usable records (skipped " +
                std::to_string(corpus.skipped) + " records)";
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
                    std::fprintf(stderr, "engine thread failed: %s\n",
                                 failure.what());
                    engine_failed_.store(true, std::memory_order_release);
                }
                catch (...) {
                    std::fprintf(stderr,
                                 "engine thread failed: unknown exception\n");
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
 * @brief 子进程入口：装配 L1 或 L2 生产者并跑 CLI 服务端
 * @param[in] options 公共选项（fidelity、rate、trace）
 * @param[in] cli_options CLI 段私有选项
 * @param[in] socket_path 最终生效的 Unix socket 路径
 * @param[in] queue_capacity 每流队列容量，写进临时配置
 * @param[in] per_stream_rate L1 每条订阅流的目标事件率 Hz；0 表示全速
 * @note 调用点必须已 fork 且尚未创建任何线程：引擎、替身与 userver 都会建
 *       线程。临时配置、PDEATHSIG 与退出码由 bench::cli::run_cli_server_child
 *       处理；L2 的收尾顺序是先源线程、再引擎，最后才析构替身与维护器。
 */
[[noreturn]] void run_server_child(const bench::CommonOptions& options,
                                   const CliOptions& cli_options,
                                   const std::string& socket_path,
                                   int queue_capacity, double per_stream_rate)
{
    bench::cli::ServerConfigSpec spec;
    spec.socket_path            = socket_path;
    spec.config_path            = cli_options.server_config;
    spec.queue_capacity         = queue_capacity;
    spec.max_concurrent_streams = kServerMaxStreams;

    bench::cli::run_cli_server_child(
        spec, [&](const PreparedCliServerConfig& prepared) {
            if (options.fidelity == bench::Fidelity::L2) {
                std::vector<hng::syscall_semantic_data> corpus;
                if (options.trace_path.empty()) {
                    corpus = make_synthetic_corpus();
                }
                else {
                    TraceCorpus trace;
                    std::string trace_error;
                    if (!load_trace_corpus(options.trace_path, trace,
                                           trace_error)) {
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
                    std::fprintf(
                        stderr,
                        "engine thread failed, did not shut down cleanly\n");
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
        });
}

// ============================================================
// 父进程：客户端
// ============================================================

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

/// @brief 服务端 CPU 快照
struct ServerCpuSnapshot {
    double process = 0.0;  ///< 进程总 CPU（含 gRPC 与其他线程）
    double cli_tp  = 0.0;  ///< comm 前缀 cli-tp 的线程 CPU 之和
    double engine  = 0.0;  ///< comm 前缀 hng-bench-engine 的线程 CPU 之和
    double source  = 0.0;  ///< comm 前缀 hng-bench-source 的线程 CPU 之和
};

/// @brief CLI 段实现
int run_cli(const bench::CommonOptions& options,
            const std::vector<std::string>& rest)
{
    CliOptions cli_options;
    std::string error;
    if (!parse_rest(rest, cli_options, error)) {
        std::fprintf(stderr, "parameter error: %s\n", error.c_str());
        std::fprintf(stderr, "cli stage options:\n%s", kExtraHelp);
        return kExitUsage;
    }
    const bool l2 = options.fidelity == bench::Fidelity::L2;
    if (cli_options.streams > kServerMaxStreams) {
        std::fprintf(
            stderr,
            "hint: --streams %d exceeds the server concurrency quota %ld, "
            "the extra streams are expected to receive RESOURCE_EXHAUSTED\n",
            cli_options.streams, kServerMaxStreams);
    }
    if (options.pin_consumer >= 0 || options.pin_producer >= 0) {
        std::printf(
            "the cli stage ignores --pin-consumer/--pin-producer: "
            "worker threads live in the server child process\n");
    }
    if (!l2) {
        if (!options.trace_path.empty()) {
            std::printf(
                "hint: L1 ignores --trace, only the L2 producer replays the "
                "trace\n");
        }
        if (cli_options.filter != CliFilter::NONE) {
            std::printf(
                "hint: the L1 stub engine skips should_take, --filter has no "
                "effect\n");
        }
    }

    const std::string socket_path =
        cli_options.socket_path.empty()
            ? bench::cli::temporary_socket_path("hng-bench-cli")
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
    const pid_t child = bench::cli::fork_server_process();
    if (child < 0) {
        return kExitRuntimeFailure;
    }
    if (child == 0) {
        run_server_child(options, cli_options, socket_path, queue_capacity,
                         per_stream_rate);
    }

    // 声明顺序：server 先析构（SIGTERM + waitpid），再清理由本进程创建的 socket
    bench::cli::ServerProcess server(child);
    bench::cli::SocketFile socket_file(socket_path, owns_socket);
    bench::cli::Client client              = bench::cli::make_client(socket_path);
    hng::clisv::RuntimeService::Stub& stub = *client.stub;

    if (!bench::cli::wait_for_server(stub, server, socket_path, error)) {
        std::fprintf(stderr, "runtime failure: %s\n", error.c_str());
        return kExitRuntimeFailure;
    }

    // cli-tp 线程必须已在：本段的 us/event 用它而不是进程总 CPU
    double probe_cpu = 0.0;
    if (!bench::read_tasks_cpu(server.pid(), kCliTaskProcessor, probe_cpu,
                               error)) {
        std::fprintf(stderr, "runtime failure: %s\n", error.c_str());
        return kExitRuntimeFailure;
    }

    bench::cli::StreamList streams =
        bench::cli::make_streams(cli_options.streams);

    const auto fail = [&streams](const std::string& message) {
        bench::cli::stop_streams(streams);
        std::fprintf(stderr, "runtime failure: %s\n", message.c_str());
        return kExitRuntimeFailure;
    };

    const bench::Clock::time_point run_start = bench::Clock::now();
    const bench::Clock::time_point measure_start =
        run_start + std::chrono::seconds(options.warmup_seconds);
    const bench::Clock::time_point measure_end =
        measure_start + std::chrono::seconds(options.seconds);

    bench::cli::start_streams(stub, streams, batch, role_ids);

    if (!bench::cli::wait_stream_tids(streams)) {
        return fail("timed out waiting for client stream threads to publish tid");
    }

    const auto sample_server_cpu = [&server](ServerCpuSnapshot& snapshot,
                                             std::string& sample_error) -> bool {
        if (!bench::read_process_cpu(server.pid(), snapshot.process,
                                     sample_error)) {
            sample_error = "failed to read server process CPU: " + sample_error;
            return false;
        }
        if (!bench::read_tasks_cpu(server.pid(), kCliTaskProcessor,
                                   snapshot.cli_tp, sample_error)) {
            sample_error = "failed to read server cli-tp CPU: " + sample_error;
            return false;
        }
        snapshot.engine =
            bench::cli::thread_cpu_by_comm(server.pid(), kBenchEngineComm);
        snapshot.source =
            bench::cli::thread_cpu_by_comm(server.pid(), kBenchSourceComm);
        return true;
    };

    std::this_thread::sleep_until(measure_start);
    double client_cpu_start = 0.0;
    ServerCpuSnapshot server_start;
    std::vector<bench::cli::StreamCounts> counts_start(streams.size());
    if (!bench::cli::sample_client_cpu(streams, client_cpu_start, error) ||
        !sample_server_cpu(server_start, error)) {
        return fail(error);
    }
    for (std::size_t index = 0; index < streams.size(); ++index) {
        counts_start[index] = bench::cli::read_counts(*streams[index]);
    }

    bench::cli::PipelineStatsSnapshot stats_pre;
    if (!bench::cli::fetch_pipeline_stats(stub, stats_pre, error)) {
        return fail("GetPipelineStats at window start failed: " + error);
    }

    std::this_thread::sleep_until(measure_end);
    double client_cpu_end = 0.0;
    ServerCpuSnapshot server_end;
    std::vector<bench::cli::StreamCounts> counts_end(streams.size());
    if (!bench::cli::sample_client_cpu(streams, client_cpu_end, error) ||
        !sample_server_cpu(server_end, error)) {
        return fail(error);
    }
    for (std::size_t index = 0; index < streams.size(); ++index) {
        counts_end[index] = bench::cli::read_counts(*streams[index]);
    }
    const std::uint64_t child_rss_kb = read_process_rss_kb(server.pid());

    bench::cli::PipelineStatsSnapshot stats_post;
    std::string stats_post_error;
    const bool stats_post_ok =
        bench::cli::fetch_pipeline_stats(stub, stats_post, stats_post_error);

    // drops 以服务端流水线计数器为准：streamstats 在持续过载时不上报（服务端
    // 只在队列取空的分支检查并发送丢弃计数），不能作为容量判据
    std::uint64_t stats_drops = 0;
    if (stats_post_ok && stats_post.dropped >= stats_pre.dropped) {
        stats_drops = stats_post.dropped - stats_pre.dropped;
    }

    bench::cli::stop_streams(streams);

    // 逐流状态：正常结束只有取消（CANCELLED）与 OK；其余按失败上报
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
            "source: a single source pushes at --rate/%.0f=%.1fHz (each event "
            "fans out to all streams, "
            "--rate is the total delivery rate across all streams)\n",
            stream_count, per_stream_rate);
    }
    std::printf(
        "events/s=%.1f per-stream=%.1f messages/s=%.1f "
        "events/message=%.2f bytes/s=%.1f (scaled from 1/64 sampling)\n",
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
                l2 ? "" : " (L1 has no engine/source threads, counted as 0)");
    if (l2 && cli_options.filter == CliFilter::NONE) {
        // 无过滤时每个输入事件扇出到全部流，输入数 = 交付数 / 流数
        std::printf(
            "engine us/input≈%.2f (input = delivered / streams, fanned out to "
            "all streams)\n",
            engine_us_per_event * stream_count);
    }
    else if (l2) {
        std::printf(
            "hint: the denominator of engine us/event is delivered events; the "
            "filter changes the delivery "
            "ratio, so it cannot be used directly as the engine per-event "
            "cost\n");
    }
    if (l2) {
        std::printf(
            "fidelity: L2 (real engine thread consumes the semantic channel; the "
            "control plane Role/Context/"
            "Process are L1 stubs, ContextMaintainer is a real component)\n");
    }
    else {
        std::printf(
            "fidelity: L1 (stub engine produces per stream, skips should_take; "
            "engine/source threads do not exist)\n");
    }
    std::printf("rss: parent=%" PRIu64 "kB child=%" PRIu64 "kB\n", result.rss_kb,
                child_rss_kb);
    if (stats_post_ok) {
        std::printf("drops: streamstats=+%" PRIu64
                    " GetPipelineStats cli=+%" PRIu64
                    " (TSV uses the server; cli active=%" PRIu64 "->%" PRIu64
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
                "engine stats: GetPipelineStats has no engine section"
                " (the L1 stub is empty)\n");
        }
        if (stats_drops != drops) {
            std::printf(
                "hint: streamstats and GetPipelineStats disagree on drops"
                " (per-stream stats may not have arrived yet, or may include "
                "counts from removed streams)\n");
        }
    }
    else {
        std::printf("drops: streamstats=+%" PRIu64
                    " GetPipelineStats is unavailable (%s), TSV falls back to "
                    "per-stream counts\n",
                    drops, stats_post_error.c_str());
    }
    const char* zero_drop_server =
        stats_post_ok ? (stats_drops == 0 ? "yes" : "no") : "unknown";
    std::printf("per-stream drops: %" PRIu64
                "/%d streams have drops; zero drops: per-stream=%s server=%s "
                "(capacity is judged by the server)\n",
                streams_with_drops, cli_options.streams,
                drops == 0 ? "yes" : "no", zero_drop_server);
    if (server_total_cpu > 0.0 && l2) {
        std::printf(
            "cpu attribution: cli-tp=%.1f%% engine=%.1f%% source=%.1f%%"
            " (of the child process total CPU)\n",
            cli_tp_cpu / server_total_cpu * 100.0,
            engine_cpu / server_total_cpu * 100.0,
            source_cpu / server_total_cpu * 100.0);
    }
    else if (server_total_cpu > 0.0) {
        std::printf(
            "cpu attribution: cli-tp accounts for %.1f%% of the process total "
            "CPU\n",
            cli_tp_cpu / server_total_cpu * 100.0);
    }
    if (cli_tp_cpu > 0.0 && client_cpu >= cli_tp_cpu * 0.8) {
        std::printf(
            "hint: client CPU %.3fs is close to server cli-tp CPU %.3fs, "
            "the benchmarker may become the bottleneck\n",
            client_cpu, cli_tp_cpu);
    }
    if (l2 && cli_options.filter != CliFilter::NONE && records == 0) {
        std::printf(
            "hint: the filter let no events through; the engine side still "
            "charges per event, "
            "us/event is only meaningful when there are delivered records\n");
    }
    if (options.rate == 0.0) {
        std::printf(
            "hint: rate=0 is saturated mode, producers push events at full speed "
            "and the queue necessarily rejects a lot; "
            "capacity is the highest rate with zero drops (scan with --rate)\n");
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
    if (!clean_shutdown) {
        return kExitRuntimeFailure;
    }
    if (!bench::append_tsv(options.out_path, result)) {
        std::fprintf(
            stderr, "failed to write TSV: %s\n",
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
