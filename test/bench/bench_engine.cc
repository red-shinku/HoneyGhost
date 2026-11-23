/**
 * @file bench_engine.cc
 * @brief 引擎段压测：语义通道 → RuntimeEngineComponent → 订阅端
 * @details
 * 在测量开始前读取 raw 语料并离线语义化、常驻内存。
 * 生产者按 --rate 节拍或全速循环回放，直接以拷贝方式写入语义通道；
 * 真实引擎组件在独立线程上消费、组装运行时事件并分发给计数订阅端。
 * 控制平面各服务全部是临时替身，非真实业务，只用语料库出现过的进程
 * 做控制平面服务的数据项
 */

#include "test/bench/stages.hpp"
#include "test/bench/bench_trace.hpp"

#include "agent/context_maintainer/include/context_maintainer.hpp"
#include "agent/control_plane/include/context_service.hpp"
#include "agent/control_plane/include/process_service.hpp"
#include "agent/control_plane/include/role_service.hpp"
#include "agent/event_data/include/runtime_event.hpp"
#include "agent/event_data/include/runtime_info_filter.hpp"
#include "agent/event_data/include/syscall_event.hpp"
#include "agent/runtime_engine/include/runtime_decision_sink.hpp"
#include "agent/runtime_engine/include/runtime_engine_component.hpp"
#include "agent/runtime_engine/include/runtime_engine_factory.hpp"
#include "agent/runtime_engine/include/runtime_event_sink.hpp"
#include "agent/semantic/src/semantic.hpp"
#include "agent/util/include/event_channel.hpp"
#include "kernel/include/syscall_event_type.h"

#include <poll.h>
#include <sys/types.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <chrono>
#include <cinttypes>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <variant>
#include <vector>

namespace {

/// @brief 退出码：运行期失败
constexpr int kExitRuntimeFailure = 1;
/// @brief 退出码：参数错误
constexpr int kExitUsage          = 3;

/// @brief 取空线程轮询唤醒 fd 的间隔，仅用于防住意外丢失的唤醒
constexpr int kDrainPollMs        = 10;
/// @brief 等待工作线程退出的上限；超过后告警并再等一次
constexpr std::chrono::seconds kThreadJoinLimit(2);
/// @brief 等待工作线程发布 tid 的上限
constexpr std::chrono::milliseconds kTidWaitLimit(1000);

/// @brief 引擎段私有选项的多行用法
constexpr const char* kExtraHelp =
    "  --streams N       CLI 订阅流数，0..1024（默认 1）\n"
    "  --system-sinks K  计数系统订阅数，引擎模式 1..64；--no-engine 时忽略"
    "（默认 1）\n"
    "  --filter MODE     订阅过滤器：none|etype|role（默认 none）\n"
    "  --settled R       角色与 context 种子落定比例，0..1（默认 1）\n"
    "  --pids N          把进程身份压成 N 个（pid/ppid/target_pid 重映射，"
    "start_time 一并归一化），0 保留原值（默认 0）\n"
    "  --no-engine       只跑生产者与语义通道取空线程，测生产者天花板\n";

/// @brief 订阅过滤器模式
enum class FilterMode : std::uint8_t { NONE, ETYPE, ROLE };

/// @brief 引擎段私有选项
struct EngineOptions {
    int streams       = 1;                 ///< CLI 订阅流数
    int system_sinks  = 1;                 ///< 计数系统订阅数
    FilterMode filter = FilterMode::NONE;  ///< 订阅过滤器
    double settled    = 1.0;               ///< 种子落定比例
    int pids          = 0;                 ///< 进程身份压缩到 N 个，0 表示保留
    bool no_engine    = false;             ///< 跳过引擎
};

/// @brief 过滤器模式的命令行名字
const char* filter_name(FilterMode mode)
{
    switch (mode) {
        case FilterMode::ETYPE:
            return "etype";
        case FilterMode::ROLE:
            return "role";
        case FilterMode::NONE:
            break;
    }
    return "none";
}

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
 * @brief 解析引擎段私有选项
 * @param[in] rest 入口未识别的参数，保持原序
 * @param[out] options 解析结果
 * @param[out] error 失败原因
 * @return 解析成功时为 true
 * @note 支持 --name value 与 --name=value 两种写法。
 */
bool parse_rest(const std::vector<std::string>& rest, EngineOptions& options,
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

        if (name == "--no-engine") {
            if (has_inline) {
                error = "--no-engine 不接受取值";
                return false;
            }
            options.no_engine = true;
            continue;
        }
        if (name == "--streams") {
            std::string text;
            if (!take_value(text) ||
                !parse_integer(text, 0, 1024, options.streams)) {
                error = "--streams 需为 0..1024 的整数";
                return false;
            }
            continue;
        }
        if (name == "--system-sinks") {
            std::string text;
            if (!take_value(text) ||
                !parse_integer(text, 0, 64, options.system_sinks)) {
                error = "--system-sinks 需为 0..64 的整数";
                return false;
            }
            continue;
        }
        if (name == "--pids") {
            std::string text;
            if (!take_value(text) ||
                !parse_integer(text, 0, 1048576, options.pids)) {
                error = "--pids 需为 0..1048576 的整数";
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
        if (name == "--filter") {
            std::string text;
            if (!take_value(text)) {
                error = "--filter 缺少取值";
                return false;
            }
            if (text == "none") {
                options.filter = FilterMode::NONE;
            }
            else if (text == "etype") {
                options.filter = FilterMode::ETYPE;
            }
            else if (text == "role") {
                options.filter = FilterMode::ROLE;
            }
            else {
                error = "--filter 需为 none|etype|role";
                return false;
            }
            continue;
        }
        error = "未知选项 " + name;
        return false;
    }
    return true;
}

/// @brief 读入内存并离线语义化后的语料
struct TraceData {
    std::vector<hng::syscall_semantic_data> events;  ///< 逐条语义事件
    std::uint64_t skipped = 0;                       ///< 尺寸不合法而跳过的条数
};

/// @brief 按 head + payload 两段把语料记录拷进原始事件
void rebuild_raw(const std::vector<char>& record, struct syscall_event& raw)
{
    std::memcpy(&raw.hdr, record.data(), sizeof(raw.hdr));
    std::memcpy(reinterpret_cast<char*>(&raw) + sizeof(raw.hdr),
                record.data() + sizeof(raw.hdr), record.size() - sizeof(raw.hdr));
}

/// @brief 把非 0 pid 映射到 [1, mod]；0 是森林根哨兵，保持不变
std::uint32_t remap_pid(std::uint32_t pid, std::uint32_t mod)
{
    return pid == 0 ? 0 : ((pid - 1) % mod) + 1;
}

/// @brief 按 remap 后的 pid 归一化 start_time，使同一 pid 收敛为同一 Process
std::uint64_t remapped_start_time(std::uint32_t remapped_pid)
{
    return remapped_pid == 0 ? 0 : 1000ULL + remapped_pid;
}

/// @brief 把事件头与载荷里的 pid 类字段压缩到 mod 个身份
void remap_event(hng::syscall_semantic_data& event, std::uint32_t mod)
{
    const std::uint32_t pid    = remap_pid(event.head.pid, mod);
    const std::uint32_t ppid   = remap_pid(event.head.ppid, mod);
    event.head.pid             = pid;
    event.head.pid_start_time  = remapped_start_time(pid);
    event.head.ppid            = ppid;
    event.head.ppid_start_time = remapped_start_time(ppid);

    if (auto* payload = std::get_if<hng::process_semantic_data>(&event.data)) {
        if (payload->target_pid() != 0) {
            payload->set_target_pid(remap_pid(payload->target_pid(), mod));
        }
    }
    else if (auto* kernel = std::get_if<hng::kernel_semantic_data>(&event.data)) {
        if (kernel->target_pid() != 0) {
            kernel->set_target_pid(remap_pid(kernel->target_pid(), mod));
        }
    }
    else if (auto* signal = std::get_if<hng::signal_semantic_data>(&event.data)) {
        if (signal->target_pid() != 0) {
            signal->set_target_pid(remap_pid(signal->target_pid(), mod));
        }
        if (signal->target_tid() != 0) {
            signal->set_target_tid(remap_pid(signal->target_tid(), mod));
        }
    }
}

/**
 * @brief 读入并校验语料，逐条离线语义化
 * @param[in] path 语料路径
 * @param[in] pid_mod 非 0 时把进程身份压成 pid_mod 个并重映射 pid 类字段
 * @param[out] data 读入结果
 * @param[out] error 失败原因
 * @return 成功时为 true
 * @note 记录尺寸须不小于 syscall_event_head 且不大于 syscall_event；不合法的
 *       记录跳过并计数，全部不合法等同空语料。
 */
bool load_trace(const std::string& path, std::uint32_t pid_mod, TraceData& data,
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
            ++data.skipped;
            continue;
        }
        struct syscall_event raw{};
        rebuild_raw(record, raw);
        hng::syscall_semantic_data event;
        semantic.transform_one(raw, event);
        if (pid_mod != 0) {
            remap_event(event, pid_mod);
        }
        data.events.push_back(std::move(event));
    }
    if (!reader_error.empty()) {
        error = "读取语料 " + path + " 失败：" + reader_error;
        return false;
    }
    if (data.events.empty()) {
        error = "语料 " + path + " 没有可用记录（跳过 " +
                std::to_string(data.skipped) + " 条）";
        return false;
    }
    return true;
}

// ---- 控制平面 伪实现 替身 ----

/// @brief 进程注册通知替身：只计数
class FakeProcessJoin final : public ProcessJoinService {
   public:
    std::uint64_t registered   = 0;  ///< register_pid 次数
    std::uint64_t unregistered = 0;  ///< unregister_pid 次数

    void register_pid(hng::event_head) override { ++registered; }
    void unregister_pid(hng::Process) override { ++unregistered; }
};

/// @brief 进程镜像更新通知替身：只计数
class FakeProcessUpdate final : public ProcessUpdateService {
   public:
    std::uint64_t updates = 0;  ///< update_exe_image 次数

    void update_exe_image(hng::Process, std::string) override { ++updates; }
};

/**
 * @brief 进程查询替身
 * @details 只服务事件路径的 lookup；按 (pid, pid_start_time) 命中，返回种子
 *          时写入的镜像。resolve 与 stats 返回空。
 */
class FakeProcessLookup final : public ProcessLookupService {
   public:
    void seed(hng::Process process, std::string exe)
    {
        hng::ProcessMessage message;
        message.pid            = process.pid;
        message.pid_start_time = process.pid_start_time;
        message.exe            = std::move(exe);
        images_[process]       = std::move(message);
    }

    std::optional<hng::ProcessMessage> lookup(hng::Process process) const override
    {
        const auto it = images_.find(process);
        if (it == images_.end()) {
            return std::nullopt;
        }
        return it->second;
    }

    std::optional<hng::Process> resolve(std::uint32_t) const override
    {
        return std::nullopt;
    }

    ProcessManagerStats stats() const override { return {}; }

   private:
    std::unordered_map<hng::Process, hng::ProcessMessage> images_;
};

/// @brief 角色继承通知替身：只计数
class FakeRoleJoin final : public RoleJoinService {
   public:
    std::uint64_t binds = 0;  ///< bind_to_role 次数

    void bind_to_role(hng::Process, hng::Process) override { ++binds; }
};

/**
 * @brief 角色查询替身
 * @details pid → roleID；role(id) 总是返回 "role-label-<id>"，其余查询返回空。
 */
class FakeRoleLookup final : public RoleLookupService {
   public:
    void seed(std::uint32_t pid, std::uint32_t role_id)
    {
        role_of_pid_[pid] = role_id;
    }

    std::optional<std::uint32_t> lookup(hng::Process process) const override
    {
        const auto it = role_of_pid_.find(process.pid);
        if (it == role_of_pid_.end()) {
            return std::nullopt;
        }
        return it->second;
    }

    std::optional<hng::Role> role(std::uint32_t role_id) const override
    {
        return hng::Role{role_id, "role-label-" + std::to_string(role_id)};
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

   private:
    std::unordered_map<std::uint32_t, std::uint32_t> role_of_pid_;
};

/**
 * @brief context 查询 / 登记 / 更新替身
 * @details lookup 命中种子或引擎线程登记的 map；register_context 记入；
 *          其余空操作或空返回。表只由引擎线程写，主线程只在 run() 前读。
 */
class FakeContextService final : public ContextLookupService,
                                 public ContextJoinService,
                                 public ContextUpdateService {
   public:
    struct Key {
        hng::Process process;
        bool operator==(const Key& other) const
        {
            return process == other.process;
        }
    };
    struct KeyHash {
        std::size_t operator()(const Key& key) const
        {
            return std::hash<hng::Process>{}(key.process);
        }
    };

    void seed(hng::Process process, std::uint32_t context_id)
    {
        contexts_[Key{process}] = context_id;
    }

    std::optional<std::uint32_t> lookup(hng::Process process) const override
    {
        const auto it = contexts_.find(Key{process});
        if (it == contexts_.end()) {
            return std::nullopt;
        }
        return it->second;
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

    void register_context(hng::Process process, ContextDeriveDecision decision,
                          ContextParentRef) override
    {
        ++register_calls;
        contexts_[Key{process}] = decision.contextID;
    }

    void register_extra_context(hng::Process, std::uint32_t,
                                hng::contextattr) override
    {
    }

    void unregister_context(hng::Process process) override
    {
        contexts_.erase(Key{process});
    }

    void bind_to_ctxroot(hng::Process, ContextParentRef) override {}

    void set_attr(hng::Process, std::uint32_t, hng::contextattr) override {}

    std::uint64_t register_calls = 0;  ///< register_context 次数

   private:
    std::unordered_map<Key, std::uint32_t, KeyHash> contexts_;
};

/// @brief 种子过程与结果计数
struct SeedCounts {
    std::uint64_t processes = 0;  ///< 去重后的进程数
    std::uint64_t roles     = 0;  ///< 写入角色归属的进程数
    std::uint64_t contexts  = 0;  ///< 写入 context 归属的进程数
};

/// @brief 按哈希决定该进程是否在 --settled 比例内落定
bool settled_by_hash(std::size_t hash, double ratio)
{
    if (ratio >= 1.0) {
        return true;
    }
    if (ratio <= 0.0) {
        return false;
    }
    return static_cast<double>(hash % 1000) < ratio * 1000.0;
}

/**
 * @brief 用 corpus 出现过的进程给 L1 替身做种子
 * @param[in] events 语义事件
 * @param[in] settled 角色与 context 归属落定比例
 * @param[in,out] process_lookup 进程查询替身
 * @param[in,out] role_lookup 角色查询替身
 * @param[in,out] context_service context 替身
 * @param[out] counts 种子计数
 * @note 进程镜像对所有进程写入；角色与 context 按 settled 比例写入，未写入的
 *       查询不到，走未落定路径。pid 为 0 的森林根不参与种子。
 */
void seed_services(const std::vector<hng::syscall_semantic_data>& events,
                   double settled, FakeProcessLookup& process_lookup,
                   FakeRoleLookup& role_lookup,
                   FakeContextService& context_service, SeedCounts& counts)
{
    std::unordered_set<hng::Process> seen;
    for (const hng::syscall_semantic_data& event : events) {
        const hng::Process process{event.head.pid, event.head.pid_start_time};
        if (process.pid == 0 || !seen.insert(process).second) {
            continue;
        }
        ++counts.processes;
        process_lookup.seed(process,
                            "/usr/bin/proc-" + std::to_string(process.pid));
        const std::size_t hash = std::hash<hng::Process>{}(process);
        if (!settled_by_hash(hash, settled)) {
            continue;
        }
        role_lookup.seed(process.pid, static_cast<std::uint32_t>(hash % 8) + 1);
        context_service.seed(process, static_cast<std::uint32_t>(hash % 16) + 1);
        ++counts.roles;
        ++counts.contexts;
    }
}

// ---- 订阅端 ----

/// @brief 按过滤器模式构造一份过滤器
RuntimeInfoFilter make_filter(FilterMode mode)
{
    RuntimeInfoFilter filter;
    switch (mode) {
        case FilterMode::ETYPE:
            filter.set_etype(
                std::vector<hng::EventType>{hng::EventType::SYSCALL_EVENT});
            break;
        case FilterMode::ROLE: {
            std::vector<std::uint32_t> role_ids;
            role_ids.reserve(8);
            for (std::uint32_t role_id = 1; role_id <= 8; ++role_id) {
                role_ids.push_back(role_id);
            }
            filter.set_role(std::move(role_ids), {});
            break;
        }
        case FilterMode::NONE:
            break;
    }
    return filter;
}

/**
 * @brief CLI 订阅计数端
 * @details on_event 的形参按值，与接口一致；拷贝成本计入分发路径。
 */
class CountSink final : public RuntimeEventSink {
   public:
    explicit CountSink(RuntimeInfoFilter filter_value)
        : filter(std::move(filter_value))
    {
    }

    void on_event(const hng::RuntimeEvent) override
    {
        count_.fetch_add(1, std::memory_order_relaxed);
    }

    std::uint64_t count() const { return count_.load(std::memory_order_relaxed); }

    RuntimeInfoFilter filter;  ///< 本流持有的过滤器副本

   private:
    std::atomic<std::uint64_t> count_{0};
};

/// @brief 系统订阅计数端，同时充当事件总数计数器
class CountSystemSink final : public RuntimeDecisionSink {
   public:
    void on_event(const hng::RuntimeEvent&, const ContextDeriveDecision&) override
    {
        count_.fetch_add(1, std::memory_order_relaxed);
    }

    std::uint64_t count() const { return count_.load(std::memory_order_relaxed); }

   private:
    std::atomic<std::uint64_t> count_{0};
};

/// @brief 通道容量向上取整为 2 的幂，与 SPSC_Queue 的容量语义一致
std::size_t channel_capacity(int queue)
{
    std::size_t capacity = 1;
    while (capacity < static_cast<std::size_t>(queue)) {
        capacity <<= 1;
    }
    return capacity;
}

/**
 * @brief 持续取空并丢弃一个通道，直到写端关闭且队列取空
 * @param[in,out] reader 通道读端
 * @param[out] done 退出标志
 */
template <class T>
void drain_until_closed(hng::EventChannelReader<T>& reader,
                        std::atomic<bool>& done)
{
    T item;
    while (true) {
        if (reader.try_pop(item)) {
            continue;
        }
        if (reader.closed()) {
            break;
        }
        struct pollfd descriptor;
        descriptor.fd      = reader.fd();
        descriptor.events  = POLLIN;
        descriptor.revents = 0;
        (void)::poll(&descriptor, 1, kDrainPollMs);
    }
    done.store(true, std::memory_order_release);
}

/// @brief 等待线程退出并 join；超时返回 false 且不 join
bool wait_for_thread(std::thread& thread, const std::atomic<bool>& done,
                     std::chrono::milliseconds limit)
{
    const bench::Clock::time_point deadline = bench::Clock::now() + limit;
    while (!done.load(std::memory_order_acquire)) {
        if (bench::Clock::now() >= deadline) {
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    if (thread.joinable()) {
        thread.join();
    }
    return true;
}

/**
 * @brief 等待生产者与消费侧工作线程发布 tid
 * @param[in] producer_tid 生产者 tid
 * @param[in] consumer_tid 引擎线程或取空线程的 tid
 * @param[out] error 失败原因
 * @return 两个 tid 都发布时为 true
 * @note 最多等待 1 秒；超时后列出尚未发布的线程。
 */
bool wait_for_tids(const std::atomic<pid_t>& producer_tid,
                   const std::atomic<pid_t>& consumer_tid, std::string& error)
{
    const bench::Clock::time_point deadline = bench::Clock::now() + kTidWaitLimit;
    while (true) {
        const bool producer_ready =
            producer_tid.load(std::memory_order_acquire) != 0;
        const bool consumer_ready =
            consumer_tid.load(std::memory_order_acquire) != 0;
        if (producer_ready && consumer_ready) {
            return true;
        }
        if (bench::Clock::now() >= deadline) {
            error = "等待线程 tid 发布超时（1s）：";
            if (!producer_ready) {
                error += " producer";
            }
            if (!consumer_ready) {
                error += " engine/drain";
            }
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

/// @brief 工作线程的窗口 CPU 快照
struct CpuSnapshot {
    double producer = 0.0;  ///< 生产者线程
    double engine   = 0.0;  ///< 引擎线程
    double drain    = 0.0;  ///< 取空线程（仅 --no-engine）
};

/// @brief 窗口计数快照
struct CounterSnapshot {
    std::uint64_t system_events = 0;  ///< 系统订阅端计数之和
    std::uint64_t cli_events    = 0;  ///< CLI 订阅端计数之和
    std::uint64_t drops         = 0;  ///< 语义通道 dropped + rejected
    std::uint64_t push_calls    = 0;  ///< 生产者 push 尝试次数
    std::uint64_t push_ok       = 0;  ///< 生产者 push 成功次数
    hng::RuntimeEngineStats stats;    ///< 引擎统计快照
};

/// @brief 引擎段实现
int run_engine(const bench::CommonOptions& options,
               const std::vector<std::string>& rest)
{
    EngineOptions engine_options;
    std::string error;
    if (!parse_rest(rest, engine_options, error)) {
        std::fprintf(stderr, "参数错误：%s\n", error.c_str());
        std::fprintf(stderr, "engine 段选项：\n%s", kExtraHelp);
        return kExitUsage;
    }
    if (!engine_options.no_engine && engine_options.system_sinks == 0) {
        std::fprintf(stderr,
                     "参数错误：引擎模式至少需要 1 个系统订阅用于计数；"
                     "测生产者天花板请用 --no-engine\n");
        std::fprintf(stderr, "engine 段选项：\n%s", kExtraHelp);
        return kExitUsage;
    }

    TraceData trace;
    if (!load_trace(options.trace_path,
                    static_cast<std::uint32_t>(engine_options.pids), trace,
                    error)) {
        std::fprintf(stderr, "%s\n", error.c_str());
        return kExitRuntimeFailure;
    }

    // 通道、替身、维护器、引擎与 sink 都由本函数持有；声明顺序保证线程
    // 收尾后引擎先于通道与 sink 析构
    hng::EventChannel<hng::syscall_semantic_data> channel(
        static_cast<std::size_t>(options.queue));

    FakeProcessJoin process_join;
    FakeProcessUpdate process_update;
    FakeProcessLookup process_lookup;
    FakeRoleJoin role_join;
    FakeRoleLookup role_lookup;
    FakeContextService context_service;
    ContextMaintainer maintainer;
    maintainer.set_context_service(&context_service, &context_service,
                                   &context_service);

    SeedCounts seeds;
    if (!engine_options.no_engine) {
        seed_services(trace.events, engine_options.settled, process_lookup,
                      role_lookup, context_service, seeds);
    }

    std::vector<std::unique_ptr<CountSystemSink>> system_sinks;
    std::vector<std::unique_ptr<CountSink>> cli_sinks;
    if (!engine_options.no_engine) {
        system_sinks.reserve(
            static_cast<std::size_t>(engine_options.system_sinks));
        for (int index = 0; index < engine_options.system_sinks; ++index) {
            system_sinks.push_back(std::make_unique<CountSystemSink>());
        }
        cli_sinks.reserve(static_cast<std::size_t>(engine_options.streams));
        for (int index = 0; index < engine_options.streams; ++index) {
            cli_sinks.push_back(
                std::make_unique<CountSink>(make_filter(engine_options.filter)));
        }
    }

    std::unique_ptr<hng::RuntimeEngineComponent> engine;
    if (!engine_options.no_engine) {
        hng::RuntimeEngineOptions engine_settings;
        engine_settings.syscall_input  = &channel.reader();
        engine_settings.ctx_maintainer = &maintainer;
        engine_settings.process_join   = &process_join;
        engine_settings.process_update = &process_update;
        engine_settings.process_lookup = &process_lookup;
        engine_settings.role_join      = &role_join;
        engine_settings.role_lookup    = &role_lookup;
        try {
            engine = hng::RuntimeEngineFactory::create(engine_settings);
        }
        catch (const std::exception& failure) {
            std::fprintf(stderr, "引擎构造失败：%s\n", failure.what());
            return kExitRuntimeFailure;
        }
        for (const std::unique_ptr<CountSystemSink>& sink : system_sinks) {
            engine->add_system_sink(sink.get());
        }
        for (const std::unique_ptr<CountSink>& sink : cli_sinks) {
            if (!engine->subscriber_service().subscribe(sink.get(), sink->filter,
                                                        nullptr)) {
                std::fprintf(stderr, "订阅登记失败：引擎已停机\n");
                return kExitRuntimeFailure;
            }
        }
    }

    std::atomic<bool> producer_stop{false};
    std::atomic<std::uint64_t> push_calls{0};
    std::atomic<std::uint64_t> push_ok{0};
    std::atomic<pid_t> producer_tid{0};
    std::atomic<pid_t> consumer_tid{0};
    std::atomic<bool> consumer_done{false};
    std::atomic<bool> engine_failed{false};

    const bench::Clock::time_point run_start = bench::Clock::now();
    std::unique_ptr<bench::Pacer> pacer;
    if (options.rate > 0.0) {
        pacer = std::make_unique<bench::Pacer>(options.rate);
    }
    const bench::Clock::time_point measure_start =
        run_start + std::chrono::seconds(options.warmup_seconds);
    const bench::Clock::time_point measure_end =
        measure_start + std::chrono::seconds(options.seconds);

    std::thread producer([&] {
        producer_tid.store(::gettid(), std::memory_order_release);
        if (options.pin_producer >= 0) {
            std::string pin_error;
            if (!bench::pin_this_thread(options.pin_producer, pin_error)) {
                std::fprintf(stderr, "生产者绑核失败：%s\n", pin_error.c_str());
            }
        }
        std::uint64_t index = 0;
        while (!producer_stop.load(std::memory_order_acquire)) {
            for (const hng::syscall_semantic_data& event : trace.events) {
                if (producer_stop.load(std::memory_order_relaxed)) {
                    break;
                }
                if (pacer) {
                    (void)pacer->wait(index);
                }
                ++index;
                push_calls.fetch_add(1, std::memory_order_relaxed);
                if (channel.writer().push(event)) {
                    push_ok.fetch_add(1, std::memory_order_relaxed);
                }
            }
        }
    });

    std::thread consumer;
    if (engine_options.no_engine) {
        consumer = std::thread([&] {
            consumer_tid.store(::gettid(), std::memory_order_release);
            if (options.pin_consumer >= 0) {
                std::string pin_error;
                if (!bench::pin_this_thread(options.pin_consumer, pin_error)) {
                    std::fprintf(stderr, "取空线程绑核失败：%s\n",
                                 pin_error.c_str());
                }
            }
            drain_until_closed(channel.reader(), consumer_done);
        });
    }
    else {
        consumer = std::thread([&] {
            consumer_tid.store(::gettid(), std::memory_order_release);
            if (options.pin_consumer >= 0) {
                std::string pin_error;
                if (!bench::pin_this_thread(options.pin_consumer, pin_error)) {
                    std::fprintf(stderr, "引擎线程绑核失败：%s\n",
                                 pin_error.c_str());
                }
            }
            try {
                engine->run();
            }
            catch (const std::exception& failure) {
                std::fprintf(stderr, "引擎线程失败：%s\n", failure.what());
                engine_failed.store(true);
            }
            catch (...) {
                std::fprintf(stderr, "引擎线程失败：未知异常\n");
                engine_failed.store(true);
            }
            consumer_done.store(true, std::memory_order_release);
        });
    }

    // 收尾顺序：先停生产者，再停引擎（或关闭通道并等取空线程）
    bool threads_stopped    = false;
    const auto stop_threads = [&]() {
        if (threads_stopped) {
            return;
        }
        threads_stopped = true;
        producer_stop.store(true, std::memory_order_release);
        if (producer.joinable()) {
            producer.join();
        }
        if (engine_options.no_engine) {
            channel.writer().close();
            if (consumer.joinable() &&
                !wait_for_thread(consumer, consumer_done, kThreadJoinLimit)) {
                std::fprintf(stderr,
                             "告警：取空线程在 %lld 秒内未退出，再等一次\n",
                             static_cast<long long>(kThreadJoinLimit.count()));
                if (!wait_for_thread(consumer, consumer_done, kThreadJoinLimit)) {
                    std::fprintf(stderr, "取空线程仍未退出，退出进程\n");
                    std::_Exit(kExitRuntimeFailure);
                }
            }
        }
        else {
            engine->stop();
            if (consumer.joinable() &&
                !wait_for_thread(consumer, consumer_done, kThreadJoinLimit)) {
                std::fprintf(stderr,
                             "告警：引擎线程在 %lld 秒内未退出，再等一次\n",
                             static_cast<long long>(kThreadJoinLimit.count()));
                if (!wait_for_thread(consumer, consumer_done, kThreadJoinLimit)) {
                    std::fprintf(stderr, "引擎线程仍未退出，退出进程\n");
                    std::_Exit(kExitRuntimeFailure);
                }
            }
        }
    };

    if (!wait_for_tids(producer_tid, consumer_tid, error)) {
        std::fprintf(stderr, "%s\n", error.c_str());
        stop_threads();
        return kExitRuntimeFailure;
    }

    const auto sample_cpu = [&](CpuSnapshot& snapshot,
                                std::string& sample_error) -> bool {
        const std::uint64_t producer_id = static_cast<std::uint64_t>(
            producer_tid.load(std::memory_order_acquire));
        if (!bench::read_thread_cpu(producer_id, snapshot.producer,
                                    sample_error)) {
            sample_error = "读取生产者线程 CPU 失败：" + sample_error;
            return false;
        }
        const std::uint64_t consumer_id = static_cast<std::uint64_t>(
            consumer_tid.load(std::memory_order_acquire));
        if (engine_options.no_engine) {
            if (!bench::read_thread_cpu(consumer_id, snapshot.drain,
                                        sample_error)) {
                sample_error = "读取取空线程 CPU 失败：" + sample_error;
                return false;
            }
        }
        else if (!bench::read_thread_cpu(consumer_id, snapshot.engine,
                                         sample_error)) {
            sample_error = "读取引擎线程 CPU 失败：" + sample_error;
            return false;
        }
        return true;
    };

    const auto sample_counters = [&](CounterSnapshot& snapshot) {
        snapshot.system_events = 0;
        for (const std::unique_ptr<CountSystemSink>& sink : system_sinks) {
            snapshot.system_events += sink->count();
        }
        snapshot.cli_events = 0;
        for (const std::unique_ptr<CountSink>& sink : cli_sinks) {
            snapshot.cli_events += sink->count();
        }
        snapshot.drops = channel.reader().dropped() + channel.reader().rejected();
        snapshot.push_calls = push_calls.load(std::memory_order_relaxed);
        snapshot.push_ok    = push_ok.load(std::memory_order_relaxed);
        if (engine) {
            snapshot.stats = engine->stats();
        }
    };

    std::this_thread::sleep_until(measure_start);
    CpuSnapshot cpu_start;
    CounterSnapshot counter_start;
    if (!sample_cpu(cpu_start, error)) {
        std::fprintf(stderr, "%s\n", error.c_str());
        stop_threads();
        return kExitRuntimeFailure;
    }
    sample_counters(counter_start);

    // EventChannel::size() 只保证单线程观察；第三方线程采样可能读到瞬时
    // 不一致的 head/tail 而下溢，超出容量的样本视为无效并丢弃
    const std::size_t capacity = channel_capacity(options.queue);
    bench::OccupancySampler occupancy([&channel, capacity] {
        const std::size_t value = channel.size();
        return value <= capacity ? value : 0;
    });
    occupancy.start();

    std::this_thread::sleep_until(measure_end);
    CpuSnapshot cpu_end;
    if (!sample_cpu(cpu_end, error)) {
        occupancy.stop();
        std::fprintf(stderr, "%s\n", error.c_str());
        stop_threads();
        return kExitRuntimeFailure;
    }
    CounterSnapshot counter_end;
    sample_counters(counter_end);
    occupancy.stop();

    stop_threads();

    if (engine_failed.load(std::memory_order_acquire)) {
        std::fprintf(stderr, "引擎线程失败，未生成结果\n");
        return kExitRuntimeFailure;
    }

    const auto delta = [](std::uint64_t end, std::uint64_t start) {
        return end >= start ? end - start : 0;
    };
    const auto cpu_delta = [](double end, double start) {
        return end >= start ? end - start : 0.0;
    };

    // 每个系统 sink 都收到全量事件；K>1 时直接求和会把事件数放大 K 倍，
    // 故按 sink 数取均值。K=1 时即规格中的计数器之和。
    const std::uint64_t system_events =
        delta(counter_end.system_events, counter_start.system_events);
    const std::uint64_t events =
        engine_options.no_engine
            ? delta(counter_end.push_ok, counter_start.push_ok)
            : (engine_options.system_sinks > 0
                   ? system_events /
                         static_cast<std::uint64_t>(engine_options.system_sinks)
                   : 0);
    const std::uint64_t drops = delta(counter_end.drops, counter_start.drops);
    const std::uint64_t calls =
        delta(counter_end.push_calls, counter_start.push_calls);
    const std::uint64_t pushes_ok =
        delta(counter_end.push_ok, counter_start.push_ok);
    const std::uint64_t pushes_failed =
        calls >= pushes_ok ? calls - pushes_ok : 0;
    const std::uint64_t cli_events =
        delta(counter_end.cli_events, counter_start.cli_events);
    const std::uint64_t unsettled = delta(counter_end.stats.unsettled_events,
                                          counter_start.stats.unsettled_events);
    const std::uint64_t rejected  = delta(counter_end.stats.queue_rejected,
                                          counter_start.stats.queue_rejected);
    const std::uint64_t idle_waits =
        delta(counter_end.stats.idle_waits, counter_start.stats.idle_waits);
    const std::uint64_t syscall_dropped = delta(
        counter_end.stats.syscall_dropped, counter_start.stats.syscall_dropped);
    const double producer_cpu   = cpu_delta(cpu_end.producer, cpu_start.producer);
    const double engine_cpu     = cpu_delta(cpu_end.engine, cpu_start.engine);
    const double drain_cpu      = cpu_delta(cpu_end.drain, cpu_start.drain);
    const double window_seconds = static_cast<double>(options.seconds);

    char settled_text[32]       = {};
    std::snprintf(settled_text, sizeof(settled_text), "%g",
                  engine_options.settled);
    const std::string config =
        "streams=" + std::to_string(engine_options.streams) +
        ",system=" + std::to_string(engine_options.system_sinks) +
        ",filter=" + filter_name(engine_options.filter) +
        ",settled=" + settled_text +
        ",pids=" + std::to_string(engine_options.pids) +
        (engine_options.no_engine ? ",no-engine" : "");

    bench::Result result;
    result.stage   = "engine";
    result.config  = config;
    result.rate    = options.rate;
    result.seconds = window_seconds;
    result.events  = events;
    result.events_per_s =
        window_seconds > 0.0 ? static_cast<double>(events) / window_seconds : 0.0;
    result.us_per_event = (!engine_options.no_engine && events > 0)
                              ? engine_cpu * 1e6 / static_cast<double>(events)
                              : 0.0;
    result.producer_us_per_event =
        calls > 0 ? producer_cpu * 1e6 / static_cast<double>(calls) : 0.0;
    result.producer_us_per_success =
        pushes_ok > 0 ? producer_cpu * 1e6 / static_cast<double>(pushes_ok) : 0.0;
    result.drops          = drops;
    result.raw_drops      = drops;
    result.out_drops      = 0;
    result.rss_kb         = bench::rss_kb();
    result.peak_queue     = occupancy.peak();
    result.out_peak_queue = 0;

    bench::print_human(result, options);
    std::printf(
        "config: streams=%d system_sinks=%d filter=%s settled=%s "
        "pids=%d%s\n",
        engine_options.streams, engine_options.system_sinks,
        filter_name(engine_options.filter), settled_text, engine_options.pids,
        engine_options.no_engine ? " no-engine" : "");
    if (!engine_options.no_engine) {
        std::printf("fidelity: L1（控制面为内存替身，不含锁与入队成本）\n");
        std::printf("engine stats: unsettled_events=+%" PRIu64
                    " peak_cli_streams=%" PRIu64 " queue_rejected=+%" PRIu64
                    " idle_waits=+%" PRIu64 " syscall_dropped=+%" PRIu64
                    " cli_events=+%" PRIu64 "\n",
                    unsettled, counter_end.stats.peak_cli_streams, rejected,
                    idle_waits, syscall_dropped, cli_events);
    }
    std::printf("peak_queue=%" PRIu64
                " (semantic channel, capacity=%zu) "
                "rss_kb=%" PRIu64 "\n",
                result.peak_queue, capacity, result.rss_kb);
    std::printf("pacer overruns=%" PRIu64 " push_calls=%" PRIu64
                " push_failed=%" PRIu64 " skipped=%" PRIu64
                " seeds: processes=%" PRIu64 " roles=%" PRIu64
                " contexts=%" PRIu64 " context_registers=%" PRIu64 "\n",
                pacer ? pacer->overruns() : 0, calls, pushes_failed,
                trace.skipped, seeds.processes, seeds.roles, seeds.contexts,
                context_service.register_calls);
    std::printf("window cpu: producer=%.3fs engine=%.3fs drain=%.3fs\n",
                producer_cpu, engine_cpu, drain_cpu);
    if (engine_options.no_engine) {
        std::printf("no-engine: 无语义引擎线程，events 取 push 成功数\n");
    }
    if (options.rate == 0.0 && drops > 0) {
        std::printf(
            "提示：rate=0 时生产者以单核自旋重试，读数含缓存行争用；"
            "容量请取 0 丢的最高限速（用 --rate 扫描）\n");
    }
    if (!bench::append_tsv(options.out_path, result)) {
        std::fprintf(
            stderr, "写 TSV 失败：%s\n",
            options.out_path.empty() ? "stdout" : options.out_path.c_str());
        return kExitRuntimeFailure;
    }
    return 0;
}

bench::StageSpec make_engine_stage()
{
    bench::StageSpec stage;
    stage.name           = "engine";
    stage.extra_help     = kExtraHelp;
    stage.requires_trace = true;
    stage.run            = &run_engine;
    return stage;
}

}  // namespace

namespace bench {

const StageSpec& engine_stage()
{
    static const StageSpec stage = make_engine_stage();
    return stage;
}

}  // namespace bench
