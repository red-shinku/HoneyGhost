/**
 * @file e2e_cli_server.cc
 * @brief CLI 服务端的端到端测试
 * @details
 * 子进程里用本文件内的粗糙装配拉起 userver 应用（替身控制平面 + 替身引擎 +
 * 假事件源），父进程用标准 gRPC 客户端经 Unix socket 断言：
 *  - 查询面：可查的 RPC 返回数据，缺口 RPC 返回 UNIMPLEMENTED，非法参数返回
 *    INVALID_ARGUMENT；
 *  - 订阅流：能收到事件；按事件类型与角色标签过滤生效；并发配额满时返回
 *    RESOURCE_EXHAUSTED；客户端断开后名额被服务端回收；
 *  - 停机：SIGTERM 后子进程在 drain-timeout 内退出。
 * @note 装配工厂与 Go 客户端尚未落地，故依赖与事件源都用替身；本程序不依赖
 * 任何测试框架。
 * @author red-shinku
 * @date 2026.10.18
 */

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <grpcpp/grpcpp.h>

#include <signal.h>
#include <spawn.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <proto/cli_service.grpc.pb.h>

#include <userver/components/minimal_component_list.hpp>
#include <userver/components/run.hpp>
#include <userver/ugrpc/server/component_list.hpp>

#include "agent/cli_server/include/cli_server.hpp"
#include "agent/control_plane/include/context_service.hpp"
#include "agent/control_plane/include/process_service.hpp"
#include "agent/control_plane/include/role_service.hpp"
#include "agent/event_data/include/runtime_event.hpp"
#include "agent/runtime_engine/include/subscriber_reg_service.hpp"
#include "agent/util/include/pipeline_stats.hpp"

namespace {

int g_fail = 0;

#define CHECK(cond, msg)                                                         \
    do {                                                                         \
        if (!(cond)) {                                                           \
            ++g_fail;                                                            \
            std::fprintf(stderr, "[FAIL] %s:%d  %s\n", __FILE__, __LINE__, msg); \
        }                                                                        \
    } while (0)

constexpr uint32_t kRoleID         = 7;
constexpr char kRoleLabel[]        = "e2e";
constexpr uint32_t kIgnoredRoleID  = kRoleID + 1;
constexpr char kIgnoredRoleLabel[] = "ignored.service";
constexpr uint32_t kPidSyscall     = 1001;
constexpr uint32_t kPidFile        = 2002;
constexpr uint32_t kContextID      = 3;
constexpr uint32_t kExtraContextID = 4;
constexpr char kEventExe[]         = "/tmp/test";

constexpr char kSocketPath[]       = "/tmp/honeyghost-cli-e2e.sock";

// ============================================================
// 子进程：粗糙装配
// ============================================================

/// 静态配置：并发流上限配成 8，多流用例可同时订阅；配额用例再开第 9 条
constexpr char kConfig[]           = R"(
components_manager:
    coro_pool:
        stack_usage_monitor_enabled: false
    task_processors:
        main-task-processor:
            worker_threads: 1
        cli-tp:
            worker_threads: 2
            # 框架只为 *-task-processor 形式的名字自动派生线程名
            thread_name: cli-tp
        fs-task-processor:
            worker_threads: 1
    default_task_processor: main-task-processor
    components:
        logging:
            fs-task-processor: fs-task-processor
            loggers:
                default:
                    file_path: '@stderr'
                    level: warning
                    overflow_behavior: discard
        grpc-server:
            unix-socket-path: /tmp/honeyghost-cli-e2e.sock
            service-defaults:
                task-processor: cli-tp
        cli-server:
            max-concurrent-streams: 8
            queue-capacity: 4096
            # 配得远大于停机等待的上限，使「活跃流不收敛」会表现为超时失败
            drain-timeout: 30s
        cli-role-service: {}
        cli-context-service: {}
        cli-process-service: {}
        cli-runtime-service: {}
)";

/// 与 kConfig 的 cli-server queue-capacity 一致：突发的积压上限即此值
constexpr std::size_t kQueueCap    = 4096;
/// 突发注入量：远大于队列容量，使队列立即溢出并累计丢弃
constexpr std::size_t kBurstEvents = 20000;

/// 替身角色查询：只认识 kRoleID，其成员固定为两个进程
class RoleStub final : public RoleLookupService {
   public:
    std::optional<uint32_t> lookup(hng::Process p) const override
    {
        if (p.pid == kPidSyscall || p.pid == kPidFile) {
            return kRoleID;
        }
        return std::nullopt;
    }

    std::optional<hng::Role> role(uint32_t roleID) const override
    {
        return hng::Role{roleID, kRoleLabel};
    }

    std::optional<hng::Process> main_process(uint32_t roleID) const override
    {
        if (roleID != kRoleID) {
            return std::nullopt;
        }
        return hng::Process{kPidSyscall, kPidSyscall * 10};
    }

    std::vector<hng::Role> roles() const override
    {
        return {hng::Role{kRoleID, kRoleLabel}};
    }

    std::vector<hng::Role> supervised_roles() const override
    {
        return {hng::Role{kRoleID, kRoleLabel}};
    }

    std::vector<hng::Role> ignore_roles() const override
    {
        return {hng::Role{kIgnoredRoleID, kIgnoredRoleLabel}};
    }

    RoleManagerStats stats() const override
    {
        RoleManagerStats s;
        s.store.rejected            = 1;
        s.store.unknown_instance    = 2;
        s.store.owner_conflict      = 3;
        s.store.anchors_removed     = 4;
        s.cgroup_read_empty         = 5;
        s.queue_rejected            = 6;
        s.bind_deferred             = 7;
        s.bind_resolved             = 8;
        s.bind_rejected             = 9;
        s.bind_expired              = 10;
        s.bind_ignored              = 11;
        s.late_adopt_rejected       = 12;
        s.tombstone_depth           = 13;
        s.dead_member_rejected      = 14;
        s.dead_anchor_rejected      = 15;
        s.store.bind_deferred       = s.bind_deferred;
        s.store.bind_resolved       = s.bind_resolved;
        s.store.bind_rejected       = s.bind_rejected;
        s.store.bind_expired        = s.bind_expired;
        s.store.bind_ignored        = s.bind_ignored;
        s.store.late_adopt_rejected = s.late_adopt_rejected;
        s.store.tombstone_depth     = s.tombstone_depth;
        return s;
    }

    std::optional<hng::role::RoleIdentity> identity(uint32_t) const override
    {
        return std::nullopt;
    }

    std::vector<hng::Process> members(uint32_t roleID) const override
    {
        if (roleID != kRoleID) {
            return {};
        }
        return {hng::Process{kPidSyscall, kPidSyscall * 10},
                hng::Process{kPidFile, kPidFile * 10}};
    }
};

class ContextStub final : public ContextLookupService {
   public:
    std::optional<uint32_t> lookup(hng::Process p) const override
    {
        if (p.pid == kPidSyscall || p.pid == kPidFile) {
            return kContextID;
        }
        return std::nullopt;
    }

    std::optional<uint32_t> lookup_extra(hng::Process p) const override
    {
        if (p.pid == kPidSyscall || p.pid == kPidFile) {
            return kExtraContextID;
        }
        return std::nullopt;
    }

    std::vector<uint32_t> contexts_by_attr(hng::contextattr attr) const override
    {
        if (attr == hng::contextattr::ATTACK) {
            return {kContextID};
        }
        if (attr == hng::contextattr::EXTRA_ATTACK) {
            return {kExtraContextID};
        }
        return {};
    }

    std::optional<ContextProcessSet> members(uint32_t contextID) const override
    {
        if (contextID != kContextID && contextID != kExtraContextID) {
            return std::nullopt;
        }
        ContextProcessSet set;
        set.root    = hng::Process{kPidSyscall, kPidSyscall * 10};
        set.members = {hng::Process{kPidSyscall, kPidSyscall * 10},
                       hng::Process{kPidFile, kPidFile * 10}};
        return set;
    }

    ContextManagerStats stats() const override
    {
        ContextManagerStats s;
        s.ctxroot_parent_unsettled = 11;
        s.unknown_unregister       = 12;
        s.pending_deferred         = 13;
        s.pending_resolved         = 14;
        s.pending_rejected         = 15;
        s.pending_expired          = 16;
        s.pending_cancelled        = 17;
        s.pending_depth            = 18;
        s.bind_orphaned            = 19;
        s.extra_orphaned           = 20;
        s.parent_missing           = 21;
        s.late_register            = 22;
        s.late_bind                = 23;
        s.duplicate_context        = 24;
        s.ownership_conflict       = 25;
        s.tombstone_hits           = 26;
        s.tombstone_depth          = 27;
        return s;
    }
};

class ProcessStub final : public ProcessLookupService {
   public:
    std::optional<hng::ProcessMessage> lookup(hng::Process) const override
    {
        return std::nullopt;
    }

    std::optional<hng::Process> resolve(uint32_t pid) const override
    {
        if (pid == kPidSyscall) {
            return hng::Process{kPidSyscall, kPidSyscall * 10};
        }
        if (pid == kPidFile) {
            return hng::Process{kPidFile, kPidFile * 10};
        }
        return std::nullopt;
    }

    ProcessManagerStats stats() const override
    {
        ProcessManagerStats s;
        s.pid_reused      = 1;
        s.stale_add       = 2;
        s.parent_missing  = 3;
        s.tombstone_depth = 4;
        return s;
    }
};

/// 替身统计源：返回固定值，供 GetPipelineStats 的字段映射断言
class StatsStub final : public hng::PipelineStatsService {
   public:
    hng::PipelineStats snapshot() const override
    {
        hng::PipelineStats stats;
        hng::CollectorLineStats line;
        line.line             = "syscall";
        line.consumed         = 10;
        line.consume_errors   = 1;
        line.channel_dropped  = 2;
        line.channel_rejected = 3;
        line.reserve_failures = 4;
        line.skipped_probes   = 5;
        line.attach_failed    = 6;
        line.pending_lost     = 9;
        line.malformed        = 10;
        line.attached         = true;
        line.polling          = false;
        stats.collector.push_back(line);

        hng::SemanticStats semantic;
        semantic.processed_syscall   = 7;
        semantic.raw_syscall_dropped = 2;
        semantic.path_unresolved     = 8;
        stats.semantic               = semantic;

        hng::PipelineEngineStats engine;
        engine.peak_cli_streams = 5;
        engine.syscall_dropped  = 6;
        stats.engine            = engine;
        return stats;
    }
};

/// 一条合成的系统调用运行时事件
/// @note 进程在 kPidSyscall 与 kPidFile 之间轮换，供按 pid 过滤的用例使用
hng::RuntimeEvent MakeEvent(uint32_t seq)
{
    const uint32_t pid = (seq % 2) == 0 ? kPidSyscall : kPidFile;

    hng::RuntimeEvent event{};
    event.runtimeInfo.process      = hng::Process{pid, pid * 10};
    event.runtimeInfo.parent       = hng::Process{1, 0};
    event.runtimeInfo.etype        = hng::EventType::SYSCALL_EVENT;
    event.runtimeInfo.subtype      = PROCESS_EVENT;
    event.runtimeInfo.roleID       = kRoleID;
    event.runtimeInfo.roleLabel    = kRoleLabel;
    event.runtimeInfo.contextID    = kContextID;
    event.runtimeInfo.exe          = kEventExe;

    event.data.head.pid            = pid;
    event.data.head.pid_start_time = pid * 10;
    event.data.head.type           = hng::EventType::SYSCALL_EVENT;
    event.data.head.subtype        = PROCESS_EVENT;
    event.data.data.emplace<0>().set_syscall_name("e2e");
    return event;
}

/// @brief 突发注入量，取自环境变量 HNG_CLI_E2E_BURST；未设置或非法时为 0
/// @note 只在子进程启动时读一次；0 表示注入关闭，行为与无此能力时一致
std::size_t BurstFromEnv()
{
    const char* raw = std::getenv("HNG_CLI_E2E_BURST");
    if (raw == nullptr || raw[0] == '\0') {
        return 0;
    }
    return static_cast<std::size_t>(std::strtoul(raw, nullptr, 10));
}

/// @brief 替身引擎：登记表加一条只读，另起线程按固定节奏合成事件
/// @note 与真实引擎的差别只在「命令线程」：这里注销与停机回执在调用方线程上
/// 同步完成，契约本身（摘表后回执、此后不再 on_event）不变
/// @note 打开 HNG_CLI_E2E_BURST 时，每次 subscribe() 在登记之后同步注入该条数的
/// 事件：消费方此时尚未开始取，队列立即溢出，供过载用例使用
class FakeEngine final : public SubscriberRegService {
   public:
    FakeEngine() : burst_(BurstFromEnv()), producer_([this] { Produce(); }) {}

    ~FakeEngine() override { stop(); }

    bool subscribe(RuntimeEventSink* sink, RuntimeInfoFilter filter,
                   UnsubscribeAck* ack) override
    {
        const RuntimeInfoFilter burst_filter = filter;
        {
            const std::lock_guard lock(mu_);
            entries_.push_back(Entry{sink, std::move(filter), ack});
        }
        InjectBurst(sink, burst_filter);
        return true;
    }

    void unsubscribe(RuntimeEventSink* sink) override
    {
        UnsubscribeAck* ack = nullptr;
        {
            const std::lock_guard lock(mu_);
            for (auto it = entries_.begin(); it != entries_.end(); ++it) {
                if (it->sink == sink) {
                    ack = it->ack;
                    entries_.erase(it);
                    break;
                }
            }
        }
        if (ack != nullptr) {
            ack->on_unsubscribed();
        }
    }

    /// @brief 停机：停止合成事件，并给表内每条流回执
    void stop()
    {
        if (stopping_.exchange(true)) {
            return;
        }
        if (producer_.joinable()) {
            producer_.join();
        }

        std::vector<Entry> entries;
        {
            const std::lock_guard lock(mu_);
            entries.swap(entries_);
        }
        for (const Entry& entry : entries) {
            if (entry.ack != nullptr) {
                entry.ack->on_unsubscribed();
            }
        }
    }

   private:
    struct Entry {
        RuntimeEventSink* sink;
        RuntimeInfoFilter filter;
        UnsubscribeAck* ack;
    };

    /// @brief 向刚登记的 sink 同步注入 burst_ 条事件
    /// @note 消费方此时尚未开始取，注入量超过队列容量的部分计入丢弃
    void InjectBurst(RuntimeEventSink* sink, const RuntimeInfoFilter& filter)
    {
        if (burst_ == 0) {
            return;
        }
        const std::lock_guard lock(mu_);
        for (std::size_t i = 0; i < burst_; ++i) {
            const hng::RuntimeEvent event = MakeEvent(static_cast<uint32_t>(i));
            if (filter.should_take(event.runtimeInfo)) {
                sink->on_event(event);
            }
        }
    }

    void Produce()
    {
        // 每 16 ms 发一小批：平均速率不变，但批量协议能观察到多条记录的批
        constexpr int kBurst = 8;
        uint32_t seq         = 0;
        while (!stopping_.load()) {
            {
                const std::lock_guard lock(mu_);
                for (int i = 0; i < kBurst; ++i) {
                    const hng::RuntimeEvent event = MakeEvent(seq++);
                    for (const Entry& entry : entries_) {
                        if (entry.filter.should_take(event.runtimeInfo)) {
                            entry.sink->on_event(event);
                        }
                    }
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(16));
        }
    }

    std::mutex mu_;
    std::vector<Entry> entries_;
    std::atomic<bool> stopping_{false};
    /// 一次订阅的突发注入量，0 表示关闭
    const std::size_t burst_;
    std::thread producer_;
};

/// 子进程入口：装配并跑 userver 应用，直到收到停机信号
[[noreturn]] void RunChild()
{
    // 替身必须在 fork 之后构造：FakeEngine 持有线程，线程不随 fork 复制
    RoleStub role;
    ContextStub context;
    ProcessStub process;
    StatsStub stats;
    FakeEngine engine;

    CLIServerDeps deps;
    deps.role    = &role;
    deps.context = &context;
    deps.process = &process;
    deps.subs    = &engine;
    deps.stats   = &stats;
    InstallCliServerDeps(deps);

    userver::components::ComponentList list =
        userver::components::MinimalComponentList();
    // 服务组件依赖 grpc-server 的中间件管线，故用官方的最小 gRPC 组件表
    list.AppendComponentList(userver::ugrpc::server::MinimalComponentList());
    AppendCliServerComponents(list);

    userver::components::Run(userver::components::InMemoryConfig{kConfig}, list);

    engine.stop();
    ::_exit(0);
}

// ============================================================
// 父进程：客户端断言
// ============================================================

using Clock = std::chrono::steady_clock;

/// gRPC 的 deadline 走 system_clock，项目内的计时走 steady_clock
void SetDeadline(grpc::ClientContext& context, std::chrono::seconds timeout)
{
    context.set_deadline(std::chrono::system_clock::now() + timeout);
}

bool WaitFor(const std::function<bool()>& pred, std::chrono::milliseconds timeout)
{
    const auto deadline = Clock::now() + timeout;
    while (Clock::now() < deadline) {
        if (pred()) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    return pred();
}

std::shared_ptr<grpc::Channel> MakeChannel()
{
    return grpc::CreateChannel("unix:" + std::string{kSocketPath},
                               grpc::InsecureChannelCredentials());
}

/// @brief 等到服务端能应答；返回 false 表示超时
bool WaitForServer(hng::clisv::RoleManagerService::Stub& stub)
{
    return WaitFor(
        [&stub] {
            grpc::ClientContext context;
            SetDeadline(context, std::chrono::seconds(1));
            hng::clisv::RM_GetProcessSetRequest request;
            request.set_roleid(kRoleID);
            hng::clisv::RM_GetProcessSetResponse response;
            return stub.GetProcessSet(&context, request, &response).ok();
        },
        std::chrono::seconds(20));
}

void run_query_face(hng::clisv::RoleManagerService::Stub& role,
                    hng::clisv::ContextManagerService::Stub& context_svc,
                    hng::clisv::ProcessManagerService::Stub& process_svc)
{
    // RM_GetProcessSet：成员来自替身，root_pid 来自 main_process
    {
        grpc::ClientContext context;
        SetDeadline(context, std::chrono::seconds(5));
        hng::clisv::RM_GetProcessSetRequest request;
        request.set_roleid(kRoleID);
        hng::clisv::RM_GetProcessSetResponse response;
        const grpc::Status status =
            role.GetProcessSet(&context, request, &response);
        CHECK(status.ok(), "GetProcessSet 应成功");
        CHECK(response.root_pid() == kPidSyscall, "root_pid 应来自 main_process");
        CHECK(response.has_pids(), "成员集非空时应设置 pids");
        CHECK(response.pids().pid_size() == 2, "成员集应有两条");
    }

    // RM_GetProcessSet：参数非法
    {
        grpc::ClientContext context;
        SetDeadline(context, std::chrono::seconds(5));
        hng::clisv::RM_GetProcessSetRequest request;
        request.set_roleid(0);
        hng::clisv::RM_GetProcessSetResponse response;
        const grpc::Status status =
            role.GetProcessSet(&context, request, &response);
        CHECK(status.error_code() == grpc::StatusCode::INVALID_ARGUMENT,
              "roleID 为 0 应返回 INVALID_ARGUMENT");
    }

    // RM_GetRoles：全部角色与监管角色
    for (const hng::clisv::RM_ShowOption option :
         {hng::clisv::RM_SHOW_ALL, hng::clisv::RM_SHOW_SUPERVISION}) {
        grpc::ClientContext context;
        SetDeadline(context, std::chrono::seconds(5));
        hng::clisv::RM_GetRolesRequest request;
        request.set_showoption(option);
        hng::clisv::RM_GetRolesResponse response;
        const grpc::Status status = role.GetRoles(&context, request, &response);
        CHECK(status.ok(), "GetRoles 应成功");
        CHECK(response.r_size() == 1 && response.r(0).roleid() == kRoleID &&
                  response.r(0).rolelabel() == kRoleLabel,
              "GetRoles 应返回替身角色");
    }

    // RM_GetRoles：忽略角色
    {
        grpc::ClientContext context;
        SetDeadline(context, std::chrono::seconds(5));
        hng::clisv::RM_GetRolesRequest request;
        request.set_showoption(hng::clisv::RM_SHOW_IGNORED);
        hng::clisv::RM_GetRolesResponse response;
        const grpc::Status status = role.GetRoles(&context, request, &response);
        CHECK(status.ok(), "GetRoles 应成功");
        CHECK(response.r_size() == 1 &&
                  response.r(0).roleid() == kIgnoredRoleID &&
                  response.r(0).rolelabel() == kIgnoredRoleLabel,
              "GetRoles 应返回被忽略角色");
    }

    {
        grpc::ClientContext context;
        SetDeadline(context, std::chrono::seconds(5));
        hng::clisv::RM_GetRolesRequest request;
        request.set_showoption(static_cast<hng::clisv::RM_ShowOption>(99));
        hng::clisv::RM_GetRolesResponse response;
        CHECK(role.GetRoles(&context, request, &response).error_code() ==
                  grpc::StatusCode::INVALID_ARGUMENT,
              "未知 showoption 应返回 INVALID_ARGUMENT");
    }

    // RM_GetContextSet：组合锚点与成员进程，含附属 context
    {
        grpc::ClientContext context;
        SetDeadline(context, std::chrono::seconds(5));
        hng::clisv::RM_GetContextSetRequest request;
        request.set_roleid(kRoleID);
        hng::clisv::RM_GetContextSetResponse response;
        const grpc::Status status =
            role.GetContextSet(&context, request, &response);
        CHECK(status.ok(), "GetContextSet 应成功");
        CHECK(response.contextid_size() == 2 &&
                  response.contextid(0) == kContextID &&
                  response.contextid(1) == kExtraContextID,
              "GetContextSet 应返回主与附属 context，并按 ID 升序");
    }

    // RM_GetStats：六个字段逐一映射
    {
        grpc::ClientContext context;
        SetDeadline(context, std::chrono::seconds(5));
        hng::clisv::RM_GetStatsRequest request;
        hng::clisv::RM_GetStatsResponse response;
        const grpc::Status status = role.GetStats(&context, request, &response);
        CHECK(status.ok(), "RM_GetStats 应成功");
        CHECK(
            response.rejected() == 1 && response.unknown_instance() == 2 &&
                response.owner_conflict() == 3 &&
                response.anchors_removed() == 4 &&
                response.cgroup_read_empty() == 5 &&
                response.queue_rejected() == 6 && response.bind_deferred() == 7 &&
                response.bind_resolved() == 8 && response.bind_rejected() == 9 &&
                response.bind_expired() == 10 && response.bind_ignored() == 11 &&
                response.late_adopt_rejected() == 12 &&
                response.tombstone_depth() == 13 &&
                response.dead_member_rejected() == 14 &&
                response.dead_anchor_rejected() == 15,
            "RM_GetStats 应映射全部字段");
    }

    // RM_WhichRole：命中、未命中、参数非法
    {
        grpc::ClientContext context;
        SetDeadline(context, std::chrono::seconds(5));
        hng::clisv::RM_WhichRoleRequest request;
        request.set_pid(kPidSyscall);
        hng::clisv::RM_WhichRoleResponse response;
        const grpc::Status status = role.WhichRole(&context, request, &response);
        CHECK(
            status.ok() && response.has_roleid() && response.roleid() == kRoleID,
            "WhichRole 应命中替身角色");
    }
    {
        grpc::ClientContext context;
        SetDeadline(context, std::chrono::seconds(5));
        hng::clisv::RM_WhichRoleRequest request;
        request.set_pid(999999);
        hng::clisv::RM_WhichRoleResponse response;
        const grpc::Status status = role.WhichRole(&context, request, &response);
        CHECK(status.ok() && !response.has_roleid(),
              "未命中应成功且不设置 roleID");
    }
    {
        grpc::ClientContext context;
        SetDeadline(context, std::chrono::seconds(5));
        hng::clisv::RM_WhichRoleRequest request;
        request.set_pid(0);
        hng::clisv::RM_WhichRoleResponse response;
        CHECK(role.WhichRole(&context, request, &response).error_code() ==
                  grpc::StatusCode::INVALID_ARGUMENT,
              "pid 为 0 应返回 INVALID_ARGUMENT");
    }

    // CM_GetExcepCtx / CM_GetExtraCtx
    {
        grpc::ClientContext context;
        SetDeadline(context, std::chrono::seconds(5));
        hng::clisv::CM_GetExcepCtxRequest request;
        hng::clisv::CM_GetExcepCtxResponse response;
        const grpc::Status status =
            context_svc.GetExcepCtx(&context, request, &response);
        CHECK(status.ok() && response.contextid_size() == 1 &&
                  response.contextid(0) == kContextID,
              "GetExcepCtx 应返回 ATTACK context");
    }
    {
        grpc::ClientContext context;
        SetDeadline(context, std::chrono::seconds(5));
        hng::clisv::CM_GetExtraCtxRequest request;
        hng::clisv::CM_GetExtraCtxResponse response;
        const grpc::Status status =
            context_svc.GetExtraCtx(&context, request, &response);
        CHECK(status.ok() && response.contextid_size() == 1 &&
                  response.contextid(0) == kExtraContextID,
              "GetExtraCtx 应返回 EXTRA_ATTACK context");
    }

    // CM_GetProcessSet：根与成员；未知 ID 不是错误
    {
        grpc::ClientContext context;
        SetDeadline(context, std::chrono::seconds(5));
        hng::clisv::CM_GetProcessSetRequest request;
        request.set_contextid(kContextID);
        hng::clisv::CM_GetProcessSetResponse response;
        const grpc::Status status =
            context_svc.GetProcessSet(&context, request, &response);
        CHECK(status.ok(), "CM_GetProcessSet 应成功");
        CHECK(response.root_pid() == kPidSyscall, "context 根进程应被填出");
        CHECK(response.has_pids() && response.pids().pid_size() == 2,
              "context 成员集应有两条");
    }
    {
        grpc::ClientContext context;
        SetDeadline(context, std::chrono::seconds(5));
        hng::clisv::CM_GetProcessSetRequest request;
        request.set_contextid(0);
        hng::clisv::CM_GetProcessSetResponse response;
        CHECK(context_svc.GetProcessSet(&context, request, &response)
                      .error_code() == grpc::StatusCode::INVALID_ARGUMENT,
              "contextID 为 0 应返回 INVALID_ARGUMENT");
    }
    {
        grpc::ClientContext context;
        SetDeadline(context, std::chrono::seconds(5));
        hng::clisv::CM_GetProcessSetRequest request;
        request.set_contextid(999999);
        hng::clisv::CM_GetProcessSetResponse response;
        const grpc::Status status =
            context_svc.GetProcessSet(&context, request, &response);
        CHECK(status.ok() && response.root_pid() == 0 && !response.has_pids(),
              "未知 contextID 应成功且不设置字段");
    }

    // CM_GetStats
    {
        grpc::ClientContext context;
        SetDeadline(context, std::chrono::seconds(5));
        hng::clisv::CM_GetStatsRequest request;
        hng::clisv::CM_GetStatsResponse response;
        const grpc::Status status =
            context_svc.GetStats(&context, request, &response);
        CHECK(status.ok(), "CM_GetStats 应成功");
        CHECK(response.ctxroot_parent_unsettled() == 11 &&
                  response.unknown_unregister() == 12 &&
                  response.pending_deferred() == 13 &&
                  response.pending_resolved() == 14 &&
                  response.pending_rejected() == 15 &&
                  response.pending_expired() == 16 &&
                  response.pending_cancelled() == 17 &&
                  response.pending_depth() == 18 &&
                  response.bind_orphaned() == 19 &&
                  response.extra_orphaned() == 20 &&
                  response.parent_missing() == 21 &&
                  response.late_register() == 22 && response.late_bind() == 23 &&
                  response.duplicate_context() == 24 &&
                  response.ownership_conflict() == 25 &&
                  response.tombstone_hits() == 26 &&
                  response.tombstone_depth() == 27,
              "CM_GetStats 应映射全部字段");
    }

    // PM_GetStats
    {
        grpc::ClientContext context;
        SetDeadline(context, std::chrono::seconds(5));
        hng::clisv::PM_GetStatsRequest request;
        hng::clisv::PM_GetStatsResponse response;
        const grpc::Status status =
            process_svc.GetStats(&context, request, &response);
        CHECK(status.ok(), "PM_GetStats 应成功");
        CHECK(response.pid_reused() == 1 && response.stale_add() == 2 &&
                  response.parent_missing() == 3 &&
                  response.tombstone_depth() == 4,
              "PM_GetStats 应映射全部字段");
    }

    // CM_WhichContext：命中、未命中、参数非法
    {
        grpc::ClientContext context;
        SetDeadline(context, std::chrono::seconds(5));
        hng::clisv::CM_WhichContextRequest request;
        request.set_pid(kPidFile);
        hng::clisv::CM_WhichContextResponse response;
        const grpc::Status status =
            context_svc.WhichContext(&context, request, &response);
        CHECK(status.ok() && response.has_contextid() &&
                  response.contextid() == kContextID,
              "WhichContext 应命中替身 context");
    }
    {
        grpc::ClientContext context;
        SetDeadline(context, std::chrono::seconds(5));
        hng::clisv::CM_WhichContextRequest request;
        request.set_pid(999999);
        hng::clisv::CM_WhichContextResponse response;
        const grpc::Status status =
            context_svc.WhichContext(&context, request, &response);
        CHECK(status.ok() && !response.has_contextid(),
              "未命中应成功且不设置 contextID");
    }
    {
        grpc::ClientContext context;
        SetDeadline(context, std::chrono::seconds(5));
        hng::clisv::CM_WhichContextRequest request;
        request.set_pid(0);
        hng::clisv::CM_WhichContextResponse response;
        CHECK(
            context_svc.WhichContext(&context, request, &response).error_code() ==
                grpc::StatusCode::INVALID_ARGUMENT,
            "pid 为 0 应返回 INVALID_ARGUMENT");
    }
}

void run_pipeline_stats(hng::clisv::RuntimeService::Stub& runtime)
{
    grpc::ClientContext context;
    SetDeadline(context, std::chrono::seconds(5));
    hng::clisv::GetPipelineStatsRequest request;
    hng::clisv::GetPipelineStatsResponse response;
    const grpc::Status status =
        runtime.GetPipelineStats(&context, request, &response);
    CHECK(status.ok() && response.has_stats(), "GetPipelineStats 应成功");
    const hng::clisv::pipeline_stats& stats = response.stats();
    CHECK(stats.collector_size() == 1, "collector 应有一条线");
    CHECK(stats.collector(0).line() == "syscall" &&
              stats.collector(0).consumed() == 10 &&
              stats.collector(0).consume_errors() == 1 &&
              stats.collector(0).channel_dropped() == 2 &&
              stats.collector(0).channel_rejected() == 3 &&
              stats.collector(0).reserve_failures() == 4 &&
              stats.collector(0).skipped_probes() == 5 &&
              stats.collector(0).attach_failed() == 6 &&
              stats.collector(0).pending_lost() == 9 &&
              stats.collector(0).malformed() == 10 &&
              stats.collector(0).attached() && !stats.collector(0).polling(),
          "collector 字段应逐一映射");
    CHECK(stats.has_semantic() && stats.semantic().processed_syscall() == 7 &&
              stats.semantic().raw_syscall_dropped() == 2 &&
              stats.semantic().path_unresolved() == 8,
          "semantic 字段应逐一映射");
    CHECK(stats.has_engine() && stats.engine().peak_cli_streams() == 5 &&
              stats.engine().syscall_dropped() == 6,
          "engine 字段应逐一映射");
    CHECK(stats.has_cli(), "cli 段应始终存在");
    CHECK(stats.cli().active() == 0 && stats.cli().dropped() == 0,
          "无活跃流时 cli 计数应为 0");
}

void run_stream_quota(hng::clisv::RuntimeService::Stub& runtime)
{
    // 占满 8 个配额槽；每流先读一条，确认订阅已落地
    constexpr int kQuota = 8;
    std::vector<std::unique_ptr<grpc::ClientContext>> contexts;
    std::vector<
        std::unique_ptr<grpc::ClientReader<hng::clisv::ReceiveEventResponse>>>
        readers;
    for (int i = 0; i < kQuota; ++i) {
        auto context = std::make_unique<grpc::ClientContext>();
        SetDeadline(*context, std::chrono::seconds(10));
        hng::clisv::ReceiveEventRequest request;
        auto reader = runtime.ReceiveEvent(context.get(), request);
        hng::clisv::ReceiveEventResponse message;
        CHECK(reader->Read(&message), "配额内的订阅流应收到事件");
        CHECK(message.has_batch() && message.batch().records_size() > 0,
              "事件应装在批里");
        contexts.push_back(std::move(context));
        readers.push_back(std::move(reader));
    }

    // 第 9 条：名额已满
    {
        grpc::ClientContext context;
        SetDeadline(context, std::chrono::seconds(5));
        hng::clisv::ReceiveEventRequest request;
        auto reader = runtime.ReceiveEvent(&context, request);
        hng::clisv::ReceiveEventResponse unused;
        (void)reader->Read(&unused);
        CHECK(
            reader->Finish().error_code() == grpc::StatusCode::RESOURCE_EXHAUSTED,
            "超额订阅应返回 RESOURCE_EXHAUSTED");
    }

    // 客户端断开：服务端应回收名额
    for (std::size_t i = 0; i < readers.size(); ++i) {
        contexts[i]->TryCancel();
        (void)readers[i]->Finish();
    }

    const bool released = WaitFor(
        [&runtime] {
            grpc::ClientContext context;
            SetDeadline(context, std::chrono::seconds(1));
            hng::clisv::GetPipelineStatsRequest request;
            hng::clisv::GetPipelineStatsResponse response;
            if (!runtime.GetPipelineStats(&context, request, &response).ok() ||
                !response.has_stats() || !response.stats().has_cli()) {
                return false;
            }
            return response.stats().cli().active() == 0;
        },
        std::chrono::seconds(10));
    CHECK(released, "断开后服务端应回收全部配额槽");
}

/// @brief 4 条并发流各自收到事件；同时检查 CLI 流计数
void run_multi_stream(hng::clisv::RuntimeService::Stub& runtime)
{
    constexpr int kStreams  = 4;
    constexpr int kMessages = 10;
    std::vector<std::unique_ptr<grpc::ClientContext>> contexts;
    std::vector<
        std::unique_ptr<grpc::ClientReader<hng::clisv::ReceiveEventResponse>>>
        readers;
    for (int i = 0; i < kStreams; ++i) {
        auto context = std::make_unique<grpc::ClientContext>();
        SetDeadline(*context, std::chrono::seconds(10));
        hng::clisv::ReceiveEventRequest request;
        request.set_batch_size(8);
        readers.push_back(runtime.ReceiveEvent(context.get(), request));
        contexts.push_back(std::move(context));
    }

    const bool all_active = WaitFor(
        [&runtime] {
            grpc::ClientContext context;
            SetDeadline(context, std::chrono::seconds(1));
            hng::clisv::GetPipelineStatsRequest request;
            hng::clisv::GetPipelineStatsResponse response;
            if (!runtime.GetPipelineStats(&context, request, &response).ok() ||
                !response.has_stats() || !response.stats().has_cli()) {
                return false;
            }
            return response.stats().cli().active() == kStreams;
        },
        std::chrono::seconds(5));
    CHECK(all_active, "多流期间 active 应等于流数");

    std::vector<int> records(kStreams, 0);
    for (int message_index = 0; message_index < kMessages; ++message_index) {
        for (int stream = 0; stream < kStreams; ++stream) {
            hng::clisv::ReceiveEventResponse message;
            CHECK(readers[stream]->Read(&message), "并发流应持续收到事件");
            if (message.has_batch()) {
                records[stream] += message.batch().records_size();
            }
        }
    }
    for (int stream = 0; stream < kStreams; ++stream) {
        CHECK(records[stream] >= kMessages, "每条并发流都应收到足够事件");
    }

    for (std::size_t i = 0; i < readers.size(); ++i) {
        contexts[i]->TryCancel();
        (void)readers[i]->Finish();
    }
}

void run_filter(hng::clisv::RuntimeService::Stub& runtime)
{
    // 事件来源：只应收到系统调用事件
    grpc::ClientContext context;
    SetDeadline(context, std::chrono::seconds(10));
    hng::clisv::ReceiveEventRequest request;
    request.add_etype(hng::clisv::EVENT_TYPE_SYSCALL);
    auto reader      = runtime.ReceiveEvent(&context, request);

    bool saw_syscall = false;
    bool saw_other   = false;
    hng::clisv::ReceiveEventResponse message;
    for (int i = 0; i < 5 && reader->Read(&message); ++i) {
        if (!message.has_batch()) {
            continue;
        }
        for (const hng::clisv::eventrecord& record : message.batch().records()) {
            if (record.event_case() == hng::clisv::eventrecord::kSyscallEv) {
                saw_syscall = true;
            }
            else {
                saw_other = true;
            }
        }
    }
    context.TryCancel();
    (void)reader->Finish();

    CHECK(saw_syscall, "按事件来源过滤后应收到系统调用事件");
    CHECK(!saw_other, "按事件来源过滤后不应收到其他类型");

    // -t 语义子类型：合成事件全部是 PROCESS
    {
        grpc::ClientContext typed_context;
        SetDeadline(typed_context, std::chrono::seconds(10));
        hng::clisv::ReceiveEventRequest typed;
        typed.add_subtype(hng::clisv::SUBTYPE_PROCESS);
        auto typed_reader = runtime.ReceiveEvent(&typed_context, typed);

        bool saw_record   = false;
        hng::clisv::ReceiveEventResponse typed_message;
        for (int i = 0; i < 5 && typed_reader->Read(&typed_message); ++i) {
            if (!typed_message.has_batch()) {
                continue;
            }
            for (const hng::clisv::eventrecord& record :
                 typed_message.batch().records()) {
                saw_record = true;
                CHECK(record.head().subtype() == hng::clisv::SUBTYPE_PROCESS,
                      "-t process 只应收到该子类型");
            }
        }
        typed_context.TryCancel();
        (void)typed_reader->Finish();
        CHECK(saw_record, "-t process 应收到事件");
    }
}

/// @brief 按给定请求订阅，收集若干批中的全部事件记录
/// @note 读完即取消；内容断言留给调用方
std::vector<hng::clisv::eventrecord> CollectRecords(
    hng::clisv::RuntimeService::Stub& runtime,
    const hng::clisv::ReceiveEventRequest& request)
{
    grpc::ClientContext context;
    SetDeadline(context, std::chrono::seconds(10));
    auto reader = runtime.ReceiveEvent(&context, request);

    std::vector<hng::clisv::eventrecord> records;
    hng::clisv::ReceiveEventResponse message;
    for (int batch = 0; batch < 5 && reader->Read(&message); ++batch) {
        if (!message.has_batch()) {
            continue;
        }
        for (const hng::clisv::eventrecord& record : message.batch().records()) {
            records.push_back(record);
        }
    }
    context.TryCancel();
    (void)reader->Finish();
    return records;
}

/// @brief -e 表达式：AND 原子取交、NOT 取反、非法表达式被拒绝
void run_expr_filter(hng::clisv::RuntimeService::Stub& runtime)
{
    // subtype=process and pid=<pid>：只应收到该进程的系统调用事件
    {
        hng::clisv::ReceiveEventRequest request;
        auto* logic = request.mutable_expr()->mutable_logic();
        logic->set_logic(hng::clisv::FILTER_LOGIC_AND);
        auto* subtype_atom = logic->add_operands()->mutable_atom();
        subtype_atom->set_field(hng::clisv::FILTER_FIELD_SUBTYPE);
        subtype_atom->set_compare(hng::clisv::FILTER_COMPARE_EQ);
        subtype_atom->add_numbers(
            static_cast<uint32_t>(hng::clisv::SUBTYPE_PROCESS));
        auto* pid_atom = logic->add_operands()->mutable_atom();
        pid_atom->set_field(hng::clisv::FILTER_FIELD_PID);
        pid_atom->set_compare(hng::clisv::FILTER_COMPARE_EQ);
        pid_atom->add_numbers(kPidFile);

        const std::vector<hng::clisv::eventrecord> records =
            CollectRecords(runtime, request);
        CHECK(!records.empty(), "subtype=process and pid 应收到事件");
        for (const hng::clisv::eventrecord& record : records) {
            CHECK(record.event_case() == hng::clisv::eventrecord::kSyscallEv,
                  "事件应为系统调用事件");
            CHECK(record.head().pid() == kPidFile, "pid 原子应只命中该进程");
        }
    }

    // not pid=<pid>：不应收到该进程的事件
    {
        hng::clisv::ReceiveEventRequest request;
        auto* logic = request.mutable_expr()->mutable_logic();
        logic->set_logic(hng::clisv::FILTER_LOGIC_NOT);
        auto* atom = logic->add_operands()->mutable_atom();
        atom->set_field(hng::clisv::FILTER_FIELD_PID);
        atom->set_compare(hng::clisv::FILTER_COMPARE_EQ);
        atom->add_numbers(kPidFile);

        const std::vector<hng::clisv::eventrecord> records =
            CollectRecords(runtime, request);
        CHECK(!records.empty(), "not pid 应收到事件");
        for (const hng::clisv::eventrecord& record : records) {
            CHECK(record.event_case() == hng::clisv::eventrecord::kSyscallEv,
                  "事件应为系统调用事件");
            CHECK(record.head().pid() != kPidFile, "NOT 应排除该进程");
        }
    }

    // NOT 带两个操作数：服务端在占配额前拒绝
    {
        grpc::ClientContext context;
        SetDeadline(context, std::chrono::seconds(5));
        hng::clisv::ReceiveEventRequest request;
        auto* logic = request.mutable_expr()->mutable_logic();
        logic->set_logic(hng::clisv::FILTER_LOGIC_NOT);
        for (int i = 0; i < 2; ++i) {
            auto* atom = logic->add_operands()->mutable_atom();
            atom->set_field(hng::clisv::FILTER_FIELD_PID);
            atom->set_compare(hng::clisv::FILTER_COMPARE_EQ);
            atom->add_numbers(kPidFile);
        }
        auto reader = runtime.ReceiveEvent(&context, request);
        hng::clisv::ReceiveEventResponse message;
        CHECK(!reader->Read(&message), "非法表达式不应收到事件");
        CHECK(reader->Finish().error_code() == grpc::StatusCode::INVALID_ARGUMENT,
              "NOT 带两个操作数应返回 INVALID_ARGUMENT");
    }
}

void run_role_label_filter(hng::clisv::RuntimeService::Stub& runtime)
{
    // -i role=e2e：标签匹配；事件头的 roleLabel 也应被填上
    grpc::ClientContext context;
    SetDeadline(context, std::chrono::seconds(10));
    hng::clisv::ReceiveEventRequest request;
    request.mutable_info()->add_rolelabel(kRoleLabel);
    auto reader = runtime.ReceiveEvent(&context, request);

    hng::clisv::ReceiveEventResponse message;
    CHECK(reader->Read(&message), "按角色标签过滤应收到事件");
    CHECK(message.has_batch() && message.batch().records_size() > 0,
          "事件应装在批里");
    CHECK(message.batch().records(0).head().rolelabel() == kRoleLabel,
          "事件头应带角色标签");
    CHECK(message.batch().records(0).head().exe() == kEventExe,
          "事件头应带进程镜像");

    context.TryCancel();
    (void)reader->Finish();
}

/// @brief 批大小：请求 8 时出现多条记录，请求 1 时每条消息一条记录
void run_batching(hng::clisv::RuntimeService::Stub& runtime)
{
    {
        grpc::ClientContext context;
        SetDeadline(context, std::chrono::seconds(10));
        hng::clisv::ReceiveEventRequest request;
        request.set_batch_size(8);
        auto reader     = runtime.ReceiveEvent(&context, request);

        int batches     = 0;
        int records     = 0;
        int max_records = 0;
        hng::clisv::ReceiveEventResponse message;
        while (batches < 10 && reader->Read(&message)) {
            if (!message.has_batch()) {
                continue;
            }
            ++batches;
            const int size = message.batch().records_size();
            CHECK(size > 0, "事件批不应为空");
            records     += size;
            max_records  = std::max(max_records, size);
        }
        context.TryCancel();
        (void)reader->Finish();

        CHECK(records >= 8, "批量订阅应收到足够事件");
        CHECK(max_records > 1, "batch_size=8 时应出现多条记录的批");
    }
    {
        grpc::ClientContext context;
        SetDeadline(context, std::chrono::seconds(10));
        hng::clisv::ReceiveEventRequest request;
        request.set_batch_size(1);
        auto reader = runtime.ReceiveEvent(&context, request);

        hng::clisv::ReceiveEventResponse message;
        int batches = 0;
        while (batches < 5 && reader->Read(&message)) {
            if (!message.has_batch()) {
                continue;
            }
            ++batches;
            CHECK(message.batch().records_size() == 1,
                  "batch_size=1 时每条消息应只有一条记录");
        }
        context.TryCancel();
        (void)reader->Finish();
        CHECK(batches == 5, "batch_size=1 时应能连续收到消息");
    }
}

/// @brief 等子进程退出；超时返回 false
bool WaitForExit(pid_t child, std::chrono::milliseconds timeout, int* code)
{
    const auto deadline = Clock::now() + timeout;
    for (;;) {
        int status         = 0;
        const pid_t reaped = ::waitpid(child, &status, WNOHANG);
        if (reaped == child) {
            *code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
            return true;
        }
        if (reaped < 0 || Clock::now() >= deadline) {
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
}

// ============================================================
// 父进程：突发过载用例（单独的子进程，经 HNG_CLI_E2E_BURST 打开）
// ============================================================

/// 突发用例的 gRPC deadline。须大于修好后的实测耗时，且小于每满批挂起
/// 一个 50 ms 切片的版本读完 4096 条所需的 4096/16*50 ms ≈ 12.8 s
constexpr std::chrono::seconds kBurstDeadline{6};
/// 读完整个积压的时间上限：容器内实测约 0.1 s，取 2 s 留约 20 倍余量，
/// 仍远小于上式的 12.8 s
constexpr std::chrono::milliseconds kFullBacklogLimit{2000};

/// @brief 积压未读完时就应上报丢弃计数
/// @note 只在队列取空后读 dropped 的实现，前 4096/16 条消息之内不会出现 stats
void run_burst_stats_early(hng::clisv::RuntimeService::Stub& runtime)
{
    grpc::ClientContext context;
    SetDeadline(context, kBurstDeadline);
    hng::clisv::ReceiveEventRequest request;
    request.set_batch_size(16);
    auto reader                  = runtime.ReceiveEvent(&context, request);

    constexpr int kEarlyMessages = 10;
    bool saw_stats               = false;
    uint64_t dropped             = 0;
    hng::clisv::ReceiveEventResponse message;
    for (int i = 0; i < kEarlyMessages && reader->Read(&message); ++i) {
        if (message.has_stats()) {
            saw_stats = true;
            dropped   = message.stats().dropped_events();
        }
    }
    context.TryCancel();
    (void)reader->Finish();

    CHECK(saw_stats, "积压未读完时也应收到 stats");
    CHECK(dropped + kQueueCap >= kBurstEvents,
          "stats 应在事件流仍在继续时报告突发的丢弃量");
}

/// @brief 满批后立即续取：读完一整个队列的积压不应有空转
/// @note 每满批挂起一个唤醒切片时需 4096/16*50 ms ≈ 12.8 s，会先撞上 deadline；
/// 读数不足即判失败
void run_burst_backlog_latency(hng::clisv::RuntimeService::Stub& runtime)
{
    const auto started = Clock::now();
    grpc::ClientContext context;
    SetDeadline(context, kBurstDeadline);
    hng::clisv::ReceiveEventRequest request;
    request.set_batch_size(16);
    auto reader         = runtime.ReceiveEvent(&context, request);

    std::size_t records = 0;
    hng::clisv::ReceiveEventResponse message;
    while (records < kQueueCap && reader->Read(&message)) {
        if (message.has_batch()) {
            records += message.batch().records_size();
        }
    }
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        Clock::now() - started);
    context.TryCancel();
    (void)reader->Finish();

    std::printf("[info] batch_size=16 读完 %zu 条积压耗时 %lld ms\n", records,
                static_cast<long long>(elapsed.count()));
    CHECK(records >= kQueueCap, "应在 deadline 内读完整个积压");
    CHECK(elapsed < kFullBacklogLimit, "满批后应立即续取，不应空转");
}

/// @brief 以 HNG_CLI_E2E_SERVE 模式重新拉起本程序，作为突发用例的服务端
/// @note 父进程此时已持有 gRPC 线程，fork 出的子进程不 exec 会带着半份线程状态
/// 启动失败，故走 posix_spawn 的 fork + exec
/// @return 子进程 pid；拉起失败为 -1
pid_t SpawnBurstServer()
{
    char self[1024];
    const ssize_t length = ::readlink("/proc/self/exe", self, sizeof(self) - 1);
    if (length <= 0) {
        return -1;
    }
    self[length] = '\0';

    const std::string burst =
        std::string{"HNG_CLI_E2E_BURST="} + std::to_string(kBurstEvents);
    std::vector<char*> env;
    for (char** item = environ; *item != nullptr; ++item) {
        env.push_back(*item);
    }
    env.push_back(const_cast<char*>("HNG_CLI_E2E_SERVE=1"));
    env.push_back(const_cast<char*>(burst.c_str()));
    env.push_back(nullptr);

    char* argv[] = {self, nullptr};
    pid_t child  = -1;
    if (::posix_spawn(&child, self, nullptr, nullptr, argv, env.data()) != 0) {
        return -1;
    }
    return child;
}

/// @brief 突发用例：拉起一个置了 HNG_CLI_E2E_BURST 的专门服务端进程
/// @note 突发只在这个进程内打开，常规用例的子进程行为不变
void run_burst_phase()
{
    ::unlink(kSocketPath);

    const pid_t child = SpawnBurstServer();
    if (child < 0) {
        CHECK(false, "突发用例的服务端拉起失败");
        return;
    }

    const auto channel = MakeChannel();
    auto role          = hng::clisv::RoleManagerService::NewStub(channel);
    auto runtime       = hng::clisv::RuntimeService::NewStub(channel);

    if (WaitForServer(*role)) {
        run_burst_stats_early(*runtime);
        run_burst_backlog_latency(*runtime);
    }
    else {
        CHECK(false, "突发用例的服务端未在期限内就绪");
    }

    ::kill(child, SIGTERM);

    int child_code = -1;
    if (WaitForExit(child, std::chrono::seconds(20), &child_code)) {
        CHECK(child_code == 0, "突发用例的子进程应正常退出");
    }
    else {
        ::kill(child, SIGKILL);
        (void)::waitpid(child, nullptr, 0);
        CHECK(false, "突发用例的子进程应在停机后退出");
    }

    ::unlink(kSocketPath);
}

}  // namespace

int main()
{
    // 联调模式：在进程内装配替身服务端并驻留，供外部 CLI 经同一 socket 验证。
    // 只用于 scripts/test-cli-e2e.sh，默认路径仍是下面的 fork + 断言。
    if (const char* serve = std::getenv("HNG_CLI_E2E_SERVE");
        serve != nullptr && serve[0] != '\0') {
        ::unlink(kSocketPath);
        RunChild();
    }

    ::unlink(kSocketPath);

    const pid_t child = ::fork();
    if (child < 0) {
        std::fprintf(stderr, "[FAIL] fork failed\n");
        return 1;
    }
    if (child == 0) {
        RunChild();
    }

    const auto channel = MakeChannel();
    auto role          = hng::clisv::RoleManagerService::NewStub(channel);
    auto context_svc   = hng::clisv::ContextManagerService::NewStub(channel);
    auto process_svc   = hng::clisv::ProcessManagerService::NewStub(channel);
    auto runtime       = hng::clisv::RuntimeService::NewStub(channel);

    // 停机时故意留一条活跃流：它应由停机广播收敛，而不是拖住退出
    grpc::ClientContext held_context;
    std::unique_ptr<grpc::ClientReader<hng::clisv::ReceiveEventResponse>> held;

    if (WaitForServer(*role)) {
        run_query_face(*role, *context_svc, *process_svc);
        run_pipeline_stats(*runtime);
        run_stream_quota(*runtime);
        run_multi_stream(*runtime);
        run_filter(*runtime);
        run_expr_filter(*runtime);
        run_role_label_filter(*runtime);
        run_batching(*runtime);

        hng::clisv::ReceiveEventRequest held_request;
        held = runtime->ReceiveEvent(&held_context, held_request);
        hng::clisv::ReceiveEventResponse event;
        CHECK(held->Read(&event), "停机前应能收到事件");
        CHECK(event.has_batch() && event.batch().records_size() > 0,
              "停机前的事件应装在批里");
    }
    else {
        CHECK(false, "服务端未在期限内就绪");
    }

    // drain-timeout 配成 30s：若流不能自行收敛，退出会被拖到 30s 之后
    ::kill(child, SIGTERM);

    bool child_exited = false;
    int child_code    = -1;
    child_exited      = WaitForExit(child, std::chrono::seconds(20), &child_code);
    CHECK(child_exited,
          "SIGTERM 后子进程应在期限内退出（活跃流应被停机广播收敛）");
    if (child_exited) {
        CHECK(child_code == 0, "子进程应正常退出");
    }
    else {
        ::kill(child, SIGKILL);
        (void)::waitpid(child, nullptr, 0);
    }

    if (held) {
        held_context.TryCancel();
        (void)held->Finish();
    }

    ::unlink(kSocketPath);

    run_burst_phase();

    if (g_fail) {
        std::fprintf(stderr, "TOTAL FAILURES: %d\n", g_fail);
        return 1;
    }
    std::printf("ALL PASS\n");
    return 0;
}
