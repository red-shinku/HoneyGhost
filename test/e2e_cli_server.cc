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
constexpr uint32_t kPidSyscall     = 1001;
constexpr uint32_t kPidFile        = 2002;
constexpr uint32_t kContextID      = 3;
constexpr uint32_t kExtraContextID = 4;

constexpr char kSocketPath[]   = "/tmp/honeyghost-cli-e2e.sock";

// ============================================================
// 子进程：粗糙装配
// ============================================================

/// 静态配置：并发流上限刻意配成 1，以便用第二个订阅流观察配额
constexpr char kConfig[]       = R"(
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
            max-concurrent-streams: 1
            queue-capacity: 16
            # 配得远大于停机等待的上限，使「活跃流不收敛」会表现为超时失败
            drain-timeout: 30s
        cli-role-service: {}
        cli-context-service: {}
        cli-runtime-service: {}
)";

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

    RoleManagerStats stats() const override
    {
        RoleManagerStats s;
        s.store.rejected         = 1;
        s.store.unknown_instance = 2;
        s.store.owner_conflict   = 3;
        s.store.anchors_removed  = 4;
        s.cgroup_read_empty      = 5;
        s.queue_rejected         = 6;
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
};

/// 一条合成的运行时事件：偶数序号为系统调用事件，奇数为文件事件
hng::RuntimeEvent MakeEvent(uint32_t seq)
{
    const bool is_file = (seq % 2) != 0;
    const uint32_t pid = is_file ? kPidFile : kPidSyscall;

    hng::RuntimeEvent event{};
    event.runtimeInfo.process = hng::Process{pid, pid * 10};
    event.runtimeInfo.etype =
        is_file ? hng::EventType::FILE_EVENT : hng::EventType::SYSCALL_EVENT;
    event.runtimeInfo.roleID    = kRoleID;
    event.runtimeInfo.roleLabel = kRoleLabel;
    event.runtimeInfo.contextID = kContextID;

    if (is_file) {
        hng::file_semantic_data& file =
            event.data.emplace<hng::file_semantic_data>();
        file.head.pid            = pid;
        file.head.pid_start_time = pid * 10;
        file.head.type           = hng::EventType::FILE_EVENT;
        file.data.set_semantic_filename("/tmp/e2e");
    }
    else {
        hng::syscall_semantic_data& syscall =
            event.data.emplace<hng::syscall_semantic_data>();
        syscall.head.pid            = pid;
        syscall.head.pid_start_time = pid * 10;
        syscall.head.type           = hng::EventType::SYSCALL_EVENT;
        syscall.data.emplace<0>().set_syscall_name("e2e");
    }
    return event;
}

/// @brief 替身引擎：登记表加一条只读，另起线程按固定节奏合成事件
/// @note 与真实引擎的差别只在「命令线程」：这里注销与停机回执在调用方线程上
/// 同步完成，契约本身（摘表后回执、此后不再 on_event）不变
class FakeEngine final : public SubscriberRegService {
   public:
    FakeEngine() : producer_([this] { Produce(); }) {}

    ~FakeEngine() override { stop(); }

    bool subscribe(RuntimeEventSink* sink, RuntimeInfoFilter filter,
                   UnsubscribeAck* ack) override
    {
        const std::lock_guard lock(mu_);
        entries_.push_back(Entry{sink, std::move(filter), ack});
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

    void Produce()
    {
        uint32_t seq = 0;
        while (!stopping_.load()) {
            const hng::RuntimeEvent event = MakeEvent(seq++);
            {
                const std::lock_guard lock(mu_);
                for (const Entry& entry : entries_) {
                    if (entry.filter.should_take(event.runtimeInfo)) {
                        entry.sink->on_event(event);
                    }
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
    }

    std::mutex mu_;
    std::vector<Entry> entries_;
    std::atomic<bool> stopping_{false};
    std::thread producer_;
};

/// 子进程入口：装配并跑 userver 应用，直到收到停机信号
[[noreturn]] void RunChild()
{
    // 替身必须在 fork 之后构造：FakeEngine 持有线程，线程不随 fork 复制
    RoleStub role;
    ContextStub context;
    ProcessStub process;
    FakeEngine engine;

    CLIServerDeps deps;
    deps.role    = &role;
    deps.context = &context;
    deps.process = &process;
    deps.subs    = &engine;
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
                    hng::clisv::ContextManagerService::Stub& context_svc)
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
        CHECK(response.root_pid() == kPidSyscall,
              "root_pid 应来自 main_process");
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
        const grpc::Status status =
            role.GetRoles(&context, request, &response);
        CHECK(status.ok(), "GetRoles 应成功");
        CHECK(response.r_size() == 1 && response.r(0).roleid() == kRoleID &&
                  response.r(0).rolelabel() == kRoleLabel,
              "GetRoles 应返回替身角色");
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
        CHECK(response.rejected() == 1 && response.unknown_instance() == 2 &&
                  response.owner_conflict() == 3 &&
                  response.anchors_removed() == 4 &&
                  response.cgroup_read_empty() == 5 &&
                  response.queue_rejected() == 6,
              "RM_GetStats 应映射全部字段");
    }

    // RM_WhichRole：命中、未命中、参数非法
    {
        grpc::ClientContext context;
        SetDeadline(context, std::chrono::seconds(5));
        hng::clisv::RM_WhichRoleRequest request;
        request.set_pid(kPidSyscall);
        hng::clisv::RM_WhichRoleResponse response;
        const grpc::Status status =
            role.WhichRole(&context, request, &response);
        CHECK(status.ok() && response.has_roleid() &&
                  response.roleid() == kRoleID,
              "WhichRole 应命中替身角色");
    }
    {
        grpc::ClientContext context;
        SetDeadline(context, std::chrono::seconds(5));
        hng::clisv::RM_WhichRoleRequest request;
        request.set_pid(999999);
        hng::clisv::RM_WhichRoleResponse response;
        const grpc::Status status =
            role.WhichRole(&context, request, &response);
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
                  response.unknown_unregister() == 12,
              "CM_GetStats 应映射全部字段");
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
        CHECK(context_svc.WhichContext(&context, request, &response)
                      .error_code() == grpc::StatusCode::INVALID_ARGUMENT,
              "pid 为 0 应返回 INVALID_ARGUMENT");
    }
}

void run_stream_quota(hng::clisv::RuntimeService::Stub& runtime)
{
    // 第一条流：占满唯一的配额槽
    grpc::ClientContext first_context;
    hng::clisv::ReceiveEventRequest first_request;
    auto first = runtime.ReceiveEvent(&first_context, first_request);

    hng::clisv::ReceiveEventResponse message;
    CHECK(first->Read(&message), "首个订阅流应收到事件");
    CHECK(message.event_case() == hng::clisv::ReceiveEventResponse::kSyscallEv ||
              message.event_case() == hng::clisv::ReceiveEventResponse::kFileEv,
          "事件应带载荷");

    // 第二条流：名额已满
    {
        grpc::ClientContext second_context;
        SetDeadline(second_context, std::chrono::seconds(5));
        hng::clisv::ReceiveEventRequest second_request;
        auto second = runtime.ReceiveEvent(&second_context, second_request);
        hng::clisv::ReceiveEventResponse unused;
        (void)second->Read(&unused);
        CHECK(
            second->Finish().error_code() == grpc::StatusCode::RESOURCE_EXHAUSTED,
            "超额订阅应返回 RESOURCE_EXHAUSTED");
    }

    // 客户端断开：服务端应回收名额
    first_context.TryCancel();
    (void)first->Finish();

    const bool accepted = WaitFor(
        [&runtime] {
            grpc::ClientContext context;
            hng::clisv::ReceiveEventRequest request;
            auto reader = runtime.ReceiveEvent(&context, request);
            hng::clisv::ReceiveEventResponse event;
            const bool got = reader->Read(&event);
            context.TryCancel();
            (void)reader->Finish();
            return got;
        },
        std::chrono::seconds(10));
    CHECK(accepted, "断开后服务端应回收配额槽");
}

void run_filter(hng::clisv::RuntimeService::Stub& runtime)
{
    // -t file：只应收到文件事件
    grpc::ClientContext context;
    SetDeadline(context, std::chrono::seconds(10));
    hng::clisv::ReceiveEventRequest request;
    request.add_etype(hng::clisv::EVENT_TYPE_FILE);
    auto reader    = runtime.ReceiveEvent(&context, request);

    bool saw_file  = false;
    bool saw_other = false;
    hng::clisv::ReceiveEventResponse message;
    for (int i = 0; i < 5 && reader->Read(&message); ++i) {
        if (message.event_case() == hng::clisv::ReceiveEventResponse::kFileEv) {
            saw_file = true;
        }
        else {
            saw_other = true;
        }
    }
    context.TryCancel();
    (void)reader->Finish();

    CHECK(saw_file, "按事件类型过滤后应收到文件事件");
    CHECK(!saw_other, "按事件类型过滤后不应收到其他类型");
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
    CHECK(message.head().rolelabel() == kRoleLabel, "事件头应带角色标签");

    context.TryCancel();
    (void)reader->Finish();
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

}  // namespace

int main()
{
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
    auto runtime       = hng::clisv::RuntimeService::NewStub(channel);

    // 停机时故意留一条活跃流：它应由停机广播收敛，而不是拖住退出
    grpc::ClientContext held_context;
    std::unique_ptr<grpc::ClientReader<hng::clisv::ReceiveEventResponse>> held;

    if (WaitForServer(*role)) {
        run_query_face(*role, *context_svc);
        run_stream_quota(*runtime);
        run_filter(*runtime);
        run_role_label_filter(*runtime);

        hng::clisv::ReceiveEventRequest held_request;
        held = runtime->ReceiveEvent(&held_context, held_request);
        hng::clisv::ReceiveEventResponse event;
        CHECK(held->Read(&event), "停机前应能收到事件");
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

    if (g_fail) {
        std::fprintf(stderr, "TOTAL FAILURES: %d\n", g_fail);
        return 1;
    }
    std::printf("ALL PASS\n");
    return 0;
}
