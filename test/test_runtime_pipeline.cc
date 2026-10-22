/**
 * @file test_runtime_pipeline.cc
 * @brief RuntimePipeline 取事件 / 分派 / 组装草稿的单测
 * @details
 * 四个控制平面注入点全部走替身，语义队列为真实 SPSC 队列，无 IO / 无特权。
 * 覆盖：
 *  - 空队列与未接线队列：不取任何事件；
 *  - 生命周期分派：诞生 → 注册 + 角色继承 + 开窗，退出 → 注销 + 关窗；
 *  - exec / 其他类型 / 文件事件各自的决策入口与缺省决策；
 *  - 归属快照与决策值互不干扰：决策为空时快照仍照实填；
 *  - 轮询纪律：每轮每条队列各取至多一条，顺序固定为 syscall → file；
 *  - 槽位不足时不取事件。
 * @author red-shinku
 * @date 2026.10.11
 */

#include "agent/runtime_engine/src/runtime_pipeline.hpp"

#include <cstdint>
#include <cstdio>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "agent/control_plane/include/process_service.hpp"
#include "agent/control_plane/include/role_service.hpp"

namespace {

int g_fail = 0;

#define CHECK(cond, msg)                                                         \
    do {                                                                         \
        if (!(cond)) {                                                           \
            ++g_fail;                                                            \
            std::fprintf(stderr, "[FAIL] %s:%d  %s\n", __FILE__, __LINE__, msg); \
        }                                                                        \
    } while (0)

hng::Process mk(uint32_t pid, uint64_t start) { return hng::Process{pid, start}; }

// ---- 控制平面替身 ----

/// 控制平面 context 服务的极简替身：仅登记 context 根进程 → contextID
class FakeContextService final : public ContextLookupService,
                                 public ContextJoinService,
                                 public ContextUpdateService {
   public:
    struct Key {
        hng::Process p;
        bool operator==(const Key& o) const { return p == o.p; }
    };
    struct KeyHash {
        std::size_t operator()(const Key& k) const
        {
            return std::hash<hng::Process>{}(k.p);
        }
    };

    std::unordered_map<Key, uint32_t, KeyHash> ctx;
    std::size_t register_calls = 0;

    void seed(hng::Process p, uint32_t id) { ctx[Key{p}] = id; }

    std::optional<uint32_t> lookup(hng::Process p) const override
    {
        auto it = ctx.find(Key{p});
        if (it == ctx.end()) {
            return std::nullopt;
        }
        return it->second;
    }
    std::optional<uint32_t> lookup_extra(hng::Process p) const override
    {
        (void)p;
        return std::nullopt;
    }
    std::vector<uint32_t> contexts_by_attr(hng::contextattr) const override
    {
        return {};
    }
    std::optional<ContextProcessSet> members(uint32_t) const override
    {
        return std::nullopt;
    }
    ContextManagerStats stats() const override { return {}; }
    void register_context(hng::Process p, ContextDeriveDecision nd,
                          hng::Process) override
    {
        ++register_calls;
        ctx[Key{p}] = nd.contextID;
    }
    void register_extra_context(hng::Process, uint32_t, hng::contextattr) override
    {
    }
    void unregister_context(hng::Process p) override { ctx.erase(Key{p}); }
    void bind_to_ctxroot(hng::Process, hng::Process) override {}
    void set_attr(hng::Process, uint32_t, hng::contextattr) override {}
};

/// 记录进程注册 / 注销通知
class FakeProcessJoin final : public ProcessJoinService {
   public:
    std::vector<hng::event_head> registered;
    std::vector<hng::Process> unregistered;

    void register_pid(hng::event_head ehead) override
    {
        registered.push_back(ehead);
    }
    void unregister_pid(hng::Process p) override { unregistered.push_back(p); }
};

/// 记录进程镜像更新通知
class FakeProcessUpdate final : public ProcessUpdateService {
   public:
    struct Update {
        hng::Process process;
        std::string exe;
    };

    std::vector<Update> updates;

    void update_exe_image(hng::Process p, std::string exe) override
    {
        updates.push_back(Update{p, std::move(exe)});
    }
};

/// 记录角色继承通知
class FakeRoleJoin final : public RoleJoinService {
   public:
    std::vector<std::pair<hng::Process, hng::Process>> bound;

    void bind_to_role(hng::Process child, hng::Process parent) override
    {
        bound.emplace_back(child, parent);
    }
};

/// 静态角色归属：命中固定表，其余为空
class FakeRoleLookup final : public RoleLookupService {
   public:
    std::unordered_map<uint32_t, uint32_t> role_of_pid;

    std::optional<uint32_t> lookup(hng::Process p) const override
    {
        auto it = role_of_pid.find(p.pid);
        if (it == role_of_pid.end()) {
            return std::nullopt;
        }
        return it->second;
    }
    std::optional<hng::Role> role(uint32_t roleID) const override
    {
        return hng::Role{roleID, "role-" + std::to_string(roleID)};
    }
    std::vector<hng::Role> roles() const override { return {}; }
    std::optional<hng::Process> main_process(uint32_t) const override
    {
        return std::nullopt;
    }
    std::vector<hng::Role> supervised_roles() const override { return {}; }
    RoleManagerStats stats() const override { return {}; }
    std::optional<hng::role::RoleIdentity> identity(uint32_t) const override
    {
        return std::nullopt;
    }
    std::vector<hng::Process> members(uint32_t) const override { return {}; }
};

// ---- 装配 ----

/// 替身 + 真实 SPSC 队列 + 被测流水线
/// @note 流水线不拥有任何注入点；context 服务替身是同一个对象，装入
/// ContextMaintainer 供其查询与登记
struct Env {
    FakeContextService ctx_svc;
    FakeProcessJoin process_join;
    FakeProcessUpdate process_update;
    FakeRoleJoin role_join;
    FakeRoleLookup role_lookup;
    hng::SPSC_Queue<hng::syscall_semantic_data> sys_q{16};
    hng::SPSC_Queue<hng::file_semantic_data> file_q{16};

    ContextMaintainer cm;
    RuntimePipeline pipe{&sys_q,          &file_q,    &cm,         &process_join,
                         &process_update, &role_join, &role_lookup};

    Env() { cm.set_context_service(&ctx_svc, &ctx_svc, &ctx_svc); }
};

// ---- 事件构造 ----

hng::syscall_semantic_data make_lifecycle(uint32_t pid, uint64_t pstart,
                                          uint32_t ppid, uint64_t ppstart,
                                          const char* syscall_name)
{
    hng::syscall_semantic_data ev;
    ev.head.pid             = pid;
    ev.head.pid_start_time  = pstart;
    ev.head.ppid            = ppid;
    ev.head.ppid_start_time = ppstart;
    ev.head.type            = hng::EventType::SYSCALL_EVENT;
    auto& payload           = ev.data.emplace<hng::process_semantic_data>();
    payload.set_syscall_name(syscall_name);
    return ev;
}

hng::syscall_semantic_data make_exec(uint32_t pid, uint64_t pstart, uint32_t ppid,
                                     uint64_t ppstart, const char* filename)
{
    hng::syscall_semantic_data ev;
    ev.head.pid             = pid;
    ev.head.pid_start_time  = pstart;
    ev.head.ppid            = ppid;
    ev.head.ppid_start_time = ppstart;
    ev.head.type            = hng::EventType::SYSCALL_EVENT;
    auto& payload           = ev.data.emplace<hng::exec_semantic_data>();
    payload.set_semantic_filename(filename);
    payload.set_syscall_name("execve");
    return ev;
}

hng::syscall_semantic_data make_credential(uint32_t pid, uint64_t pstart,
                                           uint32_t ppid, uint64_t ppstart)
{
    hng::syscall_semantic_data ev;
    ev.head.pid             = pid;
    ev.head.pid_start_time  = pstart;
    ev.head.ppid            = ppid;
    ev.head.ppid_start_time = ppstart;
    ev.head.type            = hng::EventType::SYSCALL_EVENT;
    ev.data.emplace<hng::credential_semantic_data>();
    return ev;
}

hng::file_semantic_data make_file(uint32_t pid, uint64_t pstart, const char* path)
{
    hng::file_semantic_data ev;
    ev.head.pid             = pid;
    ev.head.pid_start_time  = pstart;
    ev.head.ppid            = 0;
    ev.head.ppid_start_time = 0;
    ev.head.type            = hng::EventType::FILE_EVENT;
    ev.data.set_semantic_filename(path);
    return ev;
}

/// 一条草稿的默认决策（无派生）
bool is_default_decision(const ContextDeriveDecision& d)
{
    return d.kind == ContextDecisionKind::NONE && d.contextID == 0;
}

/// 逐轮取事件直到出现空轮，最多取 max_events 条
/// @note 每轮每条队列各取至多一条，故同一条队列的多条事件需多轮才能取尽
std::size_t drain(RuntimePipeline& pipe, RuntimeDraft* drafts,
                  std::size_t max_events)
{
    std::size_t total = 0;
    while (total < max_events) {
        const std::size_t n = pipe.take_round(drafts + total, max_events - total);
        if (n == 0) {
            break;
        }
        total += n;
    }
    return total;
}

// ---- 空与未接线 ----

void run_empty()
{
    Env env;
    RuntimeDraft drafts[2]{};
    CHECK(env.pipe.take_round(drafts, 2) == 0, "空队列不产出草稿");

    // 两条队列都未接线：取轮不崩、不产出
    RuntimePipeline bare(nullptr, nullptr, &env.cm, &env.process_join,
                         &env.process_update, &env.role_join, &env.role_lookup);
    CHECK(bare.take_round(drafts, 2) == 0, "未接线的队列不产出草稿");
}

// ---- 生命周期分派 ----

void run_birth()
{
    Env env;
    const hng::Process parent = mk(50, 500);
    env.ctx_svc.seed(parent, 100);  // 父进程已有 context

    env.role_lookup.role_of_pid[5000] = 7;
    env.sys_q.push(make_lifecycle(5000, 500, 50, 500, "fork"));

    RuntimeDraft drafts[2]{};
    CHECK(env.pipe.take_round(drafts, 2) == 1, "诞生事件取出一条");

    const RuntimeDraft& d = drafts[0];
    CHECK(env.process_join.registered.size() == 1 &&
              env.process_join.registered[0].pid == 5000,
          "诞生应通知注册 PID，且头即新进程自身");
    CHECK(env.process_join.unregistered.empty(), "诞生不通知注销");
    CHECK(env.role_join.bound.size() == 1 &&
              env.role_join.bound[0] == std::make_pair(mk(5000, 500), parent),
          "诞生应按 (子, 父) 通知角色继承");
    CHECK(is_default_decision(d.decision), "诞生不产生派生决策");

    CHECK(d.event.runtimeInfo.etype == hng::EventType::SYSCALL_EVENT,
          "syscall 载荷应推出 SYSCALL_EVENT");
    CHECK(d.event.runtimeInfo.process == mk(5000, 500),
          "事件主体应是事件头的新进程");
    CHECK(d.event.runtimeInfo.roleID == 7, "角色归属应取查询结果");
    CHECK(d.event.runtimeInfo.roleLabel == "role-7", "角色标签应取自同一归属链");
    CHECK(d.event.runtimeInfo.contextID == 100, "窗口期内应归父进程的 context");
}

void run_exit()
{
    Env env;
    const hng::Process parent = mk(50, 500);
    env.ctx_svc.seed(parent, 100);

    // 先诞生再退出：退出应关窗，此后不再归父
    env.sys_q.push(make_lifecycle(6000, 600, 50, 500, "fork"));
    env.sys_q.push(make_lifecycle(6000, 600, 50, 500, "exit_group"));

    RuntimeDraft drafts[2]{};
    CHECK(drain(env.pipe, drafts, 2) == 2, "诞生与退出分两轮各取出一条");
    CHECK(drafts[0].event.runtimeInfo.contextID == 100, "诞生时归父 context");

    const RuntimeDraft& d = drafts[1];
    CHECK(env.process_join.unregistered.size() == 1 &&
              env.process_join.unregistered[0] == mk(6000, 600),
          "退出应通知注销 PID");
    CHECK(env.process_join.registered.size() == 1, "退出不通知注册");
    CHECK(env.role_join.bound.size() == 1, "退出不通知角色继承");
    CHECK(is_default_decision(d.decision), "退出不产生派生决策");
    CHECK(d.event.runtimeInfo.contextID == 0, "关窗后归属落空，快照为 0");
}

// ---- exec 分派 ----

void run_exec_derive()
{
    Env env;
    const hng::Process parent = mk(50, 500);
    env.ctx_svc.seed(parent, 100);

    env.sys_q.push(make_lifecycle(7000, 700, 50, 500, "fork"));
    env.sys_q.push(make_exec(7000, 700, 50, 500, "/bin/bash"));

    RuntimeDraft drafts[2]{};
    CHECK(drain(env.pipe, drafts, 2) == 2, "诞生与 exec 分两轮各取出一条");

    const RuntimeDraft& d = drafts[1];
    CHECK(d.decision.kind == ContextDecisionKind::DERIVE, "解释器 exec 应派生");
    CHECK(env.ctx_svc.register_calls == 1, "派生应登记到控制平面");
    CHECK(d.event.runtimeInfo.contextID == d.decision.contextID,
          "派生后的归属快照应即新 context");
    CHECK(d.event.runtimeInfo.contextID != 0, "新 context 不应是未落定哨兵");
    CHECK(env.process_update.updates.size() == 1 &&
              env.process_update.updates[0].process == mk(7000, 700) &&
              env.process_update.updates[0].exe == "/bin/bash",
          "exec 应按语义化路径更新进程镜像");
}

void run_exec_keep_keeps_snapshot()
{
    Env env;
    const hng::Process parent = mk(50, 500);
    env.ctx_svc.seed(parent, 100);

    env.sys_q.push(make_lifecycle(8000, 800, 50, 500, "fork"));
    env.sys_q.push(make_exec(8000, 800, 50, 500, "/bin/bash"));
    env.sys_q.push(make_exec(8000, 800, 50, 500, "/usr/bin/ls"));

    RuntimeDraft drafts[3]{};
    CHECK(drain(env.pipe, drafts, 3) == 3, "三次事件分三轮取出");
    const uint32_t own = drafts[1].decision.contextID;
    CHECK(own != 0, "第一次 exec 已派生自身 context");

    // 原地重 exec：决策为空，但归属快照仍是自身已登记的 context
    const RuntimeDraft& d = drafts[2];
    CHECK(is_default_decision(d.decision), "原地重 exec 不派生");
    CHECK(d.event.runtimeInfo.contextID == own, "决策为空不影响归属快照");
}

// ---- 其他类型与文件事件 ----

void run_plain_event()
{
    Env env;
    const hng::Process parent = mk(50, 500);
    env.ctx_svc.seed(parent, 100);

    // 窗口配额 2：窗口期内无 exec 的普通事件连续消耗配额，末次触发 NO_EXEC 派生
    ContextMaintainer cm(2);
    cm.set_context_service(&env.ctx_svc, &env.ctx_svc, &env.ctx_svc);
    RuntimePipeline pipe(&env.sys_q, nullptr, &cm, &env.process_join,
                         &env.process_update, &env.role_join, &env.role_lookup);

    const hng::Process worker = mk(9100, 910);
    cm.on_birth(worker, parent);

    env.sys_q.push(make_credential(9100, 910, 50, 500));
    RuntimeDraft drafts[2]{};
    CHECK(pipe.take_round(drafts, 2) == 1, "普通事件取出一条");
    CHECK(is_default_decision(drafts[0].decision), "配额未耗尽无派生");
    CHECK(drafts[0].event.runtimeInfo.contextID == 100, "窗口期内归父 context");

    env.sys_q.push(make_credential(9100, 910, 50, 500));
    CHECK(pipe.take_round(drafts, 2) == 1, "普通事件取出一条(2)");
    CHECK(drafts[0].decision.kind == ContextDecisionKind::DERIVE,
          "配额耗尽应由普通事件触发派生");
    CHECK(drafts[0].event.runtimeInfo.contextID == drafts[0].decision.contextID,
          "派生后的归属快照应即新 context");
}

void run_file_event()
{
    Env env;
    const hng::Process parent = mk(50, 500);
    env.ctx_svc.seed(parent, 100);

    // 只接线文件队列：syscall 队列为空指针
    RuntimePipeline pipe(nullptr, &env.file_q, &env.cm, &env.process_join,
                         &env.process_update, &env.role_join, &env.role_lookup);

    env.sys_q.push(make_lifecycle(1, 1, 0, 0, "fork"));  // 未接线，应被忽略
    env.file_q.push(make_file(5500, 555, "/etc/passwd"));

    RuntimeDraft drafts[2]{};
    CHECK(pipe.take_round(drafts, 2) == 1, "只取已接线队列的事件");
    CHECK(pipe.take_round(drafts, 2) == 0, "未接线的队列不产出草稿");

    const RuntimeDraft& d = drafts[0];
    CHECK(d.event.runtimeInfo.etype == hng::EventType::FILE_EVENT,
          "文件载荷应推出 FILE_EVENT");
    CHECK(d.event.runtimeInfo.process == mk(5500, 555),
          "文件事件的进程身份应取事件头");

    // 窗口外进程的文件事件不推进决策
    CHECK(is_default_decision(d.decision), "窗口外进程的文件事件无派生");
    CHECK(env.file_q.empty(), "已取出的文件事件不再滞留");
}

// ---- 轮询纪律 ----

void run_round_discipline()
{
    Env env;
    env.sys_q.push(make_credential(1, 10, 0, 0));
    env.sys_q.push(make_credential(1, 10, 0, 0));
    env.file_q.push(make_file(2, 20, "/a"));
    env.file_q.push(make_file(3, 30, "/b"));

    RuntimeDraft drafts[2]{};
    CHECK(env.pipe.take_round(drafts, 2) == 2, "每轮每条队列各取至多一条");
    CHECK(drafts[0].event.runtimeInfo.process == mk(1, 10), "syscall 先于 file");
    CHECK(drafts[1].event.runtimeInfo.process == mk(2, 20), "file 队列取队首");

    CHECK(env.pipe.take_round(drafts, 2) == 2, "下一轮取走剩余两条");
    CHECK(drafts[0].event.runtimeInfo.process == mk(1, 10),
          "上轮未取走的 syscall 事件留在队列");
    CHECK(drafts[1].event.runtimeInfo.process == mk(3, 30), "file 队列前进一条");

    CHECK(env.pipe.take_round(drafts, 2) == 0, "空队列不再产出草稿");

    // 只有一条槽位时只取最高优先级的一条
    env.sys_q.push(make_credential(4, 40, 0, 0));
    env.file_q.push(make_file(5, 50, "/c"));
    CHECK(env.pipe.take_round(drafts, 1) == 1, "槽位不足时只取一条");
    CHECK(drafts[0].event.runtimeInfo.process == mk(4, 40), "取的是最高优先级");
    CHECK(env.pipe.take_round(drafts, 0) == 0, "槽位为 0 时不取事件");
    CHECK(env.file_q.size() == 1, "槽位不足时未取走的事件仍在队列");
}

// ---- 角色归属未命中 ----

void run_role_miss()
{
    Env env;
    env.sys_q.push(make_credential(1, 10, 0, 0));

    RuntimeDraft drafts[1]{};
    CHECK(env.pipe.take_round(drafts, 1) == 1, "取出一条");
    CHECK(drafts[0].event.runtimeInfo.roleID == 0, "未归属时角色快照为 0");
    CHECK(drafts[0].event.runtimeInfo.roleLabel.empty(), "未归属时角色标签为空");
    CHECK(drafts[0].event.runtimeInfo.contextID == 0, "未登记时上下文快照为 0");
}

}  // namespace

int main()
{
    run_empty();
    run_birth();
    run_exit();
    run_exec_derive();
    run_exec_keep_keeps_snapshot();
    run_plain_event();
    run_file_event();
    run_round_discipline();
    run_role_miss();

    if (g_fail) {
        std::fprintf(stderr, "TOTAL FAILURES: %d\n", g_fail);
        return 1;
    }
    std::printf("ALL PASS\n");
    return 0;
}
