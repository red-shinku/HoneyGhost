/**
 * @file test_runtime_engine.cc
 * @brief RuntimeEngine 主循环、订阅协议与统计的单测
 * @details
 * 控制平面注入点全部走替身，语义队列为真实 SPSC 队列，引擎独占一条测试线程，
 * 无 IO / 无特权。覆盖：
 *  - 订阅命令的落地：登记后事件送达，过滤器未命中则不投递；
 *  - 销号回执：摘表时回调，回执后不再有该流的投递；
 *  - 停机排空：已入队的命令仍会落地，其后的清表给表内每条流回调回执，
 *    故注销入队被拒不影响回执的送达；
 *  - 停机后入队被拒并计数；
 *  - 统计口径：归属未落定按事件计数（一条事件最多一次）、订阅流峰值只增不减。
 * @author red-shinku
 * @date 2026.10.11
 */

#include "agent/runtime_engine/src/runtime_engine.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <thread>
#include <unordered_map>
#include <vector>

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

/// 轮询等待条件成立；超时返回条件的最终值
template <class Pred>
bool wait_until(Pred done, int timeout_ms = 3000)
{
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        if (done()) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return done();
}

// ---- 替身 ----

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
    void register_contextID(hng::Process p, ContextDeriveDecision nd,
                            uint32_t) override
    {
        ctx[Key{p}] = nd.contextID;
    }
    void unregister_contextID(hng::Process p) override { ctx.erase(Key{p}); }
    void bind_to_ctxroot(hng::Process, hng::Process) override {}
    void set_attr(hng::Process, uint32_t, hng::contextattr) override {}
};

/// 进程注册 / 注销通知的替身；只由引擎线程写，测试在 join 之后读
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

/// 角色继承通知的替身；只由引擎线程写，测试在 join 之后读
class FakeRoleJoin final : public RoleJoinService {
   public:
    std::vector<std::pair<hng::Process, hng::Process>> bound;

    void bind_to_role(hng::Process child, hng::Process parent) override
    {
        bound.emplace_back(child, parent);
    }
};

/// 静态角色归属的替身：命中固定表，其余为空
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
    std::optional<hng::Role> role(uint32_t) const override
    {
        return std::nullopt;
    }
    std::vector<hng::Role> roles() const override { return {}; }
    std::vector<hng::Role> supervised_roles() const override { return {}; }
    std::optional<hng::role::RoleIdentity> identity(uint32_t) const override
    {
        return std::nullopt;
    }
    std::vector<hng::Process> members(uint32_t) const override { return {}; }
};

/// 系统订阅者替身：只记原子量，便于跨线程读
class DecisionSinkStub final : public RuntimeDecisionSink {
   public:
    std::atomic<int> calls{0};
    std::atomic<uint32_t> last_pid{0};
    std::atomic<bool> should_derive{false};
    std::atomic<uint32_t> decision_context{0};

    void on_event(const hng::RuntimeEvent& ev,
                  const ContextDeriveDecision& decision) override
    {
        last_pid.store(ev.runtimeInfo.process.pid);
        should_derive.store(decision.should_derive);
        decision_context.store(decision.contextID);
        calls.fetch_add(1);
    }
};

/// CLI 订阅流替身：只记原子量，便于跨线程读
class EventSinkStub final : public RuntimeEventSink {
   public:
    std::atomic<int> calls{0};
    std::atomic<uint32_t> last_pid{0};

    void on_event(const hng::RuntimeEvent ev) override
    {
        last_pid.store(ev.runtimeInfo.process.pid);
        calls.fetch_add(1);
    }
};

/// 注销回执替身
class AckStub final : public UnsubscribeAck {
   public:
    std::atomic<bool> called{false};
    std::atomic<int> times{0};

    void on_unsubscribed() override
    {
        ++times;
        called.store(true);
    }
};

// ---- 装配 ----

/// 替身 + 真实 SPSC 队列 + 被测引擎；引擎不拥有任何注入点
struct Env {
    FakeContextService ctx_svc;
    FakeProcessJoin process_join;
    FakeRoleJoin role_join;
    FakeRoleLookup role_lookup;
    hng::SPSC_Queue<hng::syscall_semantic_data> sys_q{64};
    hng::SPSC_Queue<hng::file_semantic_data> file_q{64};

    ContextMaintainer cm;
    RuntimeEngine engine{&sys_q,        &file_q,    &cm,
                         &process_join, &role_join, &role_lookup};

    Env() { cm.set_context_service(&ctx_svc, &ctx_svc, &ctx_svc); }
};

// ---- 事件构造 ----

hng::syscall_semantic_data make_credential(uint32_t pid, uint64_t pstart)
{
    hng::syscall_semantic_data ev;
    ev.head.pid             = pid;
    ev.head.pid_start_time  = pstart;
    ev.head.ppid            = 0;
    ev.head.ppid_start_time = 0;
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

// ---- 停机排空（单线程可确定复现）----

void run_drain_on_stop()
{
    Env env;
    EventSinkStub cli;
    AckStub ack;

    // 命令在 run() 之前入队，停机后 run() 才被调用
    CHECK(env.engine.subscribe(&cli, RuntimeInfoFilter{}, &ack),
          "停机前订阅入队被接受");
    env.engine.unsubscribe(&cli);

    env.engine.stop();
    env.engine.run();  // 已停机：不取事件，但把已入队的命令落地

    CHECK(ack.called.load(), "停机排空时注销回执仍会送达");
    CHECK(env.engine.stats().peak_cli_streams == 1,
          "已入队的订阅在排空时落地（峰值可见）");
}

/// 注销入队被拒时回执仍会送达——这正是把回执挂在订阅表状态上、而不是挂在
/// 注销命令投递上的意义
void run_ack_from_clear_on_rejected_unsubscribe()
{
    Env env;
    EventSinkStub cli;
    AckStub ack;

    CHECK(env.engine.subscribe(&cli, RuntimeInfoFilter{}, &ack),
          "停机前订阅入队被接受");
    env.engine.stop();
    env.engine.unsubscribe(&cli);  // 已停机：入队被拒，只记账

    env.engine.run();  // 排空已入队的订阅，随后清表

    CHECK(ack.called.load(), "注销被拒不改变回执保证");
    CHECK(env.engine.stats().queue_rejected == 1, "被拒的注销计入统计");
}

void run_reject_subscribe_after_stop()
{
    Env env;
    EventSinkStub cli;
    AckStub ack;

    env.engine.stop();
    CHECK(!env.engine.subscribe(&cli, RuntimeInfoFilter{}, &ack),
          "停机后订阅被拒");

    env.engine.run();

    CHECK(!ack.called.load(), "订阅从未成立，不会有回执");

    const RuntimeEngineStats s = env.engine.stats();
    CHECK(s.queue_rejected == 1, "被拒的命令计数");
    CHECK(s.peak_cli_streams == 0, "被拒的命令不改变订阅表");
}

// ---- 主循环：投递、过滤器、注销 ----

void run_live_delivery()
{
    Env env;
    DecisionSinkStub sys;
    EventSinkStub all_cli;
    EventSinkStub file_cli;

    env.engine.add_system_sink(&sys);
    std::thread engine_thread([&env] { env.engine.run(); });

    // 归属已落定的进程：角色与上下文都可查得
    const hng::Process settled               = mk(2002, 20);
    env.role_lookup.role_of_pid[settled.pid] = 7;
    env.ctx_svc.seed(settled, 55);

    // 订阅命令是通知写，落地时间不定，故反复投递直至观察到送达
    AckStub all_ack;
    AckStub file_ack;
    CHECK(env.engine.subscribe(&all_cli, RuntimeInfoFilter{}, &all_ack),
          "全选流入队被接受");
    CHECK(env.engine.subscribe(
              &file_cli,
              RuntimeInfoFilter{}.set_etype({hng::EventType::FILE_EVENT}),
              &file_ack),
          "文件流入队被接受");

    for (int i = 0; i < 300 && all_cli.calls.load() == 0; ++i) {
        env.sys_q.push(make_credential(1001, 10));
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    CHECK(all_cli.calls.load() > 0, "全选流应收到事件");
    CHECK(file_cli.calls.load() == 0, "过滤器未命中则不投递");
    CHECK(sys.calls.load() > 0, "系统订阅者按全量投递");
    CHECK(sys.last_pid.load() == 1001, "系统订阅者收到事件主体");

    for (int i = 0; i < 300 && file_cli.calls.load() == 0; ++i) {
        env.file_q.push(make_file(3003, 30, "/tmp/a"));
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    CHECK(file_cli.calls.load() > 0, "命中过滤器应收到");
    CHECK(file_cli.last_pid.load() == 3003, "CLI 订阅流收到事件主体");

    // 注销：以回执为准，回执后不再有该流的回调
    env.engine.unsubscribe(&all_cli);
    CHECK(wait_until([&all_ack] { return all_ack.called.load(); }),
          "注销回执应送达");
    const int calls_after_ack = all_cli.calls.load();

    const int sys_before      = sys.calls.load();
    env.sys_q.push(make_credential(1001, 10));
    CHECK(
        wait_until([&sys, sys_before] { return sys.calls.load() > sys_before; }),
        "注销后引擎仍在消费事件");
    CHECK(all_cli.calls.load() == calls_after_ack, "回执后不再有该流的回调");

    env.engine.stop();
    engine_thread.join();

    CHECK(file_ack.called.load(), "停机清表时未注销的流也收到回执");

    // 峰值只增不减：注销后表内只剩一条，峰值仍是两条
    CHECK(env.engine.stats().peak_cli_streams == 2, "订阅流峰值只增不减");
}

// ---- 统计口径 ----

void run_stats_unsettled()
{
    Env env;
    DecisionSinkStub sys;

    env.engine.add_system_sink(&sys);
    std::thread engine_thread([&env] { env.engine.run(); });

    // pid 1001：角色与上下文都查不到；pid 2002：两者都查得到
    const hng::Process settled               = mk(2002, 20);
    env.role_lookup.role_of_pid[settled.pid] = 7;
    env.ctx_svc.seed(settled, 55);

    const int kUnsettled = 3;
    const int kSettled   = 2;
    for (int i = 0; i < kUnsettled; ++i) {
        env.sys_q.push(make_credential(1001, 10));
    }
    for (int i = 0; i < kSettled; ++i) {
        env.sys_q.push(make_credential(2002, 20));
    }

    CHECK(
        wait_until([&sys] { return sys.calls.load() == kUnsettled + kSettled; }),
        "全部事件应被消费");

    env.engine.stop();
    engine_thread.join();

    const RuntimeEngineStats s = env.engine.stats();
    CHECK(sys.calls.load() == kUnsettled + kSettled, "事件全部投递");
    CHECK(s.unsettled_events == static_cast<uint64_t>(kUnsettled),
          "归属未落定按事件计数，一条事件最多计一次");
    CHECK(s.queue_rejected == 0, "正常停机前无被拒命令");
    CHECK(s.peak_cli_streams == 0, "无 CLI 订阅流");
}

// ---- 生命周期事件驱动控制平面 ----

void run_lifecycle_dispatch()
{
    Env env;
    DecisionSinkStub sys;
    env.engine.add_system_sink(&sys);

    std::thread engine_thread([&env] { env.engine.run(); });

    hng::syscall_semantic_data birth;
    birth.head.pid             = 4004;
    birth.head.pid_start_time  = 40;
    birth.head.ppid            = 10;
    birth.head.ppid_start_time = 100;
    birth.head.type            = hng::EventType::SYSCALL_EVENT;
    birth.data.emplace<hng::process_semantic_data>().set_syscall_name("fork");
    env.sys_q.push(std::move(birth));

    env.sys_q.push(make_credential(4004, 40));
    CHECK(wait_until([&sys] { return sys.calls.load() >= 2; }),
          "两条事件应被消费");

    env.engine.stop();
    engine_thread.join();

    CHECK(env.process_join.registered.size() == 1, "诞生事件驱动进程注册");
    CHECK(env.role_join.bound.size() == 1, "诞生事件驱动角色继承");
    CHECK(sys.calls.load() == 2, "两条事件各投递一次");
}

}  // namespace

int main()
{
    run_drain_on_stop();
    run_ack_from_clear_on_rejected_unsubscribe();
    run_reject_subscribe_after_stop();
    run_live_delivery();
    run_stats_unsettled();
    run_lifecycle_dispatch();

    if (g_fail) {
        std::fprintf(stderr, "TOTAL FAILURES: %d\n", g_fail);
        return 1;
    }
    std::printf("ALL PASS\n");
    return 0;
}
