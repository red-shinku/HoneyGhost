/**
 * @file test_runtime_event_dispatcher.cc
 * @brief RuntimeEventDispatcher 订阅表与分发的单测
 * @details
 * 订阅者全部走替身，无 IO / 无特权。覆盖：
 *  - 两张表的分发顺序：先系统订阅表、后 CLI 订阅表；
 *  - 系统订阅表全量投递并附带决策，CLI 订阅表只投递过滤器命中者；
 *  - 每个 CLI 订阅流的过滤器互相独立；
 *  - 同一 sink 重复登记不占两个表项，过滤器与回执以最后一次为准；
 *  - 摘除：命中为 true、缺席为空操作且返回 false，不影响其他流与系统表；
 *  - 摘除与清空各自回调该流的销号回执，且回执至多一次；
 *  - 清空：不再投递，且不触碰订阅者对象。
 * @author red-shinku
 * @date 2026.10.11
 */

#include "agent/runtime_engine/src/runtime_event_dispatcher.hpp"

#include <cstdint>
#include <cstdio>
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

/// 跨订阅者的调用序列，用于断言分发顺序
struct CallLog {
    std::vector<int> ids;
};

/// 系统订阅者替身：记录调用序号、事件主体与收到的决策
class DecisionSinkStub final : public RuntimeDecisionSink {
   public:
    DecisionSinkStub(CallLog& log, int id) : log_(&log), id_(id) {}

    int calls         = 0;
    uint32_t last_pid = 0;
    ContextDeriveDecision last_decision{};

    void on_event(const hng::RuntimeEvent& ev,
                  const ContextDeriveDecision& decision) override
    {
        ++calls;
        log_->ids.push_back(id_);
        last_pid      = ev.runtimeInfo.process.pid;
        last_decision = decision;
    }

   private:
    CallLog* log_;
    int id_;
};

/// CLI 订阅流替身：记录调用序号与收到的事件主体
class EventSinkStub final : public RuntimeEventSink {
   public:
    EventSinkStub(CallLog& log, int id) : log_(&log), id_(id) {}

    int calls = 0;
    std::vector<uint32_t> pids;

    void on_event(const hng::RuntimeEvent ev) override
    {
        ++calls;
        log_->ids.push_back(id_);
        pids.push_back(ev.runtimeInfo.process.pid);
    }

   private:
    CallLog* log_;
    int id_;
};

/// 销号回执替身：只记回调次数
class AckStub final : public UnsubscribeAck {
   public:
    int calls = 0;

    void on_unsubscribed() override { ++calls; }
};

hng::RuntimeEvent mk_event(uint32_t pid, uint32_t roleID, uint32_t contextID,
                           hng::EventType etype)
{
    hng::RuntimeEvent ev{};
    ev.runtimeInfo.process   = mk(pid, pid * 10);
    ev.runtimeInfo.etype     = etype;
    ev.runtimeInfo.roleID    = roleID;
    ev.runtimeInfo.contextID = contextID;
    return ev;
}

const ContextDeriveDecision kDerived{true, 42, hng::contextattr::UNKNOWN};

// ---- 空表 ----

void run_empty_table()
{
    RuntimeEventDispatcher d;
    CHECK(d.cli_sink_count() == 0, "初始无 CLI 订阅流");
    d.dispatch(mk_event(1, 0, 0, hng::EventType::SYSCALL_EVENT), kDerived);
    CHECK(d.remove_cli_sink(nullptr) == false, "空表摘除为空操作");
}

// ---- 顺序与投递内容 ----

void run_order_and_payload()
{
    CallLog log;
    DecisionSinkStub sys_a(log, 1);
    DecisionSinkStub sys_b(log, 2);
    EventSinkStub cli(log, 3);

    RuntimeEventDispatcher d;
    d.add_system_sink(&sys_a);
    d.add_system_sink(&sys_b);
    d.add_cli_sink(&cli, RuntimeInfoFilter{}, nullptr);

    d.dispatch(mk_event(1001, 7, 33, hng::EventType::SYSCALL_EVENT), kDerived);

    CHECK((log.ids == std::vector<int>{1, 2, 3}),
          "先系统表后 CLI 表，表内按登记顺序");
    CHECK(sys_a.calls == 1 && sys_b.calls == 1 && cli.calls == 1,
          "三者各收到一次");
    CHECK(sys_a.last_pid == 1001, "系统订阅者收到事件主体");
    CHECK(
        sys_a.last_decision.should_derive && sys_a.last_decision.contextID == 42,
        "系统订阅者收到派生决策");
    CHECK(cli.pids == std::vector<uint32_t>{1001}, "CLI 订阅流收到事件主体");
}

// ---- CLI 过滤器 ----

void run_cli_filters()
{
    CallLog log;
    EventSinkStub all(log, 1);
    EventSinkStub by_role(log, 2);
    EventSinkStub by_pid(log, 3);
    EventSinkStub by_etype(log, 4);

    RuntimeEventDispatcher d;
    d.add_cli_sink(&all, RuntimeInfoFilter{}, nullptr);
    d.add_cli_sink(&by_role, RuntimeInfoFilter{}.set_role({7}), nullptr);
    d.add_cli_sink(&by_pid, RuntimeInfoFilter{}.set_process({1001}), nullptr);
    d.add_cli_sink(&by_etype,
                   RuntimeInfoFilter{}.set_etype({hng::EventType::FILE_EVENT}),
                   nullptr);

    d.dispatch(mk_event(1001, 7, 33, hng::EventType::SYSCALL_EVENT), kDerived);
    CHECK(all.calls == 1, "空过滤器全选");
    CHECK(by_role.calls == 1, "角色命中");
    CHECK(by_pid.calls == 1, "进程命中");
    CHECK(by_etype.calls == 0, "事件类型未命中则不投递");

    d.dispatch(mk_event(2002, 7, 33, hng::EventType::FILE_EVENT), kDerived);
    CHECK(all.calls == 2, "空过滤器全选(2)");
    CHECK(by_role.calls == 2, "角色仍命中");
    CHECK(by_pid.calls == 1, "进程不同则不投递");
    CHECK(by_etype.calls == 1, "文件事件命中");

    d.dispatch(mk_event(3003, 8, 44, hng::EventType::SYSCALL_EVENT), kDerived);
    CHECK(all.calls == 3, "空过滤器全选(3)");
    CHECK(by_role.calls == 2, "角色不同则不投递");
    CHECK(by_etype.calls == 1, "非文件事件不投递");

    d.dispatch(mk_event(1001, 7, 33, hng::EventType::FILE_EVENT), kDerived);
    CHECK(all.calls == 4, "空过滤器在后续事件上仍全选");
}

// ---- 重复登记 ----

void run_duplicate_cli_sink()
{
    CallLog log;
    EventSinkStub sink(log, 1);
    AckStub old_ack;
    AckStub new_ack;

    RuntimeEventDispatcher d;
    d.add_cli_sink(&sink, RuntimeInfoFilter{}.set_role({7}), &old_ack);
    d.add_cli_sink(&sink, RuntimeInfoFilter{}.set_role({8}), &new_ack);

    CHECK(d.cli_sink_count() == 1, "同一 sink 不占两个表项");
    CHECK(sink.calls == 0, "登记不回调");
    CHECK(old_ack.calls == 0, "重新登记不回调旧回执：它没有被摘表");

    d.dispatch(mk_event(1001, 7, 0, hng::EventType::SYSCALL_EVENT), kDerived);
    CHECK(sink.calls == 0, "旧过滤器不再生效");
    d.dispatch(mk_event(1001, 8, 0, hng::EventType::SYSCALL_EVENT), kDerived);
    CHECK(sink.calls == 1, "新过滤器生效");
}

// ---- 摘除 ----

void run_remove()
{
    CallLog log;
    DecisionSinkStub sys(log, 1);
    EventSinkStub a(log, 2);
    EventSinkStub b(log, 3);
    AckStub ack_a;
    AckStub ack_b;

    RuntimeEventDispatcher d;
    d.add_system_sink(&sys);
    d.add_cli_sink(&a, RuntimeInfoFilter{}, &ack_a);
    d.add_cli_sink(&b, RuntimeInfoFilter{}, &ack_b);

    CHECK(d.remove_cli_sink(&a), "表中存在则摘除成功");
    CHECK(ack_a.calls == 1, "摘除回调该流的销号回执");
    CHECK(d.cli_sink_count() == 1, "摘除后表项数减一");
    CHECK(!d.remove_cli_sink(&a), "重复摘除为空操作");
    CHECK(ack_a.calls == 1, "重复摘除不重复回调");
    CHECK(!d.remove_cli_sink(nullptr), "未登记的 sink 摘除为空操作");
    CHECK(ack_b.calls == 0, "摘除一个流不回调其他流的回执");

    d.dispatch(mk_event(1001, 0, 0, hng::EventType::SYSCALL_EVENT), kDerived);
    CHECK(a.calls == 0, "摘除后不再投递");
    CHECK(b.calls == 1, "其他订阅流不受影响");
    CHECK(sys.calls == 1, "摘除 CLI 流不影响系统订阅表");

    d.remove_cli_sink(&b);
    CHECK(ack_b.calls == 1, "摘除 B 回调其销号回执");
    CHECK(d.cli_sink_count() == 0, "全部摘除");

    d.clear();
    CHECK(ack_a.calls == 1 && ack_b.calls == 1,
          "已摘除的流不再被清空回调：回执至多一次");
}

// ---- 清空 ----

void run_clear()
{
    CallLog log;
    DecisionSinkStub sys(log, 1);
    EventSinkStub cli(log, 2);
    AckStub ack;

    RuntimeEventDispatcher d;
    d.add_system_sink(&sys);
    d.add_cli_sink(&cli, RuntimeInfoFilter{}, &ack);

    d.clear();
    CHECK(d.cli_sink_count() == 0, "清空后无 CLI 订阅流");
    CHECK(ack.calls == 1, "清空给表内每条流回调销号回执");

    d.dispatch(mk_event(1001, 0, 0, hng::EventType::SYSCALL_EVENT), kDerived);
    CHECK(sys.calls == 0 && cli.calls == 0, "清空后不再投递");

    // 清空不触碰订阅者：仍可重新登记并投递
    d.add_system_sink(&sys);
    d.add_cli_sink(&cli, RuntimeInfoFilter{}, &ack);
    d.dispatch(mk_event(1001, 0, 0, hng::EventType::SYSCALL_EVENT), kDerived);
    CHECK(sys.calls == 1 && cli.calls == 1, "重新登记后订阅者仍可用");
    CHECK(ack.calls == 1, "重新登记不回调回执");
}

}  // namespace

int main()
{
    run_empty_table();
    run_order_and_payload();
    run_cli_filters();
    run_duplicate_cli_sink();
    run_remove();
    run_clear();

    if (g_fail) {
        std::fprintf(stderr, "TOTAL FAILURES: %d\n", g_fail);
        return 1;
    }
    std::printf("ALL PASS\n");
    return 0;
}
