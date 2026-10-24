/**
 * @file test_context_manager.cc
 * @brief 上下文管理器的单元测试
 * @details
 * 覆盖 ContextManager（注意与工作平面的 test_context_maintainer 无关）：
 *  - 五个写接口经队列在消费线程上落地，注册后 lookup 命中根进程自指；
 *  - 主 context 与附属 context：同键二次注册进附属表，主表视图不变；
 *  - 挂靠与父链接的延迟收敛、父退出/删除后的降级与墓碑拒绝；
 *  - 延迟表容量、TTL 过期与墓碑过期；
 *  - 清理：进程退出时移出成员集，成员集清空才删 context；注销仍强制删除；
 *  - 幂等重放与未知注销：不改变表状态，后者计数；
 *  - stop() 语义：run() 之前 stop() 立即返回、已入队任务仍落地、此后入队被拒；
 *  - 多线程并发写入后状态自洽（供 TSAN 构建复验）。
 *
 * @note set_attr 覆盖属性索引的同步；ATTACK/EXTRA_ATTACK 的预留钩子仍无从断言。
 * @author red_shinku
 * @date 2026.9.19
 */

#include "agent/control_plane/src/context_manager.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <functional>
#include <future>
#include <optional>
#include <thread>
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

using hng::contextattr;

hng::Process proc(uint32_t pid, uint64_t start)
{
    return hng::Process{pid, start};
}

ContextParentRef parent_ref(hng::Process parent, bool expected = true)
{
    return ContextParentRef{parent, expected};
}

ContextDeriveDecision decision(uint32_t context_id, contextattr attr)
{
    return ContextDeriveDecision{ContextDecisionKind::DERIVE, context_id, attr};
}

bool has_id(const std::vector<uint32_t>& ids, uint32_t id)
{
    return std::find(ids.begin(), ids.end(), id) != ids.end();
}

/// 轮询等待断言成立：落地在消费线程上，断言点只能等
bool wait_until(const std::function<bool()>& pred, int timeout_ms = 5000)
{
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return pred();
}

/// 起 run() 线程，析构时停止并 join
class Runner {
   public:
    explicit Runner(ContextManager& manager)
        : manager_(manager), thread_([this] { manager_.run(); })
    {
    }

    ~Runner()
    {
        manager_.stop();
        thread_.join();
    }

    Runner(const Runner&)            = delete;
    Runner& operator=(const Runner&) = delete;

   private:
    ContextManager& manager_;
    std::thread thread_;
};

/// 注册一个 context 根并等它落地，再断言查询命中
void register_root(ContextManager& manager, hng::Process root,
                   uint32_t context_id, const char* what)
{
    manager.register_context(root, decision(context_id, contextattr::UNKNOWN),
                             {});
    CHECK(wait_until(
              [&] { return manager.lookup(root).value_or(0) == context_id; }),
          what);
}

/// 用一个新根的注册当屏障：它落地即说明此前的写都已落地
void barrier(ContextManager& manager, uint32_t pid)
{
    manager.register_context(proc(pid, pid * 10),
                             decision(pid, contextattr::UNKNOWN), {});
    CHECK(wait_until(
              [&] { return manager.lookup(proc(pid, pid * 10)).has_value(); }),
          "屏障应落地");
}

/// 可控时钟：只随测试推进，供延迟表与墓碑的寿命用例
struct FakeClock {
    hng::RelationTimePoint now{};
};

void run_register_and_lookup()
{
    ContextManager manager;
    Runner runner(manager);

    register_root(manager, proc(100, 1000), 7, "注册后应能查到该 context");
    CHECK(!manager.lookup(proc(100, 9999)).has_value(),
          "同 pid 不同 start_time 应失配");
    CHECK(!manager.lookup(proc(101, 1000)).has_value(), "未注册进程应失配");
    CHECK(!manager.lookup_extra(proc(100, 1000)).has_value(),
          "未注册附属 context 时应失配");

    // 幂等重放：同键同 contextID，不改变表状态
    manager.register_context(proc(100, 1000), decision(7, contextattr::UNKNOWN),
                             {});
    barrier(manager, 200);
    CHECK(manager.lookup(proc(100, 1000)).value_or(0) == 7,
          "幂等重放后主 context 不变");
    CHECK(!manager.lookup_extra(proc(100, 1000)).has_value(),
          "幂等重放不得产生附属 context");
    CHECK(wait_until([&] { return manager.stats().duplicate_context == 1; }),
          "重复注册主 context 应计数");
}

void run_extra_context()
{
    ContextManager manager;
    Runner runner(manager);

    register_root(manager, proc(100, 1000), 7, "注册后应能查到该 context");

    // 主注册接口不再把不同 contextID 转成附属 context
    manager.register_context(proc(100, 1000),
                             decision(8, contextattr::EXTRA_ATTACK), {});
    barrier(manager, 200);
    CHECK(manager.lookup(proc(100, 1000)).value_or(0) == 7,
          "重复主注册不得覆盖主 context");
    CHECK(!manager.lookup_extra(proc(100, 1000)).has_value(),
          "主注册接口不得产生附属 context");

    // 附属 context 经显式接口登记
    manager.register_extra_context(proc(100, 1000), 8, contextattr::EXTRA_ATTACK);
    CHECK(wait_until([&] {
              return manager.lookup_extra(proc(100, 1000)).value_or(0) == 8;
          }),
          "显式登记应产生附属 context");
    CHECK(manager.lookup(proc(100, 1000)).value_or(0) == 7,
          "附属 context 不得覆盖主 context");

    // 已有附属 context 时保留首个
    manager.register_extra_context(proc(100, 1000), 9, contextattr::EXTRA_ATTACK);
    barrier(manager, 201);
    CHECK(manager.lookup_extra(proc(100, 1000)).value_or(0) == 8,
          "重复附属登记应保留首个");

    // 无主 context 的附属登记被丢弃并计数
    manager.register_extra_context(proc(300, 3000), 10,
                                   contextattr::EXTRA_ATTACK);
    CHECK(wait_until([&] { return manager.stats().extra_orphaned == 1; }),
          "无主 context 的附属登记应计数");
    CHECK(!manager.lookup_extra(proc(300, 3000)).has_value(),
          "无主 context 不得登记附属 context");
}

void run_bind_to_ctxroot()
{
    ContextManager manager;
    Runner runner(manager);

    // 父已落定：子继承父的 context 根
    register_root(manager, proc(100, 1000), 7, "父进程应注册成功");
    manager.bind_to_ctxroot(proc(101, 1001), parent_ref(proc(100, 1000)));
    CHECK(wait_until(
              [&] { return manager.lookup(proc(101, 1001)).value_or(0) == 7; }),
          "子进程应继承父进程的 context");
    CHECK(manager.stats().ctxroot_parent_unsettled == 0, "父已落定时不应计数");

    // expected=false 且父未落定：直接降级，不暂存
    manager.bind_to_ctxroot(proc(300, 3000), parent_ref(proc(301, 3001), false));
    CHECK(wait_until([&] { return manager.stats().bind_orphaned == 1; }),
          "未观测父的挂靠应直接降级");
    CHECK(manager.stats().pending_depth == 0, "expected=false 不得暂存");
    CHECK(!manager.lookup(proc(300, 3000)).has_value(), "降级后归属应保持待定");

    // expected=true 且父未落定：暂存，父落地后自动挂靠
    manager.bind_to_ctxroot(proc(400, 4000), parent_ref(proc(401, 4001)));
    CHECK(wait_until([&] { return manager.stats().pending_depth == 1; }),
          "已观测父未落定时应暂存挂靠");
    CHECK(manager.stats().bind_orphaned == 1, "暂存不应计孤儿");
    CHECK(!manager.lookup(proc(400, 4000)).has_value(),
          "父未落定时归属应保持待定");

    manager.register_context(proc(401, 4001), decision(20, contextattr::UNKNOWN),
                             {});
    CHECK(wait_until(
              [&] { return manager.lookup(proc(400, 4000)).value_or(0) == 20; }),
          "父落地后应自动挂靠");
    CHECK(wait_until([&] { return manager.stats().pending_depth == 0; }),
          "挂靠收敛后延迟表应清空");
    CHECK(manager.stats().pending_resolved >= 1, "收敛应计入已解决");
}

void run_derive_child_before_parent()
{
    ContextManager manager;
    Runner runner(manager);

    const hng::Process child  = proc(500, 5000);
    const hng::Process parent = proc(501, 5010);

    manager.register_context(child, decision(55, contextattr::UNKNOWN),
                             parent_ref(parent));
    CHECK(wait_until([&] { return manager.lookup(child).value_or(0) == 55; }),
          "DERIVE 子 context 应立即存在");
    CHECK(wait_until([&] { return manager.stats().pending_depth == 1; }),
          "父未落定时子应暂存父链接");
    CHECK(manager.stats().pending_deferred == 1, "应计入延迟");
    CHECK(manager.stats().ctxroot_parent_unsettled == 1,
          "父未落定进入延迟表应计数");

    manager.register_context(parent, decision(50, contextattr::UNKNOWN), {});
    CHECK(wait_until([&] { return manager.stats().pending_depth == 0; }),
          "父落地后父链接应回填");
    CHECK(wait_until([&] { return manager.stats().pending_resolved == 1; }),
          "回填应计入已解决");
    CHECK(manager.stats().parent_missing == 0, "父已落地时不应计父缺失");
    CHECK(manager.lookup(child).value_or(0) == 55, "子 context 不变");
}

void run_keep_child_before_parent()
{
    ContextManager manager;
    Runner runner(manager);

    const hng::Process child  = proc(510, 5100);
    const hng::Process parent = proc(511, 5110);

    manager.bind_to_ctxroot(child, parent_ref(parent));
    CHECK(wait_until([&] { return manager.stats().pending_depth == 1; }),
          "KEEP 子应暂存挂靠");
    CHECK(!manager.lookup(child).has_value(), "父未落定时 KEEP 子无归属");

    manager.register_context(parent, decision(60, contextattr::UNKNOWN), {});
    CHECK(wait_until([&] { return manager.lookup(child).value_or(0) == 60; }),
          "父落地后 KEEP 子应挂靠成功");
    CHECK(wait_until([&] { return manager.stats().pending_depth == 0; }),
          "挂靠收敛后延迟表应清空");
    CHECK(manager.stats().bind_orphaned == 0, "成功收敛不应计孤儿");
    CHECK(manager.stats().pending_resolved == 1, "收敛应计入已解决");
}

void run_chained_keep()
{
    ContextManager manager;
    Runner runner(manager);

    const hng::Process grand  = proc(520, 5200);
    const hng::Process parent = proc(521, 5210);
    const hng::Process child  = proc(522, 5220);

    manager.bind_to_ctxroot(parent, parent_ref(grand));
    manager.bind_to_ctxroot(child, parent_ref(parent));
    CHECK(wait_until([&] { return manager.stats().pending_depth == 2; }),
          "链式 KEEP 应各暂存一条");

    manager.register_context(grand, decision(70, contextattr::UNKNOWN), {});
    CHECK(wait_until([&] { return manager.lookup(parent).value_or(0) == 70; }),
          "祖父落地后父应挂靠");
    CHECK(wait_until([&] { return manager.lookup(child).value_or(0) == 70; }),
          "父挂靠后子应递归收敛");
    CHECK(wait_until([&] { return manager.stats().pending_depth == 0; }),
          "链式收敛后延迟表应清空");
    CHECK(manager.stats().pending_resolved == 2, "两条都应计入已解决");
    CHECK(manager.stats().bind_orphaned == 0, "链式收敛不应计孤儿");
}

void run_parent_exit_context_alive()
{
    ContextManager manager;
    Runner runner(manager);

    const hng::Process root   = proc(530, 5300);
    const hng::Process member = proc(531, 5310);
    const hng::Process child  = proc(532, 5320);

    register_root(manager, root, 80, "根进程应注册成功");
    manager.bind_to_ctxroot(member, parent_ref(root));
    CHECK(wait_until([&] { return manager.lookup(member).value_or(0) == 80; }),
          "成员应挂靠成功");

    manager.on_process_exited(root);
    CHECK(wait_until([&] { return !manager.lookup(root).has_value(); }),
          "退出的根应失配");
    CHECK(manager.members(80).has_value(), "仍有实成员时 context 应保留");

    manager.bind_to_ctxroot(child, parent_ref(root));
    CHECK(wait_until([&] { return manager.lookup(child).value_or(0) == 80; }),
          "父退出但 context 存活时仍可挂靠");
}

void run_parent_gone_orphans_child()
{
    ContextManager manager;
    Runner runner(manager);

    const hng::Process child  = proc(540, 5400);
    const hng::Process parent = proc(541, 5410);

    manager.bind_to_ctxroot(child, parent_ref(parent));
    CHECK(wait_until([&] { return manager.stats().pending_depth == 1; }),
          "子应暂存挂靠");

    manager.on_process_exited(parent);
    CHECK(wait_until([&] { return manager.stats().pending_depth == 0; }),
          "父退出应取走等待项");
    CHECK(wait_until([&] { return manager.stats().bind_orphaned == 1; }),
          "父消失后等待中的 KEEP 子应计孤儿");
    CHECK(!manager.lookup(child).has_value(), "子应保持未归属");
}

void run_exit_before_register()
{
    ContextManager manager;
    Runner runner(manager);

    const hng::Process dead = proc(550, 5500);
    manager.on_process_exited(dead);
    CHECK(wait_until([&] { return manager.stats().tombstone_depth == 1; }),
          "退出应先写墓碑");

    manager.register_context(dead, decision(90, contextattr::UNKNOWN), {});
    CHECK(wait_until([&] { return manager.stats().late_register == 1; }),
          "墓碑应拒绝迟到注册");
    CHECK(!manager.lookup(dead).has_value(), "迟到注册不得产生 context");

    const hng::Process gone = proc(551, 5510);
    manager.on_process_exited(gone);
    CHECK(wait_until([&] { return manager.stats().tombstone_depth == 2; }),
          "第二个退出应写墓碑");
    manager.bind_to_ctxroot(gone, parent_ref(dead));
    CHECK(wait_until([&] { return manager.stats().late_bind == 1; }),
          "墓碑应拒绝迟到挂靠");
    CHECK(!manager.lookup(gone).has_value(), "迟到挂靠不得产生归属");

    // 父已退出且没有存活 context：新挂靠直接降级
    const hng::Process orphan = proc(552, 5520);
    manager.bind_to_ctxroot(orphan, parent_ref(dead));
    CHECK(wait_until([&] { return manager.stats().bind_orphaned == 1; }),
          "父已退出且无 context 时应计孤儿");
    CHECK(!manager.lookup(orphan).has_value(), "孤儿应保持未归属");
}

void run_tombstone_hits()
{
    ContextManager manager;
    Runner runner(manager);

    const hng::Process dead = proc(950, 9500);
    manager.on_process_exited(dead);
    CHECK(wait_until([&] { return manager.stats().tombstone_hits > 0; }),
          "退出解析命中墓碑应计数");

    const uint64_t before = manager.stats().tombstone_hits;
    manager.register_context(dead, decision(98, contextattr::UNKNOWN), {});
    CHECK(wait_until([&] { return manager.stats().late_register == 1; }),
          "迟到注册应被墓碑拒绝");
    CHECK(wait_until([&] { return manager.stats().tombstone_hits > before; }),
          "迟到注册查墓碑应继续计数");
}

void run_explicit_unregister_parent()
{
    ContextManager manager;
    Runner runner(manager);

    const hng::Process parent = proc(600, 6000);
    const hng::Process child  = proc(601, 6010);
    register_root(manager, parent, 96, "父进程应注册成功");

    manager.unregister_context(parent);
    CHECK(wait_until([&] { return !manager.lookup(parent).has_value(); }),
          "显式注销后父应失配");

    // 注销不写墓碑，允许同一身份重新注册。新挂靠先暂存，不得解析到已删 context
    manager.bind_to_ctxroot(child, parent_ref(parent));
    CHECK(wait_until([&] { return manager.stats().pending_depth == 1; }),
          "父 context 已删时应暂存挂靠");
    CHECK(!manager.lookup(child).has_value(), "不得挂到已删除的 context");
    CHECK(manager.stats().bind_orphaned == 0, "暂存期间不应计孤儿");

    manager.register_context(parent, decision(97, contextattr::UNKNOWN), {});
    CHECK(wait_until([&] { return manager.lookup(child).value_or(0) == 97; }),
          "父重新注册后挂靠应收敛");
    CHECK(wait_until([&] { return manager.stats().pending_depth == 0; }),
          "收敛后延迟表应清空");
}

void run_register_cancels_bind_wait()
{
    ContextManager manager;
    Runner runner(manager);

    const hng::Process child = proc(553, 5530);

    manager.bind_to_ctxroot(child, parent_ref(proc(554, 5540)));
    CHECK(wait_until([&] { return manager.stats().pending_depth == 1; }),
          "子应先暂存挂靠");

    manager.register_context(child, decision(95, contextattr::UNKNOWN), {});
    CHECK(wait_until([&] { return manager.stats().pending_depth == 0; }),
          "注册主 context 应取消自己的挂靠等待");
    CHECK(wait_until([&] { return manager.stats().pending_cancelled == 1; }),
          "取消应计数");
    CHECK(wait_until([&] { return manager.lookup(child).value_or(0) == 95; }),
          "注册后应归自身 context");
}

void run_exit_cancels_and_fails_waiters()
{
    ContextManager manager;
    Runner runner(manager);

    const hng::Process grand  = proc(560, 5600);
    const hng::Process parent = proc(561, 5610);
    const hng::Process child  = proc(562, 5620);

    manager.bind_to_ctxroot(parent, parent_ref(grand));
    manager.bind_to_ctxroot(child, parent_ref(parent));
    CHECK(wait_until([&] { return manager.stats().pending_depth == 2; }),
          "父子应各暂存一条挂靠");

    manager.on_process_exited(parent);
    CHECK(wait_until([&] { return manager.stats().pending_depth == 0; }),
          "退出应清空相关等待项");
    CHECK(manager.stats().pending_cancelled == 1, "应取消父自己的等待项");
    CHECK(manager.stats().bind_orphaned == 1, "无根时应级联失败子等待者");
    CHECK(!manager.lookup(parent).has_value(), "父应失配");
    CHECK(!manager.lookup(child).has_value(), "子应保持未归属");
}

void run_ownership_conflict()
{
    ContextManager manager;
    Runner runner(manager);

    const hng::Process root_a = proc(570, 5700);
    const hng::Process root_b = proc(571, 5710);
    const hng::Process child  = proc(572, 5720);

    register_root(manager, root_a, 71, "根 A 应注册成功");
    register_root(manager, root_b, 72, "根 B 应注册成功");

    manager.bind_to_ctxroot(child, parent_ref(root_a));
    CHECK(wait_until([&] { return manager.lookup(child).value_or(0) == 71; }),
          "首次挂靠应成功");

    // 同根重复挂靠：幂等
    manager.bind_to_ctxroot(child, parent_ref(root_a));
    barrier(manager, 900);
    CHECK(manager.lookup(child).value_or(0) == 71, "同根重复挂靠应保持归属");
    CHECK(manager.stats().ownership_conflict == 0, "同根不应计冲突");

    // 异根挂靠：保留首条并计数
    manager.bind_to_ctxroot(child, parent_ref(root_b));
    CHECK(wait_until([&] { return manager.stats().ownership_conflict == 1; }),
          "异根挂靠应计冲突");
    CHECK(manager.lookup(child).value_or(0) == 71, "归属不可变，应保留首条");
}

void run_capacity_degrade()
{
    ContextManagerOptions options;
    options.link_pending.capacity = 0;
    options.bind_pending.capacity = 0;
    ContextManager manager(options);
    Runner runner(manager);

    const hng::Process derived = proc(580, 5800);
    const hng::Process kept    = proc(581, 5810);

    manager.register_context(derived, decision(81, contextattr::UNKNOWN),
                             parent_ref(proc(582, 5820)));
    manager.bind_to_ctxroot(kept, parent_ref(proc(583, 5830)));

    CHECK(wait_until([&] { return manager.stats().pending_rejected == 2; }),
          "容量为 0 时两类暂存都应被拒绝");
    CHECK(manager.stats().pending_depth == 0, "拒绝后不应有暂存");
    CHECK(manager.stats().parent_missing == 1, "父链接拒绝应计父缺失");
    CHECK(manager.stats().bind_orphaned == 1, "挂靠拒绝应计孤儿");
    CHECK(wait_until([&] { return manager.lookup(derived).value_or(0) == 81; }),
          "主 context 应立即插入");
    CHECK(!manager.lookup(kept).has_value(), "被拒绝的挂靠应保持未归属");
}

void run_ttl_expiry()
{
    FakeClock clock;
    ContextManagerOptions options;
    options.link_pending.ttl = std::chrono::milliseconds(100);
    options.bind_pending.ttl = std::chrono::milliseconds(100);
    options.tombstones.ttl   = std::chrono::milliseconds(100);
    options.now              = [&clock] { return clock.now; };
    ContextManager manager(options);
    Runner runner(manager);

    const hng::Process derived = proc(590, 5900);
    const hng::Process kept    = proc(591, 5910);

    manager.register_context(derived, decision(91, contextattr::UNKNOWN),
                             parent_ref(proc(592, 5920)));
    manager.bind_to_ctxroot(kept, parent_ref(proc(593, 5930)));
    CHECK(wait_until([&] { return manager.stats().pending_depth == 2; }),
          "两条关系应先暂存");

    clock.now += std::chrono::milliseconds(101);
    barrier(manager, 999);
    CHECK(wait_until([&] { return manager.stats().pending_expired == 2; }),
          "过期任务应在下次落地时清理");
    CHECK(wait_until([&] { return manager.stats().pending_depth == 0; }),
          "过期后延迟表应清空");
    CHECK(manager.stats().parent_missing == 1, "链接过期为父缺失");
    CHECK(manager.stats().bind_orphaned == 1, "挂靠过期为孤儿");
    CHECK(!manager.lookup(kept).has_value(), "过期挂靠应保持未归属");

    // 墓碑过期后，同一进程的迟到注册可以落地
    const hng::Process dead = proc(594, 5940);
    manager.on_process_exited(dead);
    CHECK(wait_until([&] { return manager.stats().tombstone_depth == 1; }),
          "退出应写墓碑");
    clock.now += std::chrono::milliseconds(101);
    manager.register_context(dead, decision(94, contextattr::UNKNOWN), {});
    CHECK(wait_until([&] { return manager.lookup(dead).value_or(0) == 94; }),
          "墓碑过期后迟到注册应可落地");
    CHECK(manager.stats().late_register == 0, "墓碑过期后不应计迟到注册");
    CHECK(wait_until([&] { return manager.stats().tombstone_depth == 0; }),
          "过期墓碑应被清理");
}

void run_cleanup()
{
    ContextManager manager;
    Runner runner(manager);

    // 根退出但成员仍在：context 保留，根不再属于成员集
    register_root(manager, proc(100, 1000), 7, "根进程应注册成功");
    manager.bind_to_ctxroot(proc(101, 1001), parent_ref(proc(100, 1000)));
    CHECK(wait_until(
              [&] { return manager.lookup(proc(101, 1001)).value_or(0) == 7; }),
          "成员应挂靠成功");

    manager.on_process_exited(proc(100, 1000));
    CHECK(
        wait_until([&] { return !manager.lookup(proc(100, 1000)).has_value(); }),
        "退出根应失配");
    CHECK(manager.lookup(proc(101, 1001)).value_or(0) == 7, "其余成员应保留归属");
    {
        const std::optional<ContextProcessSet> set = manager.members(7);
        CHECK(set.has_value() && set->root == proc(100, 1000),
              "仍有实成员时 context 应保留，键仍是已退出的根");
        CHECK(set->members.size() == 1 && set->members[0] == proc(101, 1001),
              "成员集只含实进程，不补回已退出的根");
    }

    manager.on_process_exited(proc(101, 1001));
    CHECK(wait_until([&] { return !manager.members(7).has_value(); }),
          "最后一个成员退出后 context 应删除");
    CHECK(!manager.lookup(proc(101, 1001)).has_value(), "最后成员退出后应失配");

    // 注销：主 context 与同键的附属 context 一并清除
    register_root(manager, proc(200, 2000), 9, "第二个根应注册成功");
    manager.register_extra_context(proc(200, 2000), 10,
                                   contextattr::EXTRA_ATTACK);
    CHECK(wait_until([&] {
              return manager.lookup_extra(proc(200, 2000)).value_or(0) == 10;
          }),
          "附属 context 应注册成功");

    manager.unregister_context(proc(200, 2000));
    CHECK(
        wait_until([&] { return !manager.lookup(proc(200, 2000)).has_value(); }),
        "注销后应失配");
    CHECK(!manager.lookup_extra(proc(200, 2000)).has_value(),
          "注销应连同附属 context 一并清除");
    CHECK(manager.stats().unknown_unregister == 0, "已知根的注销不应计数");

    // 注销未注册的根：丢弃并计数
    manager.unregister_context(proc(500, 5000));
    CHECK(wait_until([&] { return manager.stats().unknown_unregister == 1; }),
          "注销未注册的根应计数");
}

void run_set_attr()
{
    ContextManager manager;
    Runner runner(manager);

    register_root(manager, proc(100, 1000), 7, "根进程应注册成功");

    // 属性没有查询入口，只覆盖「不崩、不动其他状态」
    manager.set_attr(proc(100, 1000), 7, contextattr::NORMAL);
    manager.set_attr(proc(100, 1000), 7,
                     contextattr::ATTACK);  // 非 UNKNOWN 起不再变更
    manager.set_attr(proc(100, 1000), 8,
                     contextattr::NORMAL);  // contextID 不匹配
    manager.set_attr(proc(999, 9990), 7, contextattr::NORMAL);  // 未注册进程
    barrier(manager, 200);
    CHECK(manager.lookup(proc(100, 1000)).value_or(0) == 7,
          "set_attr 不得影响归属视图");
    CHECK(!manager.lookup(proc(999, 9990)).has_value(),
          "对未注册进程 set_attr 不应产生条目");

    CHECK(has_id(manager.contexts_by_attr(contextattr::NORMAL), 7),
          "UNKNOWN → NORMAL 应更新属性索引");
    CHECK(!has_id(manager.contexts_by_attr(contextattr::ATTACK), 7),
          "非 UNKNOWN 起不再变更");
    CHECK(!has_id(manager.contexts_by_attr(contextattr::NORMAL), 8),
          "contextID 不匹配不得改动");
}

void run_contexts_by_attr()
{
    ContextManager manager;
    Runner runner(manager);

    register_root(manager, proc(100, 1000), 7, "根进程应注册成功");
    CHECK(has_id(manager.contexts_by_attr(contextattr::UNKNOWN), 7),
          "新 context 应进入 UNKNOWN 索引");

    manager.set_attr(proc(100, 1000), 7, contextattr::ATTACK);
    CHECK(wait_until([&] {
              return has_id(manager.contexts_by_attr(contextattr::ATTACK), 7);
          }),
          "属性变更后应进入新索引");
    CHECK(!has_id(manager.contexts_by_attr(contextattr::UNKNOWN), 7),
          "属性变更后应退出旧索引");

    // 同键的附属 context 按其属性单独入索引
    manager.register_extra_context(proc(100, 1000), 8, contextattr::EXTRA_ATTACK);
    CHECK(wait_until([&] {
              return has_id(manager.contexts_by_attr(contextattr::EXTRA_ATTACK),
                            8);
          }),
          "附属 context 应按其属性入索引");

    manager.unregister_context(proc(100, 1000));
    CHECK(wait_until([&] {
              return manager.contexts_by_attr(contextattr::ATTACK).empty() &&
                     manager.contexts_by_attr(contextattr::EXTRA_ATTACK).empty();
          }),
          "注销后两个索引都不应残留");

    // 多个 context 时按 ID 升序
    register_root(manager, proc(200, 2000), 30, "第二个根应注册成功");
    register_root(manager, proc(300, 3000), 10, "第三个根应注册成功");
    const std::vector<uint32_t> ids =
        manager.contexts_by_attr(contextattr::UNKNOWN);
    CHECK(ids.size() == 2 && ids[0] == 10 && ids[1] == 30,
          "应按 contextID 升序返回");
}

void run_members_by_context()
{
    ContextManager manager;
    Runner runner(manager);

    CHECK(!manager.members(7).has_value(), "未知 contextID 应返回空");

    register_root(manager, proc(100, 1000), 7, "根进程应注册成功");

    // 根自指：初始成员只有根
    std::optional<ContextProcessSet> set = manager.members(7);
    CHECK(set.has_value() && set->root == proc(100, 1000), "应返回根进程");
    CHECK(set->members.size() == 1 && set->members[0] == proc(100, 1000),
          "根进程应在成员集中");

    manager.bind_to_ctxroot(proc(102, 1002), parent_ref(proc(100, 1000)));
    manager.bind_to_ctxroot(proc(101, 1001), parent_ref(proc(100, 1000)));
    CHECK(wait_until([&] {
              auto current = manager.members(7);
              return current.has_value() && current->members.size() == 3;
          }),
          "挂靠后成员集应增加");

    set = manager.members(7);
    CHECK(set->members.size() == 3 && set->members[0].pid == 100 &&
              set->members[1].pid == 101 && set->members[2].pid == 102,
          "成员应按 pid 升序并含根");

    // 附属 context 共用同一根键与成员集
    manager.register_extra_context(proc(100, 1000), 8, contextattr::EXTRA_ATTACK);
    CHECK(wait_until([&] { return manager.members(8).has_value(); }),
          "附属 context 应可查询");
    set = manager.members(8);
    CHECK(set.has_value() && set->root == proc(100, 1000) &&
              set->members.size() == 3,
          "附属 context 应返回同一根与成员集");

    // 成员退出后从成员集消失
    manager.on_process_exited(proc(101, 1001));
    CHECK(wait_until([&] {
              auto current = manager.members(7);
              return current.has_value() && current->members.size() == 2;
          }),
          "成员退出后应从成员集移除");
    set = manager.members(7);
    CHECK(set->members.size() == 2 && set->members[0].pid == 100 &&
              set->members[1].pid == 102,
          "剩余成员应保持升序");

    // 根退出但成员仍在：context 与附属 context 保留，成员集只剩实进程
    manager.on_process_exited(proc(100, 1000));
    CHECK(wait_until([&] {
              auto current = manager.members(7);
              return current.has_value() && current->members.size() == 1;
          }),
          "根退出后仍有实成员，context 应保留");
    set = manager.members(7);
    CHECK(set.has_value() && set->root == proc(100, 1000) &&
              set->members[0] == proc(102, 1002),
          "成员集不补回已退出的根");
    CHECK(manager.members(8).has_value(), "附属 context 随主 context 保留");

    // 最后一个成员退出：主/附属 context 一并删除
    manager.on_process_exited(proc(102, 1002));
    CHECK(wait_until([&] {
              return !manager.members(7).has_value() &&
                     !manager.members(8).has_value();
          }),
          "最后一个成员退出后主/附属 context 应一并删除");
}

void run_stop_semantics()
{
    // run() 之前 stop()：run() 立即返回
    {
        ContextManager manager;
        manager.stop();
        manager.stop();  // 幂等

        std::packaged_task<void()> task([&manager] { manager.run(); });
        std::future<void> done = task.get_future();
        std::thread worker(std::move(task));
        const bool returned =
            done.wait_for(std::chrono::seconds(5)) == std::future_status::ready;
        CHECK(returned, "run() 之前 stop() 时 run() 应立即返回");
        if (returned) {
            worker.join();
        }
        else {
            worker.detach();  // 卡住的线程不能 join，交由进程退出兜底
        }
    }

    // 已入队的任务在 stop() 之后仍被落地
    {
        ContextManager manager;
        manager.register_context(proc(100, 1000),
                                 decision(7, contextattr::UNKNOWN), {});
        manager.stop();
        manager.run();
        CHECK(manager.lookup(proc(100, 1000)).value_or(0) == 7,
              "stop() 之后已入队的任务应被落地");
    }

    // stop() 之后的入队被拒（队列契约），不落地
    {
        ContextManager manager;
        manager.stop();
        manager.register_context(proc(200, 2000),
                                 decision(9, contextattr::UNKNOWN), {});
        manager.run();  // 队列为空，应直接返回
        CHECK(!manager.lookup(proc(200, 2000)).has_value(),
              "停止后的入队不得落地");
    }
}

void run_concurrent_writers()
{
    ContextManager manager;
    Runner runner(manager);

    constexpr int kThreads = 4;
    constexpr int kEach    = 100;

    std::vector<std::thread> writers;
    for (int t = 0; t < kThreads; ++t) {
        writers.emplace_back([&manager, t] {
            for (int i = 0; i < kEach; ++i) {
                const uint32_t pid = 1000 + static_cast<uint32_t>(t) * 100 +
                                     static_cast<uint32_t>(i);
                // 同一线程内先注册后注销：队列保序，注销不会先于注册到达
                manager.register_context(proc(pid, pid * 10),
                                         decision(pid, contextattr::UNKNOWN), {});
                manager.bind_to_ctxroot(proc(pid + 1, pid * 10 + 1),
                                        parent_ref(proc(pid, pid * 10)));
                manager.unregister_context(proc(pid, pid * 10));
            }
        });
    }
    for (std::thread& writer : writers) {
        writer.join();
    }

    barrier(manager, 9000);
    for (int t = 0; t < kThreads; ++t) {
        for (int i = 0; i < kEach; ++i) {
            const uint32_t pid =
                1000 + static_cast<uint32_t>(t) * 100 + static_cast<uint32_t>(i);
            CHECK(!manager.lookup(proc(pid, pid * 10)).has_value(),
                  "并发注册注销后不应有残留");
        }
    }
    CHECK(manager.stats().unknown_unregister == 0, "保序下不应出现未知注销");
    CHECK(manager.stats().ctxroot_parent_unsettled == 0,
          "注册先于挂靠落地，不应出现父未落定");
    CHECK(manager.stats().pending_depth == 0, "并发用例不应残留等待项");
    CHECK(manager.stats().bind_orphaned == 0, "注册先于挂靠，不应出现孤儿");
}

}  // namespace

int main()
{
    run_register_and_lookup();
    run_extra_context();
    run_bind_to_ctxroot();
    run_derive_child_before_parent();
    run_keep_child_before_parent();
    run_chained_keep();
    run_parent_exit_context_alive();
    run_parent_gone_orphans_child();
    run_exit_before_register();
    run_tombstone_hits();
    run_explicit_unregister_parent();
    run_register_cancels_bind_wait();
    run_exit_cancels_and_fails_waiters();
    run_ownership_conflict();
    run_capacity_degrade();
    run_ttl_expiry();
    run_cleanup();
    run_set_attr();
    run_contexts_by_attr();
    run_members_by_context();
    run_stop_semantics();
    run_concurrent_writers();

    if (g_fail) {
        std::fprintf(stderr, "TOTAL FAILURES: %d\n", g_fail);
        return 1;
    }
    std::printf("ALL PASS\n");
    return 0;
}
