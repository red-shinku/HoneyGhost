/**
 * @file test_context_store.cc
 * @brief 上下文关系存储层的单元测试
 * @details
 * 单线程直接调用 ContextStore，不建队列、不起线程：
 *  - 注册与查询：根自指、lookup/lookup_extra/contexts_by_attr/members 排序；
 *  - 父解析：归属索引、自身仍是根、墓碑 last_root 与 context_id 三条回退；
 *  - 暂存与降级：父未落定暂存、expected=false 不暂存、父退出级联失败；
 *  - 重复与冲突：同键保留首条、异根改绑计数、附属登记要求主 context 存在；
 *  - 收敛：链式挂靠递归收敛、注册取消自己的挂靠等待；
 *  - 过期：链接/挂靠 TTL、墓碑 TTL；
 *  - 退出与删除：成员退出、成员清空删 context、根先退而成员仍在、显式注销、
 *    未知注销计数与幂等注销；
 *  - 属性：UNKNOWN 才能变更、附属属性、实际变更返回新属性；
 *  - 容量为 0 的降级。
 *
 * @author red_shinku
 * @date 2026.10.24
 */

#include "agent/control_plane/src/context_store.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <optional>
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

bool has_id(const std::vector<uint32_t>& ids, uint32_t id)
{
    return std::find(ids.begin(), ids.end(), id) != ids.end();
}

/// 可控时钟：只随测试推进，供延迟表与墓碑的寿命用例
struct FakeClock {
    hng::RelationTimePoint now{};
};

ContextStoreOptions timed_options(FakeClock& clock)
{
    ContextStoreOptions options;
    options.link_pending.ttl = std::chrono::milliseconds(100);
    options.bind_pending.ttl = std::chrono::milliseconds(100);
    options.tombstones.ttl   = std::chrono::milliseconds(100);
    options.now              = [&clock] { return clock.now; };
    return options;
}

void run_register_and_query()
{
    ContextStore store;
    store.add_context(proc(100, 1000), 7, contextattr::UNKNOWN, {});

    CHECK(store.lookup(proc(100, 1000)).value_or(0) == 7,
          "注册后应能查到该 context");
    CHECK(!store.lookup(proc(100, 9999)).has_value(),
          "同 pid 不同 start_time 应失配");
    CHECK(!store.lookup(proc(101, 1000)).has_value(), "未注册进程应失配");
    CHECK(!store.lookup_extra(proc(100, 1000)).has_value(),
          "未登记附属 context 应失配");

    const std::optional<ContextProcessSet> set = store.members(7);
    CHECK(set.has_value() && set->root == proc(100, 1000), "应返回根进程");
    CHECK(set->members.size() == 1 && set->members[0] == proc(100, 1000),
          "根进程应在成员集中");
    CHECK(!store.members(8).has_value(), "未知 contextID 应返回空");
    CHECK(has_id(store.contexts_by_attr(contextattr::UNKNOWN), 7),
          "新 context 应进入 UNKNOWN 索引");

    // 多个 context 时按 ID 升序
    store.add_context(proc(200, 2000), 30, contextattr::UNKNOWN, {});
    store.add_context(proc(300, 3000), 10, contextattr::UNKNOWN, {});
    const std::vector<uint32_t> ids =
        store.contexts_by_attr(contextattr::UNKNOWN);
    CHECK(ids.size() == 3 && ids[0] == 7 && ids[1] == 10 && ids[2] == 30,
          "应按 contextID 升序返回");
}

void run_extra_context()
{
    ContextStore store;
    store.add_context(proc(100, 1000), 7, contextattr::UNKNOWN, {});
    store.add_extra_context(proc(100, 1000), 8, contextattr::EXTRA_ATTACK);

    CHECK(store.lookup_extra(proc(100, 1000)).value_or(0) == 8,
          "附属 context 应可查询");
    CHECK(store.lookup(proc(100, 1000)).value_or(0) == 7,
          "附属 context 不得覆盖主 context");
    CHECK(has_id(store.contexts_by_attr(contextattr::EXTRA_ATTACK), 8),
          "附属 context 应按其属性入索引");
    const std::optional<ContextProcessSet> extra = store.members(8);
    CHECK(extra.has_value() && extra->root == proc(100, 1000) &&
              extra->members.size() == 1,
          "附属 context 应返回同一根与成员集");

    // 已有附属 context 时保留首个
    store.add_extra_context(proc(100, 1000), 9, contextattr::EXTRA_ATTACK);
    CHECK(store.lookup_extra(proc(100, 1000)).value_or(0) == 8,
          "重复附属登记应保留首个");
    CHECK(!has_id(store.contexts_by_attr(contextattr::EXTRA_ATTACK), 9),
          "被丢弃的附属 context 不得入索引");

    // 无主 context 的附属登记被丢弃并计数
    store.add_extra_context(proc(300, 3000), 10, contextattr::EXTRA_ATTACK);
    CHECK(store.stats().extra_orphaned == 1, "无主 context 的附属登记应计数");
    CHECK(!store.lookup_extra(proc(300, 3000)).has_value(),
          "无主 context 不得登记附属 context");
}

void run_parent_resolution_owner_index()
{
    ContextStore store;
    store.add_context(proc(100, 1000), 7, contextattr::UNKNOWN, {});
    store.bind_to_root(proc(101, 1001), parent_ref(proc(100, 1000)));
    CHECK(store.lookup(proc(101, 1001)).value_or(0) == 7,
          "子进程应继承父进程的 context");

    // 已归属的成员本身也能解析回同一个根
    store.bind_to_root(proc(102, 1002), parent_ref(proc(101, 1001)));
    CHECK(store.lookup(proc(102, 1002)).value_or(0) == 7,
          "经归属索引应解析到同一根");
    CHECK(store.stats().ctxroot_parent_unsettled == 0, "父已落定时不应计数");

    const std::optional<ContextProcessSet> set = store.members(7);
    CHECK(set.has_value() && set->members.size() == 3, "挂靠后成员集应增加");
    CHECK(set->members[0].pid == 100 && set->members[1].pid == 101 &&
              set->members[2].pid == 102,
          "成员应按 pid 升序并含根");
}

void run_parent_resolution_self_root()
{
    ContextStore store;
    store.add_context(proc(530, 5300), 80, contextattr::UNKNOWN, {});
    store.bind_to_root(proc(531, 5310), parent_ref(proc(530, 5300)));
    store.on_process_exited(proc(530, 5300));
    CHECK(!store.lookup(proc(530, 5300)).has_value(), "退出的根应失配");
    CHECK(store.members(80).has_value(), "仍有实成员时 context 应保留");

    // 归属索引已随退出清除，锚点自身仍是存活 context 的根
    store.bind_to_root(proc(532, 5320), parent_ref(proc(530, 5300)));
    CHECK(store.lookup(proc(532, 5320)).value_or(0) == 80,
          "根退出但 context 存活时仍可挂靠");
}

void run_parent_resolution_tombstone_last_root()
{
    ContextStore store;
    store.add_context(proc(100, 1000), 7, contextattr::UNKNOWN, {});
    store.bind_to_root(proc(101, 1001), parent_ref(proc(100, 1000)));
    store.on_process_exited(proc(101, 1001));
    CHECK(!store.lookup(proc(101, 1001)).has_value(), "退出的成员应失配");
    CHECK(store.members(7).has_value(), "根仍在时 context 应保留");

    store.bind_to_root(proc(102, 1002), parent_ref(proc(101, 1001)));
    CHECK(store.lookup(proc(102, 1002)).value_or(0) == 7,
          "墓碑 last_root 应回退到原 context");
    CHECK(store.stats().tombstone_hits > 0, "墓碑查询命中应计数");
}

void run_parent_resolution_tombstone_context_id()
{
    ContextStore store;
    store.add_context(proc(100, 1000), 80, contextattr::UNKNOWN, {});
    store.bind_to_root(proc(101, 1001), parent_ref(proc(100, 1000)));
    // 墓碑记下 last_root=根键 与 context_id=80
    store.on_process_exited(proc(101, 1001));
    // 显式注销删掉 80 与根记录，同一 contextID 换根重新注册
    store.remove_context(proc(100, 1000));
    store.add_context(proc(102, 1002), 80, contextattr::UNKNOWN, {});

    store.bind_to_root(proc(103, 1003), parent_ref(proc(101, 1001)));
    CHECK(store.lookup(proc(103, 1003)).value_or(0) == 80,
          "墓碑 context_id 应回退到仍存活的同 ID");
    const std::optional<ContextProcessSet> set = store.members(80);
    CHECK(set.has_value() && set->root == proc(102, 1002), "成员集应归新的根");
}

void run_parent_unsettled()
{
    ContextStore store;

    // expected=true 且父未落定：暂存，父落地后自动挂靠
    store.bind_to_root(proc(400, 4000), parent_ref(proc(401, 4001)));
    CHECK(store.stats().pending_depth == 1, "已观测父未落定时应暂存挂靠");
    CHECK(store.stats().pending_deferred == 1, "应计入延迟");
    CHECK(store.stats().ctxroot_parent_unsettled == 1,
          "父未落定进入延迟表应计数");
    CHECK(!store.lookup(proc(400, 4000)).has_value(), "父未落定时归属应保持待定");

    store.add_context(proc(401, 4001), 20, contextattr::UNKNOWN, {});
    CHECK(store.lookup(proc(400, 4000)).value_or(0) == 20, "父落地后应自动挂靠");
    CHECK(store.stats().pending_depth == 0, "挂靠收敛后延迟表应清空");
    CHECK(store.stats().pending_resolved == 1, "收敛应计入已解决");

    // expected=false 且父未落定：直接降级，不暂存
    store.bind_to_root(proc(300, 3000), parent_ref(proc(301, 3001), false));
    CHECK(store.stats().bind_orphaned == 1, "未观测父的挂靠应直接降级");
    CHECK(store.stats().pending_depth == 0, "expected=false 不得暂存");
    CHECK(!store.lookup(proc(300, 3000)).has_value(), "降级后归属应保持待定");

    // 派生 context 先于父落地：主 context 立即插入，父链接暂存
    store.add_context(proc(500, 5000), 55, contextattr::UNKNOWN,
                      parent_ref(proc(501, 5010)));
    CHECK(store.lookup(proc(500, 5000)).value_or(0) == 55,
          "DERIVE 子 context 应立即存在");
    CHECK(store.stats().pending_depth == 1, "父未落定时子应暂存父链接");
    store.add_context(proc(501, 5010), 50, contextattr::UNKNOWN, {});
    CHECK(store.stats().pending_depth == 0, "父落地后父链接应回填");
    CHECK(store.stats().parent_missing == 0, "父已落地时不应计父缺失");
}

void run_duplicate_and_conflict()
{
    ContextStore store;
    store.add_context(proc(100, 1000), 7, contextattr::UNKNOWN, {});
    store.add_context(proc(100, 1000), 8, contextattr::UNKNOWN, {});
    CHECK(store.lookup(proc(100, 1000)).value_or(0) == 7,
          "同键重复注册应保留首条");
    CHECK(store.stats().duplicate_context == 1, "重复注册应计数");

    store.add_context(proc(570, 5700), 71, contextattr::UNKNOWN, {});
    store.add_context(proc(571, 5710), 72, contextattr::UNKNOWN, {});
    store.bind_to_root(proc(572, 5720), parent_ref(proc(570, 5700)));
    store.bind_to_root(proc(572, 5720), parent_ref(proc(570, 5700)));
    CHECK(store.lookup(proc(572, 5720)).value_or(0) == 71,
          "同根重复挂靠应保持归属");
    CHECK(store.stats().ownership_conflict == 0, "同根不应计冲突");

    store.bind_to_root(proc(572, 5720), parent_ref(proc(571, 5710)));
    CHECK(store.stats().ownership_conflict == 1, "异根挂靠应计冲突");
    CHECK(store.lookup(proc(572, 5720)).value_or(0) == 71,
          "归属不可变，应保留首条");
}

void run_chained_convergence()
{
    ContextStore store;
    store.bind_to_root(proc(521, 5210), parent_ref(proc(520, 5200)));
    store.bind_to_root(proc(522, 5220), parent_ref(proc(521, 5210)));
    CHECK(store.stats().pending_depth == 2, "链式挂靠应各暂存一条");

    store.add_context(proc(520, 5200), 70, contextattr::UNKNOWN, {});
    CHECK(store.lookup(proc(521, 5210)).value_or(0) == 70, "祖父落地后父应挂靠");
    CHECK(store.lookup(proc(522, 5220)).value_or(0) == 70,
          "父挂靠后子应递归收敛");
    CHECK(store.stats().pending_depth == 0, "链式收敛后延迟表应清空");
    CHECK(store.stats().pending_resolved == 2, "两条都应计入已解决");
    CHECK(store.stats().bind_orphaned == 0, "链式收敛不应计孤儿");
}

void run_parent_exit_degrades()
{
    ContextStore store;
    store.bind_to_root(proc(540, 5400), parent_ref(proc(541, 5410)));
    CHECK(store.stats().pending_depth == 1, "子应暂存挂靠");

    store.on_process_exited(proc(541, 5410));
    CHECK(store.stats().pending_depth == 0, "父退出应取走等待项");
    CHECK(store.stats().bind_orphaned == 1, "父消失后等待中的 KEEP 子应计孤儿");
    CHECK(!store.lookup(proc(540, 5400)).has_value(), "子应保持未归属");

    // 级联失败：以退出的父为锚点的子等待者一并失败
    ContextStore chained;
    chained.bind_to_root(proc(561, 5610), parent_ref(proc(560, 5600)));
    chained.bind_to_root(proc(562, 5620), parent_ref(proc(561, 5610)));
    CHECK(chained.stats().pending_depth == 2, "父子应各暂存一条挂靠");

    chained.on_process_exited(proc(561, 5610));
    CHECK(chained.stats().pending_depth == 0, "退出应清空相关等待项");
    CHECK(chained.stats().pending_cancelled == 1, "应取消父自己的等待项");
    CHECK(chained.stats().bind_orphaned == 1, "无根时应级联失败子等待者");
    CHECK(!chained.lookup(proc(562, 5620)).has_value(), "子应保持未归属");
}

void run_register_cancels_wait()
{
    ContextStore store;
    store.bind_to_root(proc(553, 5530), parent_ref(proc(554, 5540)));
    CHECK(store.stats().pending_depth == 1, "子应先暂存挂靠");

    store.add_context(proc(553, 5530), 95, contextattr::UNKNOWN, {});
    CHECK(store.stats().pending_depth == 0,
          "注册主 context 应取消自己的挂靠等待");
    CHECK(store.stats().pending_cancelled == 1, "取消应计数");
    CHECK(store.lookup(proc(553, 5530)).value_or(0) == 95,
          "注册后应归自身 context");
}

void run_ttl_expiry()
{
    FakeClock clock;
    ContextStore store(timed_options(clock));

    store.add_context(proc(590, 5900), 91, contextattr::UNKNOWN,
                      parent_ref(proc(592, 5920)));
    store.bind_to_root(proc(591, 5910), parent_ref(proc(593, 5930)));
    CHECK(store.stats().pending_depth == 2, "两条关系应先暂存");

    clock.now += std::chrono::milliseconds(101);
    store.add_context(proc(599, 5990), 92, contextattr::UNKNOWN, {});
    CHECK(store.stats().pending_expired == 2, "过期关系应在下次落地时清理");
    CHECK(store.stats().pending_depth == 0, "过期后延迟表应清空");
    CHECK(store.stats().parent_missing == 1, "链接过期为父缺失");
    CHECK(store.stats().bind_orphaned == 1, "挂靠过期为孤儿");
    CHECK(!store.lookup(proc(591, 5910)).has_value(), "过期挂靠应保持未归属");

    // 墓碑过期后，同一进程的迟到注册可以落地
    store.on_process_exited(proc(594, 5940));
    CHECK(store.stats().tombstone_depth == 1, "退出应写墓碑");
    clock.now += std::chrono::milliseconds(101);
    store.add_context(proc(594, 5940), 94, contextattr::UNKNOWN, {});
    CHECK(store.lookup(proc(594, 5940)).value_or(0) == 94,
          "墓碑过期后迟到注册应可落地");
    CHECK(store.stats().late_register == 0, "墓碑过期后不应计迟到注册");
    CHECK(store.stats().tombstone_depth == 0, "过期墓碑应被清理");
}

void run_exit_and_cleanup()
{
    ContextStore store;
    store.add_context(proc(100, 1000), 7, contextattr::UNKNOWN, {});
    store.bind_to_root(proc(101, 1001), parent_ref(proc(100, 1000)));

    // 成员退出：从成员集移除，context 保留
    store.on_process_exited(proc(101, 1001));
    CHECK(!store.lookup(proc(101, 1001)).has_value(), "退出的成员应失配");
    std::optional<ContextProcessSet> set = store.members(7);
    CHECK(set.has_value() && set->members.size() == 1 &&
              set->members[0] == proc(100, 1000),
          "成员退出后应从成员集移除");

    // 根退出但成员仍在：context 保留，键仍是已退出的根
    store.bind_to_root(proc(102, 1002), parent_ref(proc(100, 1000)));
    store.on_process_exited(proc(100, 1000));
    CHECK(!store.lookup(proc(100, 1000)).has_value(), "退出的根应失配");
    CHECK(store.lookup(proc(102, 1002)).value_or(0) == 7,
          "根退出后其余成员应保留归属");
    set = store.members(7);
    CHECK(set.has_value() && set->root == proc(100, 1000) &&
              set->members.size() == 1 && set->members[0] == proc(102, 1002),
          "成员集只含实进程，不补回已退出的根");

    // 最后一个成员退出：context 删除
    store.on_process_exited(proc(102, 1002));
    CHECK(!store.members(7).has_value(), "最后一个成员退出后 context 应删除");
    CHECK(!store.lookup(proc(102, 1002)).has_value(), "最后成员退出后应失配");

    // 已退出进程的幂等注销：不计数
    store.remove_context(proc(100, 1000));
    CHECK(store.stats().unknown_unregister == 0, "已退出进程的注销应幂等");

    // 根退出导致成员集清空：主 context 与附属 context 一并删除
    store.add_context(proc(200, 2000), 9, contextattr::UNKNOWN, {});
    store.add_extra_context(proc(200, 2000), 10, contextattr::EXTRA_ATTACK);
    store.on_process_exited(proc(200, 2000));
    CHECK(!store.members(9).has_value(), "最后一个成员退出后 context 应删除");
    CHECK(!store.members(10).has_value(), "附属 context 应一并删除");

    // 显式注销强制删除：主 context 与同键的附属 context 一并清除
    store.add_context(proc(210, 2100), 11, contextattr::UNKNOWN, {});
    store.add_extra_context(proc(210, 2100), 12, contextattr::EXTRA_ATTACK);
    store.remove_context(proc(210, 2100));
    CHECK(!store.lookup(proc(210, 2100)).has_value(), "注销后应失配");
    CHECK(!store.lookup_extra(proc(210, 2100)).has_value(),
          "注销应连同附属 context 一并清除");
    CHECK(store.stats().unknown_unregister == 0, "已知根的注销不应计数");

    // 注销未注册的根：丢弃并计数
    store.remove_context(proc(500, 5000));
    CHECK(store.stats().unknown_unregister == 1, "注销未注册的根应计数");
}

void run_set_attr()
{
    ContextStore store;
    store.add_context(proc(100, 1000), 7, contextattr::UNKNOWN, {});

    const auto changed = store.set_attr(proc(100, 1000), 7, contextattr::NORMAL);
    CHECK(changed.value_or(contextattr::UNKNOWN) == contextattr::NORMAL,
          "UNKNOWN → NORMAL 应返回新属性");
    CHECK(has_id(store.contexts_by_attr(contextattr::NORMAL), 7),
          "属性变更后应进入新索引");
    CHECK(!has_id(store.contexts_by_attr(contextattr::UNKNOWN), 7),
          "属性变更后应退出旧索引");

    CHECK(!store.set_attr(proc(100, 1000), 7, contextattr::ATTACK).has_value(),
          "非 UNKNOWN 起不再变更，应返回空");
    CHECK(!has_id(store.contexts_by_attr(contextattr::ATTACK), 7),
          "非 UNKNOWN 起不改动属性索引");
    CHECK(!store.set_attr(proc(100, 1000), 8, contextattr::NORMAL).has_value(),
          "contextID 不匹配应返回空");
    CHECK(!store.set_attr(proc(999, 9990), 7, contextattr::NORMAL).has_value(),
          "目标不存在应返回空");
    CHECK(store.lookup(proc(100, 1000)).value_or(0) == 7,
          "set_attr 不得影响归属视图");

    // 附属 context 的属性同样只能由 UNKNOWN 变更
    store.add_extra_context(proc(100, 1000), 8, contextattr::UNKNOWN);
    const auto extra =
        store.set_attr(proc(100, 1000), 8, contextattr::EXTRA_ATTACK);
    CHECK(extra.value_or(contextattr::UNKNOWN) == contextattr::EXTRA_ATTACK,
          "附属属性 UNKNOWN 应可变");
    CHECK(has_id(store.contexts_by_attr(contextattr::EXTRA_ATTACK), 8),
          "附属属性变更应更新索引");
    CHECK(!store.set_attr(proc(100, 1000), 8, contextattr::NORMAL).has_value(),
          "附属属性已变更后不再变动");
}

void run_capacity_degrade()
{
    ContextStoreOptions options;
    options.link_pending.capacity = 0;
    options.bind_pending.capacity = 0;
    ContextStore store(options);

    store.add_context(proc(580, 5800), 81, contextattr::UNKNOWN,
                      parent_ref(proc(582, 5820)));
    store.bind_to_root(proc(581, 5810), parent_ref(proc(583, 5830)));
    CHECK(store.stats().pending_rejected == 2, "容量为 0 时两类暂存都应被拒绝");
    CHECK(store.stats().pending_depth == 0, "拒绝后不应有暂存");
    CHECK(store.stats().parent_missing == 1, "父链接拒绝应计父缺失");
    CHECK(store.stats().bind_orphaned == 1, "挂靠拒绝应计孤儿");
    CHECK(store.lookup(proc(580, 5800)).value_or(0) == 81,
          "主 context 应立即插入");
    CHECK(!store.lookup(proc(581, 5810)).has_value(), "被拒绝的挂靠应保持未归属");
}

}  // namespace

int main()
{
    run_register_and_query();
    run_extra_context();
    run_parent_resolution_owner_index();
    run_parent_resolution_self_root();
    run_parent_resolution_tombstone_last_root();
    run_parent_resolution_tombstone_context_id();
    run_parent_unsettled();
    run_duplicate_and_conflict();
    run_chained_convergence();
    run_parent_exit_degrades();
    run_register_cancels_wait();
    run_ttl_expiry();
    run_exit_and_cleanup();
    run_set_attr();
    run_capacity_degrade();

    if (g_fail) {
        std::fprintf(stderr, "TOTAL FAILURES: %d\n", g_fail);
        return 1;
    }
    std::printf("ALL PASS\n");
    return 0;
}
