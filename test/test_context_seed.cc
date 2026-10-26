/**
 * @file test_context_seed.cc
 * @brief context 初始计划与 CM seed 的单元测试
 * @details
 * 覆盖阶段 2：
 *  - 计划生成：根与默认派生、解释器父下的普通命令为 BIND、解释器子仍派生、
 *    父不在批内按根处理、exe 为空按非解释器、非法与重复条目忽略；
 *  - 计划顺序：父先子后，就绪集合按 pid 升序，contextID 从 1 起唯一；
 *  - 本地状态：seed 后首次 exec 返回 NONE，DERIVE 的 lookup_contextID 命中
 *    本地 ID，BIND 只查控制平面；
 *  - CM seed：只登记主 context、KEEP 并入父所属 context、成员集与属性索引与
 *    计划一致、无 pending、运行期统计不被改动；
 *  - 拒绝路径：乱序的 BIND 与 DERIVE 子、非法条目、重复 DERIVE/BIND、重复
 *    seed、未 seed 的 run()、stop-before-seed；
 *  - 生命周期：CONSTRUCTED → READY → RUNNING → STOPPED；
 *  - 集成：ContextMaintainer 与已 seed 的 ContextManager 归属一致。
 * @author red_shinku
 * @date 2026.10.25
 */

#include "agent/context_maintainer/include/context_maintainer.hpp"
#include "agent/context_maintainer/include/context_seed.hpp"
#include "agent/control_plane/include/context_component.hpp"
#include "agent/control_plane/include/context_seed_service.hpp"
#include "agent/control_plane/src/context_manager.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <future>
#include <optional>
#include <string>
#include <thread>
#include <utility>
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

hng::ProcessSeedEntry entry(uint32_t pid, uint64_t start, uint32_t ppid = 0,
                            uint64_t ppid_start = 0, std::string exe = {})
{
    hng::ProcessSeedEntry e;
    e.process         = hng::Process{pid, start};
    e.ppid            = ppid;
    e.ppid_start_time = ppid_start;
    e.exe             = std::move(exe);
    return e;
}

ContextSeedEntry seed_entry(ContextSeedKind kind, hng::Process process,
                            hng::Process parent, uint32_t contextID)
{
    ContextSeedEntry e;
    e.kind      = kind;
    e.process   = process;
    e.parent    = parent;
    e.contextID = contextID;
    e.attr      = contextattr::UNKNOWN;
    return e;
}

const ContextSeedEntry* find_entry(const ContextSeedPlan& plan, uint32_t pid)
{
    auto it = std::find_if(
        plan.entries.begin(), plan.entries.end(),
        [pid](const ContextSeedEntry& e) { return e.process.pid == pid; });
    return it == plan.entries.end() ? nullptr : &*it;
}

std::size_t count_kind(const ContextSeedPlan& plan, ContextSeedKind kind)
{
    return static_cast<std::size_t>(std::count_if(
        plan.entries.begin(), plan.entries.end(),
        [kind](const ContextSeedEntry& e) { return e.kind == kind; }));
}

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

/// 运行期统计全零：seed 不得改动其中任何一项
bool stats_all_zero(const ContextManagerStats& s)
{
    return s.pending_deferred == 0 && s.pending_resolved == 0 &&
           s.pending_rejected == 0 && s.pending_expired == 0 &&
           s.pending_cancelled == 0 && s.pending_depth == 0 &&
           s.bind_orphaned == 0 && s.extra_orphaned == 0 &&
           s.parent_missing == 0 && s.late_register == 0 && s.late_bind == 0 &&
           s.duplicate_context == 0 && s.ownership_conflict == 0 &&
           s.tombstone_hits == 0 && s.tombstone_depth == 0 &&
           s.ctxroot_parent_unsettled == 0 && s.unknown_unregister == 0;
}

bool run_returns_immediately(ContextManager& manager)
{
    std::packaged_task<void()> task([&manager] { manager.run(); });
    std::future<void> done = task.get_future();
    std::thread worker(std::move(task));
    const bool returned =
        done.wait_for(std::chrono::seconds(5)) == std::future_status::ready;
    if (returned) {
        worker.join();
    }
    else {
        worker.detach();  // 卡住的线程不能 join，交由进程退出兜底
    }
    return returned;
}

// ---- 计划生成：根与默认派生 ----
void run_plan_roots_and_derive()
{
    ContextMaintainer maintainer;
    hng::ProcessSeedBatch batch;
    batch.entries.push_back(entry(100, 1000, 0, 0, "/usr/sbin/nginx"));
    batch.entries.push_back(entry(101, 1010, 100, 1000, "/usr/sbin/nginx"));
    batch.entries.push_back(entry(102, 1020, 101, 1010, "/usr/sbin/nginx"));
    // 同一身份重复：首条有效；若被覆盖成解释器，101 会变成 BIND
    batch.entries.push_back(entry(100, 1000, 0, 0, "/bin/bash"));
    // 非法身份：忽略
    batch.entries.push_back(entry(0, 0, 0, 0, "/bin/bash"));
    batch.entries.push_back(entry(103, 0, 0, 0, "/bin/bash"));

    const ContextSeedPlan plan = maintainer.build_seed_plan(batch);
    CHECK(plan.entries.size() == 3, "非法与重复条目不应进入计划");

    const ContextSeedEntry* root = find_entry(plan, 100);
    CHECK(root != nullptr && root->kind == ContextSeedKind::DERIVE,
          "无父进程应为 DERIVE");
    CHECK(root != nullptr && root->parent.pid == 0 &&
              root->parent.pid_start_time == 0,
          "根进程的 parent 应为 pid 0");
    CHECK(root != nullptr && root->contextID == 1, "contextID 应从 1 起分配");
    CHECK(root != nullptr && root->attr == contextattr::UNKNOWN,
          "初始派生一律 UNKNOWN");

    const ContextSeedEntry* child = find_entry(plan, 101);
    CHECK(child != nullptr && child->kind == ContextSeedKind::DERIVE,
          "非解释器父的普通命令应派生");
    CHECK(child != nullptr && child->parent == proc(100, 1000),
          "派生条目应带父进程");
    CHECK(child != nullptr && child->contextID == 2, "第二个 contextID 应为 2");

    const ContextSeedEntry* grandchild = find_entry(plan, 102);
    CHECK(grandchild != nullptr && grandchild->kind == ContextSeedKind::DERIVE,
          "普通命令链应继续派生");
    CHECK(grandchild != nullptr && grandchild->contextID == 3,
          "第三个 contextID 应为 3");
}

// ---- 计划生成：解释器父下的普通命令为 BIND，解释器子仍派生 ----
void run_plan_interpreter_parent()
{
    ContextMaintainer maintainer;
    hng::ProcessSeedBatch batch;
    batch.entries.push_back(entry(200, 2000, 0, 0, "/bin/bash"));
    batch.entries.push_back(entry(201, 2010, 200, 2000, "/bin/ls"));
    batch.entries.push_back(entry(202, 2020, 200, 2000, "/bin/bash"));

    const ContextSeedPlan plan = maintainer.build_seed_plan(batch);
    CHECK(plan.entries.size() == 3, "计划应包含全部进程");

    const ContextSeedEntry* root = find_entry(plan, 200);
    CHECK(root != nullptr && root->kind == ContextSeedKind::DERIVE,
          "解释器根应派生");

    const ContextSeedEntry* command = find_entry(plan, 201);
    CHECK(command != nullptr && command->kind == ContextSeedKind::BIND,
          "解释器父 + 普通命令应为 BIND");
    CHECK(command != nullptr && command->contextID == 0, "BIND 不携带 contextID");
    CHECK(command != nullptr && command->parent == proc(200, 2000),
          "BIND 应带父进程");
    CHECK(count_kind(plan, ContextSeedKind::DERIVE) == 2, "解释器子仍应派生");
    CHECK(find_entry(plan, 202) != nullptr &&
              find_entry(plan, 202)->kind == ContextSeedKind::DERIVE,
          "解释器子不并入父 context");
}

// ---- 计划生成：父不在批内按根处理，其子仍以该父为父 ----
void run_plan_missing_parent()
{
    ContextMaintainer maintainer;
    hng::ProcessSeedBatch batch;
    // 父 300 不在批内：301 按根处理
    batch.entries.push_back(entry(301, 3010, 300, 3000, "/bin/ls"));
    // 401 的父 400 不在批内（401 成根）；402 的父 401 在批内
    batch.entries.push_back(entry(402, 4020, 401, 4010, "/bin/ls"));
    batch.entries.push_back(entry(401, 4010, 400, 4000, "/bin/cat"));

    const ContextSeedPlan plan     = maintainer.build_seed_plan(batch);
    const ContextSeedEntry* orphan = find_entry(plan, 301);
    CHECK(orphan != nullptr && orphan->kind == ContextSeedKind::DERIVE &&
              orphan->parent.pid == 0,
          "父不在批内的进程应按根处理");

    const ContextSeedEntry* middle = find_entry(plan, 401);
    CHECK(middle != nullptr && middle->kind == ContextSeedKind::DERIVE &&
              middle->parent.pid == 0,
          "父缺失的中间进程应成根");

    const ContextSeedEntry* leaf = find_entry(plan, 402);
    CHECK(leaf != nullptr && leaf->parent == proc(401, 4010),
          "子进程仍以批内父为父");
    CHECK(leaf != nullptr && leaf->kind == ContextSeedKind::DERIVE,
          "非解释器父下的子进程应派生");
}

// ---- 计划生成：exe 为空按非解释器 ----
void run_plan_empty_exe()
{
    ContextMaintainer maintainer;
    hng::ProcessSeedBatch batch;
    batch.entries.push_back(entry(500, 5000, 0, 0, ""));
    batch.entries.push_back(entry(501, 5010, 500, 5000, ""));
    batch.entries.push_back(entry(510, 5100, 0, 0, "/bin/bash"));
    batch.entries.push_back(entry(511, 5110, 510, 5100, ""));

    const ContextSeedPlan plan   = maintainer.build_seed_plan(batch);
    const ContextSeedEntry* root = find_entry(plan, 500);
    CHECK(root != nullptr && root->kind == ContextSeedKind::DERIVE,
          "exe 为空按非解释器，根仍派生");
    const ContextSeedEntry* plain = find_entry(plan, 501);
    CHECK(plain != nullptr && plain->kind == ContextSeedKind::DERIVE,
          "exe 为空的子进程不得被当作解释器而 BIND");
    const ContextSeedEntry* under_bash = find_entry(plan, 511);
    CHECK(under_bash != nullptr && under_bash->kind == ContextSeedKind::BIND,
          "解释器父下 exe 为空的子进程仍是普通命令");
}

// ---- 计划顺序：父先子后且按 pid 升序取就绪集合 ----
void run_plan_topological_order()
{
    ContextMaintainer maintainer;
    hng::ProcessSeedBatch batch;
    // 逆序给入，期望 600 610 620 700 650
    batch.entries.push_back(entry(650, 6500, 700, 7000, "/bin/ls"));
    batch.entries.push_back(entry(620, 6200, 610, 6100, "/bin/ls"));
    batch.entries.push_back(entry(610, 6100, 600, 6000, "/bin/ls"));
    batch.entries.push_back(entry(700, 7000, 0, 0, "/bin/ls"));
    batch.entries.push_back(entry(600, 6000, 0, 0, "/bin/ls"));

    const ContextSeedPlan plan           = maintainer.build_seed_plan(batch);
    const std::vector<uint32_t> expected = {600, 610, 620, 700, 650};
    bool order_ok                        = plan.entries.size() == expected.size();
    for (std::size_t i = 0; order_ok && i < expected.size(); ++i) {
        order_ok = plan.entries[i].process.pid == expected[i];
    }
    CHECK(order_ok, "拓扑序应按 pid 升序取就绪集合且父先子后");

    // 每个非根条目的父必须出现在它之前
    bool parent_first = true;
    for (std::size_t i = 0; i < plan.entries.size(); ++i) {
        const hng::Process parent = plan.entries[i].parent;
        if (parent.pid == 0) {
            continue;
        }
        bool seen = false;
        for (std::size_t j = 0; j < i; ++j) {
            seen = seen || plan.entries[j].process == parent;
        }
        parent_first = parent_first && seen;
    }
    CHECK(parent_first, "父进程必须先于子进程出现");

    bool unique_ids = true;
    for (std::size_t i = 0; i < plan.entries.size(); ++i) {
        unique_ids = unique_ids && plan.entries[i].contextID == i + 1;
    }
    CHECK(unique_ids, "contextID 应唯一且从 1 起按分配顺序递增");
}

// ---- 本地状态：首次 exec 返回 NONE，DERIVE 命中本地 ID ----
void run_plan_local_states()
{
    ContextMaintainer maintainer;
    hng::ProcessSeedBatch batch;
    batch.entries.push_back(entry(200, 2000, 0, 0, "/bin/bash"));
    batch.entries.push_back(entry(201, 2010, 200, 2000, "/bin/ls"));

    const ContextSeedPlan plan   = maintainer.build_seed_plan(batch);
    const ContextSeedEntry* root = find_entry(plan, 200);
    const ContextSeedEntry* kept = find_entry(plan, 201);
    CHECK(root != nullptr && kept != nullptr, "计划应包含两个进程");

    for (const ContextSeedEntry& e : plan.entries) {
        const ContextDeriveDecision d = maintainer.should_derive_context(
            e.process, e.parent, e.process.pid == 200 ? "/bin/bash" : "/bin/ls");
        CHECK(d.kind == ContextDecisionKind::NONE,
              "seed 落定后的首次 exec 不应再决策");
    }

    CHECK(maintainer.lookup_contextID(proc(200, 2000)) ==
              std::optional<uint32_t>(root->contextID),
          "DERIVE 应按本地 contextID 归因");
    CHECK(!maintainer.lookup_contextID(proc(201, 2010)).has_value(),
          "BIND 只查控制平面，未注入服务时无归属");
    CHECK(maintainer.stats().keep_parent_unobserved == 0,
          "计划生成不应改动运行统计");
}

// ---- CM seed：落地结果与计划一致 ----
void run_seed_matches_plan()
{
    ContextMaintainer maintainer;
    hng::ProcessSeedBatch batch;
    batch.entries.push_back(entry(1000, 10000, 0, 0, "/bin/bash"));
    batch.entries.push_back(entry(1001, 10010, 1000, 10000, "/bin/ls"));
    batch.entries.push_back(entry(1002, 10020, 1001, 10010, "/bin/cat"));
    const ContextSeedPlan plan = maintainer.build_seed_plan(batch);

    ContextManager manager;
    const ContextSeedReport report = manager.seed(plan);
    CHECK(report.inserted == count_kind(plan, ContextSeedKind::DERIVE),
          "inserted 应等于 DERIVE 条数");
    CHECK(report.bound == count_kind(plan, ContextSeedKind::BIND),
          "bound 应等于 BIND 条数");
    CHECK(report.duplicate == 0 && report.rejected_invalid == 0 &&
              report.rejected_out_of_order == 0 && report.rejected_state == 0,
          "合法计划不应被拒");

    const ContextSeedEntry* root = find_entry(plan, 1000);
    const ContextSeedEntry* kept = find_entry(plan, 1001);
    CHECK(root != nullptr && kept != nullptr, "计划应包含根与 BIND 子");

    CHECK(manager.lookup(proc(1000, 10000)) ==
              std::optional<uint32_t>(root->contextID),
          "根进程应命中自己的 context");
    CHECK(manager.lookup(proc(1001, 10010)) ==
              std::optional<uint32_t>(root->contextID),
          "KEEP 成员应归到父所属 context 的根");
    CHECK(manager.lookup(proc(1002, 10020)) ==
              std::optional<uint32_t>(find_entry(plan, 1002)->contextID),
          "非解释器父下的子进程应有自己的 context");
    CHECK(!manager.lookup_extra(proc(1000, 10000)).has_value(),
          "seed 不登记附属 context");

    const std::optional<ContextProcessSet> set = manager.members(root->contextID);
    CHECK(set.has_value() && set->root == proc(1000, 10000),
          "成员集的根应是计划中的根进程");
    CHECK(set.has_value() && set->members.size() == 2 &&
              set->members[0] == proc(1000, 10000) &&
              set->members[1] == proc(1001, 10010),
          "成员集应含根与 KEEP 成员");
    CHECK(manager.members(find_entry(plan, 1002)->contextID)
                  .value_or(ContextProcessSet{})
                  .members.size() == 1,
          "派生子孙不得并入父 context");

    std::vector<uint32_t> expected_ids;
    for (const ContextSeedEntry& e : plan.entries) {
        if (e.kind == ContextSeedKind::DERIVE) {
            expected_ids.push_back(e.contextID);
        }
    }
    std::sort(expected_ids.begin(), expected_ids.end());
    CHECK(manager.contexts_by_attr(contextattr::UNKNOWN) == expected_ids,
          "UNKNOWN 属性索引应与计划的 DERIVE 集合一致");
    CHECK(stats_all_zero(manager.stats()), "seed 不得改动运行期统计");
}

// ---- CM seed：乱序条目被拒且不落库 ----
void run_seed_out_of_order()
{
    // BIND 先于父：拒绝
    {
        ContextManager manager;
        ContextSeedPlan plan;
        plan.entries.push_back(seed_entry(ContextSeedKind::BIND, proc(800, 8000),
                                          proc(801, 8010), 0));
        plan.entries.push_back(
            seed_entry(ContextSeedKind::DERIVE, proc(801, 8010), proc(0, 0), 1));
        const ContextSeedReport report = manager.seed(plan);
        CHECK(report.rejected_out_of_order == 1, "父未落地的 BIND 应被拒");
        CHECK(report.inserted == 1 && report.bound == 0,
              "父落地后只插入根，不补挂靠");
        CHECK(!manager.lookup(proc(800, 8000)).has_value(),
              "被拒的 BIND 不得落库");
        CHECK(manager.lookup(proc(801, 8010)) == std::optional<uint32_t>(1),
              "父仍应落地");
    }
    // DERIVE 子先于父：拒绝
    {
        ContextManager manager;
        ContextSeedPlan plan;
        plan.entries.push_back(seed_entry(ContextSeedKind::DERIVE,
                                          proc(810, 8100), proc(811, 8110), 5));
        plan.entries.push_back(
            seed_entry(ContextSeedKind::DERIVE, proc(811, 8110), proc(0, 0), 1));
        const ContextSeedReport report = manager.seed(plan);
        CHECK(report.rejected_out_of_order == 1,
              "父 contextID 未落地的派生应被拒");
        CHECK(report.inserted == 1, "只应落地父");
        CHECK(!manager.lookup(proc(810, 8100)).has_value(), "被拒的派生不得落库");
        CHECK(manager.contexts_by_attr(contextattr::UNKNOWN) ==
                  std::vector<uint32_t>{1},
              "被拒的 contextID 不得进入属性索引");
    }
}

// ---- CM seed：非法条目与重复计数 ----
void run_seed_invalid_and_duplicates()
{
    ContextManager manager;
    ContextSeedPlan plan;
    // 非法：pid 为 0、start_time 为 0、DERIVE 无 contextID、BIND 带 contextID、
    // BIND 无父、父与自身相同
    plan.entries.push_back(
        seed_entry(ContextSeedKind::DERIVE, proc(0, 0), proc(0, 0), 1));
    plan.entries.push_back(
        seed_entry(ContextSeedKind::DERIVE, proc(900, 0), proc(0, 0), 2));
    plan.entries.push_back(
        seed_entry(ContextSeedKind::DERIVE, proc(901, 9010), proc(0, 0), 0));
    plan.entries.push_back(
        seed_entry(ContextSeedKind::BIND, proc(902, 9020), proc(903, 9030), 3));
    plan.entries.push_back(
        seed_entry(ContextSeedKind::BIND, proc(904, 9040), proc(0, 0), 0));
    plan.entries.push_back(
        seed_entry(ContextSeedKind::DERIVE, proc(905, 9050), proc(905, 9050), 4));
    // 首次插入、同键重复、contextID 被占用
    plan.entries.push_back(
        seed_entry(ContextSeedKind::DERIVE, proc(910, 9100), proc(0, 0), 10));
    plan.entries.push_back(
        seed_entry(ContextSeedKind::DERIVE, proc(910, 9100), proc(0, 0), 11));
    plan.entries.push_back(
        seed_entry(ContextSeedKind::DERIVE, proc(911, 9110), proc(0, 0), 10));
    plan.entries.push_back(
        seed_entry(ContextSeedKind::DERIVE, proc(912, 9120), proc(0, 0), 12));
    // BIND 首次落地、重复 BIND
    plan.entries.push_back(
        seed_entry(ContextSeedKind::BIND, proc(913, 9130), proc(910, 9100), 0));
    plan.entries.push_back(
        seed_entry(ContextSeedKind::BIND, proc(913, 9130), proc(912, 9120), 0));

    const ContextSeedReport report = manager.seed(plan);
    CHECK(report.rejected_invalid == 7, "非法条目与 contextID 冲突应被拒");
    CHECK(report.duplicate == 2, "重复 DERIVE 与重复 BIND 应各计一条");
    CHECK(report.rejected_out_of_order == 0, "父均已落地，不应计乱序");
    CHECK(report.inserted == 2, "只应插入两个主 context");
    CHECK(report.bound == 1, "只应并入一个成员");

    CHECK(!manager.lookup(proc(905, 9050)).has_value(),
          "父与自身相同的条目不得落库");
    CHECK(manager.lookup(proc(910, 9100)) == std::optional<uint32_t>(10),
          "重复 DERIVE 应保留首条");
    CHECK(!manager.lookup(proc(911, 9110)).has_value(),
          "contextID 被占用时应拒绝新根");
    CHECK(manager.lookup(proc(913, 9130)) == std::optional<uint32_t>(10),
          "重复 BIND 应保留首条归属");
    CHECK(manager.contexts_by_attr(contextattr::UNKNOWN) ==
              std::vector<uint32_t>({10, 12}),
          "只应登记两个主 context");
    CHECK(stats_all_zero(manager.stats()), "拒绝路径不得改动运行期统计");
}

// ---- CM seed 后运行期正常：重复注册仍计入运行期统计 ----
void run_runtime_stats_after_seed()
{
    ContextMaintainer maintainer;
    hng::ProcessSeedBatch batch;
    batch.entries.push_back(entry(1100, 11000, 0, 0, "/bin/bash"));
    batch.entries.push_back(entry(1101, 11010, 1100, 11000, "/bin/ls"));
    const ContextSeedPlan plan = maintainer.build_seed_plan(batch);

    ContextManager manager;
    manager.seed(plan);

    std::thread worker([&manager] { manager.run(); });
    CHECK(wait_until([&manager] {
              return manager.state() == hng::ComponentState::RUNNING;
          }),
          "seed 后 run() 应进入 RUNNING");

    // 已 seed 的根再次注册：保留首条，运行期 duplicate 统计递增
    manager.register_context(proc(1100, 11000),
                             ContextDeriveDecision{ContextDecisionKind::DERIVE, 7,
                                                   contextattr::UNKNOWN},
                             {});
    CHECK(
        wait_until([&manager] { return manager.stats().duplicate_context == 1; }),
        "运行期重复注册应计数");
    CHECK(manager.lookup(proc(1100, 11000)) == std::optional<uint32_t>(1),
          "运行期重复注册不得覆盖已 seed 的 context");

    manager.stop();
    worker.join();
    const ContextManagerStats after = manager.stats();
    CHECK(after.pending_depth == 0 && after.pending_deferred == 0 &&
              after.pending_resolved == 0 && after.pending_rejected == 0 &&
              after.pending_expired == 0 && after.pending_cancelled == 0,
          "运行期写入不应产生延迟关系");
}

// ---- 重复 seed 被拒且树不变 ----
void run_seed_twice_rejected()
{
    ContextMaintainer maintainer;
    hng::ProcessSeedBatch batch;
    batch.entries.push_back(entry(1200, 12000, 0, 0, "/bin/bash"));
    batch.entries.push_back(entry(1201, 12010, 1200, 12000, "/bin/ls"));
    const ContextSeedPlan plan = maintainer.build_seed_plan(batch);

    ContextManager manager;
    const ContextSeedReport first = manager.seed(plan);
    CHECK(first.rejected_state == 0, "首次 seed 应被接受");
    CHECK(manager.state() == hng::ComponentState::READY, "seed 后应为 READY");

    const ContextSeedReport second = manager.seed(plan);
    CHECK(second.rejected_state == 1, "重复 seed 应被拒");
    CHECK(second.inserted == 0 && second.bound == 0, "重复 seed 不得写表");
    CHECK(manager.contexts_by_attr(contextattr::UNKNOWN).size() == 1,
          "树不应变化");
    CHECK(manager.members(1).value_or(ContextProcessSet{}).members.size() == 2,
          "成员集不应变化");
}

// ---- 未 seed 的 run() 立即返回；stop-before-seed 后 seed 被拒 ----
void run_lifecycle_preconditions()
{
    {
        ContextManager manager;
        CHECK(run_returns_immediately(manager), "未 seed 的 run() 应立即返回");
        CHECK(manager.state() == hng::ComponentState::CONSTRUCTED,
              "未 seed 的 run() 不应改变状态");
    }
    {
        ContextManager manager;
        manager.stop();
        CHECK(manager.state() == hng::ComponentState::STOPPED,
              "stop-before-seed 应置 STOPPED");
        CHECK(manager.seed(ContextSeedPlan{}).rejected_state == 1,
              "STOPPED 后的 seed 应被拒");
        CHECK(run_returns_immediately(manager), "STOPPED 后的 run() 应立即返回");
    }
}

// ---- 状态迁移 CONSTRUCTED → READY → RUNNING → STOPPED ----
void run_state_transitions()
{
    ContextManager manager;
    CHECK(manager.state() == hng::ComponentState::CONSTRUCTED,
          "构造后应为 CONSTRUCTED");

    manager.seed(ContextSeedPlan{});
    CHECK(manager.state() == hng::ComponentState::READY, "seed 后应为 READY");

    std::thread worker([&manager] { manager.run(); });
    CHECK(wait_until([&manager] {
              return manager.state() == hng::ComponentState::RUNNING;
          }),
          "run() 应进入 RUNNING");

    manager.stop();
    worker.join();
    CHECK(manager.state() == hng::ComponentState::STOPPED,
          "run() 返回后应为 STOPPED");

    // 重新进入的 run() 被拒，状态不再变化
    CHECK(run_returns_immediately(manager), "STOPPED 后的 run() 应立即返回");
    CHECK(manager.state() == hng::ComponentState::STOPPED,
          "STOPPED 后的 run() 不应改变状态");
}

// ---- 公共句柄：经 ContextComponent 的 seed_service 落地 ----
void run_component_seed()
{
    ContextMaintainer maintainer;
    hng::ProcessSeedBatch batch;
    batch.entries.push_back(entry(1400, 14000, 0, 0, "/bin/bash"));
    batch.entries.push_back(entry(1401, 14010, 1400, 14000, "/bin/ls"));
    const ContextSeedPlan plan = maintainer.build_seed_plan(batch);

    auto component             = hng::make_context_component();
    CHECK(component->state() == hng::ComponentState::CONSTRUCTED,
          "组件初始应为 CONSTRUCTED");

    const ContextSeedReport report = component->seed_service().seed(plan);
    CHECK(report.inserted == 1 && report.bound == 1,
          "经组件 seed_service 应落地一个根与一个成员");
    CHECK(component->state() == hng::ComponentState::READY,
          "经组件 seed 后应为 READY");

    const auto root = component->lookup_service().lookup(proc(1400, 14000));
    CHECK(root == std::optional<uint32_t>(1), "组件查询面应看到 seed 的根");
}

// ---- 集成：ContextMaintainer 与已 seed 的 ContextManager 一致 ----
void run_integration_with_manager()
{
    ContextMaintainer maintainer;
    hng::ProcessSeedBatch batch;
    batch.entries.push_back(entry(1300, 13000, 0, 0, "/bin/bash"));
    batch.entries.push_back(entry(1301, 13010, 1300, 13000, "/bin/ls"));
    batch.entries.push_back(entry(1302, 13020, 1301, 13010, "/opt/tool"));
    batch.entries.push_back(entry(1303, 13030, 1300, 13000, "/usr/bin/python3"));
    const ContextSeedPlan plan = maintainer.build_seed_plan(batch);

    ContextManager manager;
    const ContextSeedReport report = manager.seed(plan);
    CHECK(report.rejected_state == 0 && report.rejected_invalid == 0 &&
              report.rejected_out_of_order == 0,
          "集成用例的计划应全部落地");

    maintainer.set_context_service(&manager, &manager, &manager);

    for (const hng::ProcessSeedEntry& e : batch.entries) {
        const std::optional<uint32_t> local =
            maintainer.lookup_contextID(e.process);
        const std::optional<uint32_t> store = manager.lookup(e.process);
        CHECK(local.has_value() && local == store,
              "lookup_contextID 应与 CM lookup 一致");
    }

    // BIND 成员的归因来自控制平面，与父的 context 相同
    const ContextSeedEntry* kept = find_entry(plan, 1301);
    CHECK(kept != nullptr && kept->kind == ContextSeedKind::BIND,
          "1301 应为 BIND");
    CHECK(maintainer.lookup_contextID(proc(1301, 13010)) ==
              manager.lookup(proc(1300, 13000)),
          "KEEP 成员应归到父 context");

    for (const hng::ProcessSeedEntry& e : batch.entries) {
        hng::Process parent{0, 0};
        if (e.ppid != 0) {
            parent = proc(e.ppid, e.ppid_start_time);
        }
        const ContextDeriveDecision d =
            maintainer.should_derive_context(e.process, parent, e.exe);
        CHECK(d.kind == ContextDecisionKind::NONE,
              "seed 后的首次 exec 应返回 NONE");
    }
}

}  // namespace

int main()
{
    run_plan_roots_and_derive();
    run_plan_interpreter_parent();
    run_plan_missing_parent();
    run_plan_empty_exe();
    run_plan_topological_order();
    run_plan_local_states();
    run_seed_matches_plan();
    run_seed_out_of_order();
    run_seed_invalid_and_duplicates();
    run_runtime_stats_after_seed();
    run_seed_twice_rejected();
    run_lifecycle_preconditions();
    run_state_transitions();
    run_component_seed();
    run_integration_with_manager();

    if (g_fail) {
        std::fprintf(stderr, "TOTAL FAILURES: %d\n", g_fail);
        return 1;
    }
    std::printf("ALL PASS\n");
    return 0;
}
