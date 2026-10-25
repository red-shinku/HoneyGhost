/**
 * @file test_component_handles.cc
 * @brief 控制面组件句柄的单元测试
 * @details
 * 覆盖阶段 0 的公共构造路径：
 *  - 工厂返回非空句柄，状态初值为 CONSTRUCTED 且未就绪；
 *  - 各服务访问器重复取到同一地址，生命周期 sink 同理；
 *  - stats() 初值为零；
 *  - 未 run() 的句柄退出作用域即析构，不崩溃。
 * @author red_shinku
 * @date 2026.10.25
 */

#include "agent/control_plane/include/context_component.hpp"
#include "agent/control_plane/include/process_component.hpp"
#include "agent/control_plane/include/role_component.hpp"

#include <cstdio>

namespace {

int g_fail = 0;

#define CHECK(cond, msg)                                                         \
    do {                                                                         \
        if (!(cond)) {                                                           \
            ++g_fail;                                                            \
            std::fprintf(stderr, "[FAIL] %s:%d  %s\n", __FILE__, __LINE__, msg); \
        }                                                                        \
    } while (0)

void run_process_component()
{
    {
        auto component = hng::make_process_component();
        CHECK(component != nullptr, "进程组件工厂应返回非空句柄");
        if (!component) {
            return;
        }
        CHECK(component->state() == hng::ComponentState::CONSTRUCTED,
              "进程组件初始状态应为 CONSTRUCTED");
        CHECK(!component->ready(), "未初始化的进程组件不应就绪");

        ProcessLookupService* lookup     = &component->lookup_service();
        ProcessJoinService* join         = &component->join_service();
        ProcessUpdateService* update     = &component->update_service();
        ProcessLivenessService* liveness = &component->liveness_service();
        ProcessSeedService* seed         = &component->seed_service();
        CHECK(lookup == &component->lookup_service(),
              "进程查询服务访问器应稳定返回同一地址");
        CHECK(join == &component->join_service(),
              "进程注册服务访问器应稳定返回同一地址");
        CHECK(update == &component->update_service(),
              "进程更新服务访问器应稳定返回同一地址");
        CHECK(liveness == &component->liveness_service(),
              "进程存活服务访问器应稳定返回同一地址");
        CHECK(seed == &component->seed_service(),
              "进程 seed 服务访问器应稳定返回同一地址");

        const ProcessManagerStats stats = component->stats();
        CHECK(stats.pid_reused == 0, "pid_reused 初值应为零");
        CHECK(stats.stale_add == 0, "stale_add 初值应为零");
        CHECK(stats.parent_missing == 0, "parent_missing 初值应为零");
        CHECK(stats.tombstone_depth == 0, "tombstone_depth 初值应为零");
    }
}

void run_context_component()
{
    {
        auto component = hng::make_context_component();
        CHECK(component != nullptr, "上下文组件工厂应返回非空句柄");
        if (!component) {
            return;
        }
        CHECK(component->state() == hng::ComponentState::CONSTRUCTED,
              "上下文组件初始状态应为 CONSTRUCTED");
        CHECK(!component->ready(), "未初始化的上下文组件不应就绪");

        ContextLookupService* lookup = &component->lookup_service();
        ContextJoinService* join     = &component->join_service();
        ContextUpdateService* update = &component->update_service();
        CHECK(lookup == &component->lookup_service(),
              "上下文查询服务访问器应稳定返回同一地址");
        CHECK(join == &component->join_service(),
              "上下文注册服务访问器应稳定返回同一地址");
        CHECK(update == &component->update_service(),
              "上下文更新服务访问器应稳定返回同一地址");

        ProcessLifecycleSink* sink = &component->lifecycle_sink();
        CHECK(sink == &component->lifecycle_sink(),
              "上下文生命周期 sink 应稳定返回同一地址");

        const ContextManagerStats stats = component->stats();
        CHECK(stats.pending_deferred == 0, "pending_deferred 初值应为零");
        CHECK(stats.pending_depth == 0, "pending_depth 初值应为零");
        CHECK(stats.tombstone_depth == 0, "tombstone_depth 初值应为零");
        CHECK(stats.late_register == 0, "late_register 初值应为零");
    }
}

void run_role_component()
{
    {
        auto component = hng::make_role_component();
        CHECK(component != nullptr, "角色组件工厂应返回非空句柄");
        if (!component) {
            return;
        }
        CHECK(component->state() == hng::ComponentState::CONSTRUCTED,
              "角色组件初始状态应为 CONSTRUCTED");
        CHECK(!component->ready(), "未初始化的角色组件不应就绪");

        RoleLookupService* lookup           = &component->lookup_service();
        RoleJoinService* join               = &component->join_service();
        RoleSupervisionService* supervision = &component->supervision_service();
        CHECK(lookup == &component->lookup_service(),
              "角色查询服务访问器应稳定返回同一地址");
        CHECK(join == &component->join_service(),
              "角色继承服务访问器应稳定返回同一地址");
        CHECK(supervision == &component->supervision_service(),
              "角色监管服务访问器应稳定返回同一地址");

        ProcessLifecycleSink* sink = &component->lifecycle_sink();
        CHECK(sink == &component->lifecycle_sink(),
              "角色生命周期 sink 应稳定返回同一地址");

        const RoleManagerStats stats = component->stats();
        CHECK(stats.store.rejected == 0, "关系表 rejected 初值应为零");
        CHECK(stats.store.tombstone_depth == 0,
              "关系表 tombstone_depth 初值应为零");
        CHECK(stats.cgroup_read_empty == 0, "cgroup_read_empty 初值应为零");
        CHECK(stats.queue_rejected == 0, "queue_rejected 初值应为零");
        CHECK(stats.dead_member_rejected == 0, "dead_member_rejected 初值应为零");
        CHECK(stats.dead_anchor_rejected == 0, "dead_anchor_rejected 初值应为零");
    }
}

}  // namespace

int main()
{
    run_process_component();
    run_context_component();
    run_role_component();

    if (g_fail) {
        std::fprintf(stderr, "TOTAL FAILURES: %d\n", g_fail);
        return 1;
    }
    std::printf("ALL PASS\n");
    return 0;
}
