/**
 * @file verify_role_containerd.cc
 * @brief 校验：连真实的翻译进程运行发现器，核对事件、锚点与补齐
 * @details
 * 连 containerd_bridge 的 Unix socket 运行 ContainerdRoleDiscoverer，按 Ctrl-C
 * 停止。每产出一个事件即做三项自校验，任一不成立记一次失败：
 *   - 锚点：载荷里主进程的 pid_start_time 等于现场读 /proc/<pid>/stat 字段 22；
 *   - 补齐：member_processes 含主进程，且等于现场重读 cgroup.procs 的结果集；
 *   - 身份：实例键非空、类型键非空、cgroup_path 非空。
 * 退出事件的 member_processes 必须为空（加入瞬间的成员列表在退出时已过期）。
 * 结束时打印结算健康度：作废次数与「距上次成功结算的时长」。
 *
 * 需先起翻译进程（root，需读宿主 /run/containerd/containerd.sock），故不注册为
 * ctest 用例。校验方式见 docs/role_discovery/04-containerd角色发现器.md §10。
 * 从仓库根手动执行：
 *
 *   sudo /usr/local/go/bin/go run
 * ./agent/control_plane/role_discovery/containerd_bridge/cmd/containerd-bridge &
 *   sudo build-agent/test/verify_role_containerd
 *
 * 另开一个终端制造事件：
 *   sudo ctr -n default run -d --rm docker.io/library/nginx:latest hng-probe
 *   sudo ctr -n default task kill -s SIGKILL hng-probe
 *   sudo ctr -n default container rm hng-probe
 *
 * @author red_shinku
 * @date 2026.9.13
 */

#include "agent/control_plane/role_discovery/include/role_cgroup_reader.hpp"
#include "agent/control_plane/role_discovery/include/role_containerd_discoverer.hpp"

#include <algorithm>
#include <csignal>
#include <cstdio>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace {

int g_fail                                        = 0;
int g_events                                      = 0;
int g_joins                                       = 0;
int g_leaves                                      = 0;
int g_main_process_changes                        = 0;

hng::role::ContainerdRoleDiscoverer* g_discoverer = nullptr;

/// 现场读 /proc/<pid>/stat 字段 22
std::optional<uint64_t> live_start_time(uint32_t pid)
{
    std::ifstream stat("/proc/" + std::to_string(pid) + "/stat");
    if (!stat) {
        return std::nullopt;
    }
    std::ostringstream buffer;
    buffer << stat.rdbuf();
    return hng::role::RoleCgroupReader::parse_start_time(buffer.str());
}

/// 现场重读 cgroup.procs，核对成员补齐
void check_members(const hng::role::RolePayload& payload, const char* action)
{
    const std::vector<hng::Process> live =
        hng::role::RoleCgroupReader::read(payload.cgroup_path);
    if (live.size() != payload.member_processes.size()) {
        ++g_fail;
        std::fprintf(stderr, "[FAIL] %s：成员数 %zu 现场 %zu\n", action,
                     payload.member_processes.size(), live.size());
        return;
    }
    for (const hng::Process& process : live) {
        const bool found = std::any_of(
            payload.member_processes.begin(), payload.member_processes.end(),
            [&process](const hng::Process& candidate) {
                return hng::role::same_process(candidate, process);
            });
        if (!found) {
            ++g_fail;
            std::fprintf(stderr, "[FAIL] %s：成员缺 pid=%u\n", action,
                         process.pid);
        }
    }
    const bool has_main = std::any_of(
        payload.member_processes.begin(), payload.member_processes.end(),
        [&payload](const hng::Process& candidate) {
            return hng::role::same_process(candidate, payload.main_process);
        });
    if (!has_main) {
        ++g_fail;
        std::fprintf(stderr, "[FAIL] %s：成员列表不含主进程\n", action);
    }
}

void on_event(const hng::role::RoleEvent& event)
{
    ++g_events;
    const char* action = "?";
    switch (event.action) {
        case hng::role::RoleAction::JOIN:
            action = "JOIN";
            ++g_joins;
            break;
        case hng::role::RoleAction::LEAVE:
            action = "LEAVE";
            ++g_leaves;
            break;
        case hng::role::RoleAction::MAIN_PROCESS_CHANGE:
            action = "MAIN_PROCESS_CHANGE";
            ++g_main_process_changes;
            break;
    }

    const hng::role::RolePayload& payload = event.payload;
    std::printf(
        "%-19s %-24s 类型=%-16s pid=%-7u start=%-12llu 成员=%zu\n", action,
        payload.identity.instance_key.c_str(), payload.identity.type_key.c_str(),
        payload.main_process.pid,
        static_cast<unsigned long long>(payload.main_process.pid_start_time),
        payload.member_processes.size());

    if (payload.identity.instance_key.empty() ||
        payload.identity.type_key.empty()) {
        ++g_fail;
        std::fprintf(stderr, "[FAIL] %s：身份不全\n", action);
    }

    if (event.action == hng::role::RoleAction::LEAVE) {
        // 退出事件的成员列表在加入瞬间就已过期，保留会误导下游
        if (!payload.member_processes.empty()) {
            ++g_fail;
            std::fprintf(stderr, "[FAIL] %s：退出不应带成员列表\n", action);
        }
        return;
    }

    if (payload.cgroup_path.empty()) {
        ++g_fail;
        std::fprintf(stderr, "[FAIL] %s：cgroup 路径为空\n", action);
        return;
    }

    // 锚点：现场重读同一 pid，starttime 必须一致
    const std::optional<uint64_t> live =
        live_start_time(payload.main_process.pid);
    if (!live || *live != payload.main_process.pid_start_time) {
        ++g_fail;
        std::fprintf(stderr, "[FAIL] %s：锚点与现场不符（现场 %s）\n", action,
                     live ? std::to_string(*live).c_str() : "读不到");
    }
    check_members(payload, action);
}

void on_signal(int)
{
    if (g_discoverer != nullptr) {
        g_discoverer->stop();
    }
}

}  // namespace

int main(int argc, char** argv)
{
    hng::role::ContainerdRoleDiscoverer::Config config;
    if (argc > 1) {
        config.socket_path = argv[1];
    }
    config.on_event = on_event;

    hng::role::ContainerdRoleDiscoverer discoverer(config);
    g_discoverer = &discoverer;

    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    std::printf("角色发现器已启动（socket=%s），Ctrl-C 停止。\n",
                config.socket_path.c_str());
    std::printf("另开终端制造事件：\n");
    std::printf(
        "  sudo ctr -n default run -d --rm docker.io/library/nginx:latest "
        "hng-probe\n");
    std::printf("  sudo ctr -n default task kill -s SIGKILL hng-probe\n\n");

    discoverer.run();
    g_discoverer                           = nullptr;

    const hng::role::SettlementStats stats = discoverer.settlement_stats();
    std::printf("\n================ 汇总 ================\n");
    std::printf("事件 %d：加入 %d，退出 %d，主进程更换 %d\n", g_events, g_joins,
                g_leaves, g_main_process_changes);
    std::printf("结算 %llu 段，作废 %llu 段，帧序违约 %llu 次，待补锚点 %zu\n",
                static_cast<unsigned long long>(stats.settlements),
                static_cast<unsigned long long>(stats.voids),
                static_cast<unsigned long long>(stats.anomalies),
                stats.pending_anchors);
    if (stats.since_last_settlement_ms >= 0) {
        std::printf("距上次成功结算 %lld ms\n",
                    static_cast<long long>(stats.since_last_settlement_ms));
    }
    if (g_events == 0) {
        std::printf("未观察到任何事件——若确实制造了容器变化，说明有漏报。\n");
    }
    if (g_fail == 0) {
        std::printf("自校验全部通过\n");
        return 0;
    }
    std::fprintf(stderr, "自校验失败 %d 处\n", g_fail);
    return 1;
}
