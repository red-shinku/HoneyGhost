/**
 * @file verify_role_systemd.cc
 * @brief 校验：对真实 systemd 运行发现器，核对事件、锚点与补齐
 * @details
 * 连真实的 system bus 运行 SystemdRoleDiscoverer，按 Ctrl-C 停止。每产出一个
 * 事件即做三项自校验，任一不成立记一次失败：
 *   - 锚点：载荷里主进程的 pid_start_time 等于现场读 /proc/<pid>/stat 字段 22；
 *   - 补齐：member_processes 含主进程，且等于现场重读 cgroup.procs 的结果集；
 *   - 身份：实例键非空、cgroup_path 非空。
 * 退出事件的 member_processes 必须为空（加入瞬间的成员列表在退出时已过期）。
 *
 * 校验用进程与 cgroup 都取自现场，因此需要能与发现器同时观察到同一批 unit。
 * 需 root（Manager.Subscribe 需要特权），故不注册为 ctest 用例。校验方式见
 * docs/role_discovery/03-systemd角色发现器.md §8。从仓库根手动执行：
 *
 *   sudo build-agent/test/verify_role_systemd
 *
 * 另开一个终端制造事件，例如：
 *   sudo systemd-run --unit=hng-probe --property=Type=simple /bin/sleep 5
 *   sudo systemctl restart avahi-daemon.service     # 多进程 cgroup，验补齐
 *
 * 可选参数为周期快照间隔（毫秒），0 关掉；调小可观察结算健康度累积：
 *   sudo build-agent/test/verify_role_systemd 3000
 *
 * 两条需要盲窗的校验改用手动制造（单测已覆盖其逻辑，此处验的是真实时序）：
 *   - 对账生效：`sudo systemctl daemon-reexec` 会让本连接重新订阅并重跑快照段，
 *     在该窗口内停掉一个 unit，重连后应产出它的退出，而不是把它留在表里。
 *   - 盲窗内重启：同上窗口内停掉再启同一个 unit，应产出 LEAVE + JOIN，
 *     而不是被折叠成一次「主进程更换」。
 *
 * @author red_shinku
 * @date 2026.9.12
 */

#include "agent/control_plane/role_discovery/include/role_cgroup_reader.hpp"
#include "agent/control_plane/role_discovery/include/role_systemd_discoverer.hpp"

#include <algorithm>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace {

using hng::Process;
using hng::role::RoleAction;
using hng::role::RoleCgroupReader;
using hng::role::RoleEvent;
using hng::role::SystemdRoleDiscoverer;
using hng::role::SystemdSettlementStats;

SystemdRoleDiscoverer* g_discoverer = nullptr;

int g_events                        = 0;
int g_joins                         = 0;
int g_leaves                        = 0;
int g_main_process_changes          = 0;
int g_fail                          = 0;

const char* action_name(RoleAction action)
{
    switch (action) {
        case RoleAction::JOIN:
            return "JOIN";
        case RoleAction::LEAVE:
            return "LEAVE";
        case RoleAction::MAIN_PROCESS_CHANGE:
            return "MAIN_PROCESS_CHANGE";
    }
    return "?";
}

/// 现场读 /proc/<pid>/stat 字段 22，与发现器侧同一契约
std::optional<uint64_t> read_start_time(uint32_t pid)
{
    std::ifstream stat(std::filesystem::path("/proc") / std::to_string(pid) /
                       "stat");
    if (!stat) {
        return std::nullopt;
    }
    std::ostringstream buffer;
    buffer << stat.rdbuf();
    return RoleCgroupReader::parse_start_time(buffer.str());
}

bool contains(const std::vector<Process>& list, const Process& needle)
{
    for (const Process& item : list) {
        if (item.pid == needle.pid &&
            item.pid_start_time == needle.pid_start_time) {
            return true;
        }
    }
    return false;
}

bool same_process_set(std::vector<Process> a, std::vector<Process> b)
{
    auto less = [](const Process& x, const Process& y) {
        return x.pid != y.pid ? x.pid < y.pid
                              : x.pid_start_time < y.pid_start_time;
    };
    std::sort(a.begin(), a.end(), less);
    std::sort(b.begin(), b.end(), less);
    if (a.size() != b.size()) {
        return false;
    }
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (a[i].pid != b[i].pid || a[i].pid_start_time != b[i].pid_start_time) {
            return false;
        }
    }
    return true;
}

void report_failure(const char* what, const std::string& detail)
{
    ++g_fail;
    std::fprintf(stderr, "  [FAIL] %s：%s\n", what, detail.c_str());
}

void on_event(const RoleEvent& event)
{
    ++g_events;
    switch (event.action) {
        case RoleAction::JOIN:
            ++g_joins;
            break;
        case RoleAction::LEAVE:
            ++g_leaves;
            break;
        case RoleAction::MAIN_PROCESS_CHANGE:
            ++g_main_process_changes;
            break;
    }

    const std::string& key = event.payload.identity.instance_key;
    std::printf("\n#%d %s %s\n", g_events, action_name(event.action),
                key.c_str());
    std::printf("    类型键      %s\n", event.payload.identity.type_key.c_str());
    std::printf("    锚点        pid=%u pid_start_time=%llu\n",
                event.payload.main_process.pid,
                static_cast<unsigned long long>(
                    event.payload.main_process.pid_start_time));
    std::printf("    cgroup      %s\n", event.payload.cgroup_path.c_str());
    std::printf("    成员数      %zu\n", event.payload.member_processes.size());
    for (const auto& attribute : event.payload.identity.attributes) {
        std::printf("    属性        %s=%s\n", attribute.first.c_str(),
                    attribute.second.c_str());
    }

    if (key.empty()) {
        report_failure("实例键非空", "载荷的实例键为空");
    }
    if (event.payload.cgroup_path.empty()) {
        report_failure("cgroup 路径非空", key);
    }

    if (event.action == RoleAction::LEAVE) {
        // 加入瞬间的成员列表在退出时刻已过期，保留会误导下游
        if (!event.payload.member_processes.empty()) {
            report_failure("退出事件的成员列表为空", key);
        }
        return;
    }

    // 锚点自校验：与现场 /proc 比对
    const uint32_t pid = event.payload.main_process.pid;
    if (pid == 0) {
        report_failure("锚点非零", key);
        return;
    }
    const std::optional<uint64_t> start_time = read_start_time(pid);
    if (!start_time) {
        report_failure("锚点进程可读", "/proc/" + std::to_string(pid) + "/stat");
    }
    else if (*start_time != event.payload.main_process.pid_start_time) {
        std::ostringstream detail;
        detail << "载荷 " << event.payload.main_process.pid_start_time
               << " 与 /proc 的 " << *start_time << " 不一致";
        report_failure("锚点 pid_start_time 与 /proc 一致", detail.str());
    }

    // 补齐自校验：主进程必须在成员列表内
    if (!contains(event.payload.member_processes, event.payload.main_process)) {
        report_failure("成员补齐含主进程", key);
    }

    // 补齐自校验：与现场重读 cgroup.procs 的结果集比对
    if (!event.payload.cgroup_path.empty()) {
        const std::vector<Process> live =
            RoleCgroupReader::read(event.payload.cgroup_path);
        if (!same_process_set(live, event.payload.member_processes)) {
            std::ostringstream detail;
            detail << "现场 " << live.size() << " 个进程，载荷 "
                   << event.payload.member_processes.size() << " 个";
            report_failure("成员补齐与现场 cgroup.procs 一致", detail.str());
        }
    }
}

void on_signal(int)
{
    // stop() 只置原子标志并写 eventfd，在信号处理器里是安全的
    if (g_discoverer != nullptr) {
        g_discoverer->stop();
    }
}

}  // namespace

int main(int argc, char** argv)
{
    std::setvbuf(stdout, nullptr, _IONBF, 0);  // 事件与跟踪按真实时序交错

    SystemdRoleDiscoverer::Config config;
    config.on_event = on_event;
    // 可选：周期快照间隔（毫秒），传 0 关掉。调小可以观察结算健康度累积
    if (argc > 1) {
        config.snapshot_interval = std::chrono::milliseconds(std::atoi(argv[1]));
    }

    SystemdRoleDiscoverer discoverer(config);
    g_discoverer = &discoverer;

    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    std::printf("角色发现器已启动，Ctrl-C 停止。\n");
    std::printf("另开终端制造事件：\n");
    std::printf(
        "  sudo systemd-run --unit=hng-probe --property=Type=simple "
        "/bin/sleep 5\n");
    std::printf("  sudo systemctl restart avahi-daemon.service\n\n");

    discoverer.run();
    g_discoverer = nullptr;

    std::printf("\n================ 汇总 ================\n");
    std::printf("事件 %d：加入 %d，退出 %d，主进程更换 %d\n", g_events, g_joins,
                g_leaves, g_main_process_changes);

    const SystemdSettlementStats stats = discoverer.settlement_stats();
    std::printf(
        "结算 %llu 段，作废 %llu 段，结构异常 %llu 次，"
        "取数时对象已不在 %llu 次，逐项取数失败 %llu 次，"
        "距上次成功结算 %lld ms\n",
        static_cast<unsigned long long>(stats.settlements),
        static_cast<unsigned long long>(stats.voids),
        static_cast<unsigned long long>(stats.anomalies),
        static_cast<unsigned long long>(stats.units_gone),
        static_cast<unsigned long long>(stats.unknown_fetches),
        static_cast<long long>(stats.since_last_settlement_ms));
    if (g_events == 0) {
        std::printf("未观察到任何事件——若确实制造了 unit 变化，说明有漏报。\n");
    }
    if (g_fail == 0) {
        std::printf("自校验全部通过\n");
        return 0;
    }
    std::fprintf(stderr, "自校验失败 %d 处\n", g_fail);
    return 1;
}
