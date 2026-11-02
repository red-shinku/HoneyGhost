/**
 * @file query_handlers.cc
 * @brief query_handlers.hpp 中非模板部分的实现
 * @author red-shinku
 * @date 2026.10.15
 */

#include "agent/cli_server/src/query_handlers.hpp"

#include <unordered_set>

namespace hng::cli {

namespace {

/// @brief 按 pid 去重后追加；proto 的 pidList 不携带 start_time
void AppendPids(const std::vector<hng::Process>& members,
                hng::clisv::pidList& pids)
{
    std::unordered_set<uint32_t> seen;
    for (const hng::Process& p : members) {
        if (seen.insert(p.pid).second) {
            pids.add_pid(p.pid);
        }
    }
}

}  // namespace

void FillRoleProcessSet(std::optional<hng::Process> root,
                        const std::vector<hng::Process>& members,
                        hng::clisv::RM_GetProcessSetResponse& out)
{
    if (root && root->pid != 0) {
        out.set_root_pid(root->pid);
    }
    if (members.empty()) {
        return;
    }
    AppendPids(members, *out.mutable_pids());
}

void FillContextProcessSet(const ContextProcessSet& set,
                           hng::clisv::CM_GetProcessSetResponse& out)
{
    out.set_root_pid(set.root.pid);
    if (set.members.empty()) {
        return;
    }
    AppendPids(set.members, *out.mutable_pids());
}

}  // namespace hng::cli
