/**
 * @file query_handlers.cc
 * @brief query_handlers.hpp 中非模板部分的实现
 * @author red-shinku
 * @date 2026.10.15
 */

#include "agent/cli_server/src/query_handlers.hpp"

#include <string>

namespace hng::cli {

grpc::Status Unimplemented(std::string_view rpc_name, std::string_view gap)
{
    LOG_DEBUG() << rpc_name << " is not implemented yet: " << gap
                << " is not provided by the control plane";
    return grpc::Status(grpc::StatusCode::UNIMPLEMENTED,
                        std::string{rpc_name} + " is not implemented yet: " +
                            "missing " + std::string{gap});
}

void FillRoleProcessSet(const std::vector<hng::Process>& members,
                        hng::clisv::RM_GetProcessSetResponse& out)
{
    // TODO: root_pid 暂无数据源 —— RoleLookupService 未暴露角色锚点进程，
    //       先保持 proto 默认值 0
    if (members.empty()) {
        return;
    }
    hng::clisv::pidList* pids = out.mutable_pids();
    for (const hng::Process& p : members) {
        pids->add_pid(p.pid);
    }
}

}  // namespace hng::cli
