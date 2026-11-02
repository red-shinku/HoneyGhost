/**
 * @file query_handlers.hpp
 * @brief 实现控制平面只读接口的返回结果、与查询面 RPC
 * 的响应体之间的无状态映射，以及结果与错误的状态码翻译
 * @author red-shinku
 * @date 2026.10.15
 */

#ifndef HNG_QUERYHANDLERS_HPP_
#define HNG_QUERYHANDLERS_HPP_

#include <optional>
#include <string_view>
#include <utility>
#include <vector>

#include <grpcpp/support/status.h>
#include <userver/logging/log.hpp>
#include <userver/ugrpc/server/exceptions.hpp>
#include <userver/ugrpc/server/result.hpp>

#include <proto/cli_service.pb.h>

#include "agent/control_plane/include/context_service.hpp"
#include "agent/event_data/include/process.hpp"

namespace hng::cli {

/**
 * @brief 执行 handler 体并把结果翻译成返回值
 * @tparam Response 该 RPC 的响应消息
 * @tparam Body 形如 void(Response&) 的可调用对象，其体内填充 Response
 * @param rpc_name RPC 全名，仅用于日志
 * @param body handler 体；正常返回即成功，抛出的状态即该 RPC 的状态
 * @note 体内抛 userver::ugrpc::server::ErrorWithStatus 时按该状态返回，抛其余异常
 * 时记 LOG_ERROR 后返回 INTERNAL。调用点为各一元 handler 的末尾。
 */
template <typename Response, typename Body>
userver::ugrpc::server::Result<Response> ToResult(std::string_view rpc_name,
                                                  const Body& body)
{
    Response response;
    try {
        body(response);
    }
    catch (const userver::ugrpc::server::ErrorWithStatus& e) {
        LOG_ERROR() << rpc_name << " failed: " << e.what();
        return e.GetStatus();
    }
    catch (const std::exception& e) {
        LOG_ERROR() << rpc_name << " threw: " << e.what();
        return grpc::Status(grpc::StatusCode::INTERNAL, e.what());
    }
    return std::move(response);
}

/**
 * @brief 把角色的锚点与成员进程集填进 RM_GetProcessSet 的响应
 * @param root 角色锚点；为空时 root_pid 保持 0
 * @param members 成员进程集；空集不是错误，响应的 pids 字段保持未设置
 * @param out 目标响应
 */
void FillRoleProcessSet(std::optional<hng::Process> root,
                        const std::vector<hng::Process>& members,
                        hng::clisv::RM_GetProcessSetResponse& out);

/**
 * @brief 把 context 的根进程与成员进程集填进 CM_GetProcessSet 的响应
 * @param set 根进程与成员进程集
 * @param out 目标响应
 */
void FillContextProcessSet(const ContextProcessSet& set,
                           hng::clisv::CM_GetProcessSetResponse& out);

}  // namespace hng::cli

#endif  // HNG_QUERYHANDLERS_HPP_
