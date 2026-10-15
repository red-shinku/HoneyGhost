/**
 * @file query_handlers.hpp
 * @brief 实现控制平面只读接口的返回结果、与查询面 RPC
 * 的响应体之间的无状态映射，以及结果与错误的状态码翻译
 * @author red-shinku
 * @date 2026.10.15
 */

#ifndef HNG_QUERYHANDLERS_HPP_
#define HNG_QUERYHANDLERS_HPP_

#include <string_view>
#include <utility>
#include <vector>

#include <grpcpp/support/status.h>
#include <userver/logging/log.hpp>
#include <userver/ugrpc/server/exceptions.hpp>
#include <userver/ugrpc/server/result.hpp>

#include <proto/cli_service.pb.h>

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
 * @brief 服务所需接口未实现时的统一状态
 * @param rpc_name RPC 全名
 * @param gap 该 RPC 所依赖的缺口
 * @return UNIMPLEMENTED，消息里带上 rpc_name 与 gap
 * @note 缺口由其他模块另行补齐，本模块对其只回明确状态
 */
grpc::Status Unimplemented(std::string_view rpc_name, std::string_view gap);

/**
 * @brief 把角色的成员进程集填进 RM_GetProcessSet 的响应
 * @param members 成员进程集；空集不是错误，响应的 pids 字段保持未设置
 * @param out 目标响应
 */
void FillRoleProcessSet(const std::vector<hng::Process>& members,
                        hng::clisv::RM_GetProcessSetResponse& out);

}  // namespace hng::cli

#endif  // HNG_QUERYHANDLERS_HPP_
