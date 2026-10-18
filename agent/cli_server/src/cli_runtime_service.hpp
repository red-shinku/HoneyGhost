/**
 * @file cli_runtime_service.hpp
 * @brief 定义 CLIRuntimeService，cli_service.proto 中 RuntimeService 的 handler
 * @author red-shinku
 * @date 2026.10.16
 */

#ifndef HNG_CLI_RUNTIME_SERVICE_HPP
#define HNG_CLI_RUNTIME_SERVICE_HPP

#include <cstddef>

#include <proto/cli_service_service.usrv.pb.hpp>

#include "agent/cli_server/include/cli_server.hpp"
#include "agent/cli_server/src/cli_stream_manager.hpp"
#include "agent/event_data/include/runtime_info_filter.hpp"

namespace hng::cli {

/// @brief 把订阅请求的 -t / -i 转成过滤器
/// @param request 订阅请求；未设置的维度表示该维度不限
/// @return 取值集合原样落进过滤器；服务端不做解析，故不存在解析失败
/// @note roleID 与 roleLabel 同属角色维度，过滤时取并集
RuntimeInfoFilter ToRuntimeInfoFilter(
    const hng::clisv::ReceiveEventRequest& request);

}  // namespace hng::cli

/**
 * @brief RuntimeService 的服务组件
 * @details handler 任务的整个生命期就是该路的消费循环：建立订阅、把事件写进响应
 * 流、退出时拆除订阅。依赖取自 CLIServer 组件。
 * @note 须登记在 CLIServer 之后：服务组件在构造期经 FindComponent 取用后者
 */
class CLIRuntimeService final : public hng::clisv::RuntimeServiceBase::Component {
   public:
    static constexpr std::string_view kName = "cli-runtime-service";

    CLIRuntimeService(const userver::components::ComponentConfig& config,
                      const userver::components::ComponentContext& context);

    /// 流式响应，传输被订阅的事件。处理过程是：
    /// 尝试向 CLIStreamManager 申请一条流配额，成功后构造 CLIStream，并发起订阅。
    ReceiveEventResult ReceiveEvent(CallContext& context,
                                    hng::clisv::ReceiveEventRequest&& request,
                                    ReceiveEventWriter& writer) override;

   private:
    /// 指向 CLIServer 持有的依赖集合，存活期覆盖本组件
    const CLIServerDeps& deps_;
    /// 配额与流表
    CLIStreamManager& manager_;
    /// 每流事件队列的目标容量，取自 CLIServer 的静态配置
    const std::size_t queue_capacity_;
};

#endif  // HNG_CLI_RUNTIME_SERVICE_HPP
