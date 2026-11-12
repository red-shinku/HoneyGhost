/**
 * @file cli_runtime_service.cc
 * @brief CLIRuntimeService 的实现
 * @author red-shinku
 * @date 2026.10.16
 */

#include "agent/cli_server/src/cli_runtime_service.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <utility>
#include <vector>

#include <userver/components/component_context.hpp>
#include <userver/logging/log.hpp>
#include <userver/ugrpc/server/exceptions.hpp>

#include "agent/cli_server/src/cli_server.hpp"
#include "agent/cli_server/src/cli_stream.hpp"
#include "agent/cli_server/src/event_converter.hpp"

namespace {

/// 请求未指定 batch_size 时每批携带的事件数
constexpr std::uint32_t kDefaultBatchSize = 64;

/// 单批事件数的上界，防止请求方指定过大的批
constexpr std::uint32_t kMaxBatchSize = 256;

/// @brief 作用域退出即拆除流：任何退出路径都不会漏掉注销与摘表
class StreamGuard final {
   public:
    explicit StreamGuard(CLIStream& stream) : stream_(stream) {}
    ~StreamGuard() { stream_.teardown(); }

    StreamGuard(const StreamGuard&)            = delete;
    StreamGuard& operator=(const StreamGuard&) = delete;

   private:
    CLIStream& stream_;
};

/// @brief 把一条消息写进订阅流
/// @return 客户端已断开为 false；其余异常照抛，由调用方翻译成状态
bool Write(CLIRuntimeService::ReceiveEventWriter& writer,
           hng::clisv::ReceiveEventResponse&& msg)
{
    try {
        writer.Write(std::move(msg));
    }
    catch (const userver::ugrpc::server::RpcInterruptedError&) {
        // 客户端断开由下一次写发现
        return false;
    }
    return true;
}

/// @brief 把一批事件写进订阅流；各事件载荷被移出
bool WriteBatch(CLIRuntimeService::ReceiveEventWriter& writer,
                hng::clisv::ReceiveEventBatch&& batch)
{
    hng::clisv::ReceiveEventResponse msg;
    *msg.mutable_batch() = std::move(batch);
    return Write(writer, std::move(msg));
}

/// @brief 写一条丢弃统计；不带 head，不与具体事件对应
bool WriteStats(CLIRuntimeService::ReceiveEventWriter& writer, uint64_t dropped)
{
    hng::clisv::ReceiveEventResponse msg;
    msg.mutable_stats()->set_dropped_events(dropped);
    return Write(writer, std::move(msg));
}

}  // namespace

RuntimeInfoFilter hng::cli::ToRuntimeInfoFilter(
    const hng::clisv::ReceiveEventRequest& request)
{
    RuntimeInfoFilter filter;

    std::vector<hng::EventType> etypes;
    etypes.reserve(static_cast<std::size_t>(request.etype_size()));
    for (const int raw : request.etype()) {
        etypes.push_back(
            FromProtoEventType(static_cast<hng::clisv::EventType>(raw)));
    }
    filter.set_etype(std::move(etypes));

    if (request.has_info()) {
        const hng::clisv::runtimeinfo& info = request.info();
        filter.set_role(
            std::vector<uint32_t>(info.roleid().begin(), info.roleid().end()),
            std::vector<hng::role_label_t>(info.rolelabel().begin(),
                                           info.rolelabel().end()));
        filter.set_context(std::vector<uint32_t>(info.contextid().begin(),
                                                 info.contextid().end()));
        filter.set_process(
            std::vector<uint32_t>(info.pid().begin(), info.pid().end()));
    }
    return filter;
}

CLIRuntimeService::CLIRuntimeService(
    const userver::components::ComponentConfig& config,
    const userver::components::ComponentContext& context)
    : hng::clisv::RuntimeServiceBase::Component(config, context),
      deps_(context.FindComponent<CLIServer>().server_deps()),
      manager_(context.FindComponent<CLIServer>().stream_manager()),
      queue_capacity_(context.FindComponent<CLIServer>().queue_capacity())
{
}

CLIRuntimeService::ReceiveEventResult CLIRuntimeService::ReceiveEvent(
    CallContext& context, hng::clisv::ReceiveEventRequest&& request,
    ReceiveEventWriter& writer)
{
    // 依赖为空说明装配方漏填，不是客户端错误
    if (deps_.subs == nullptr) {
        return grpc::Status(grpc::StatusCode::FAILED_PRECONDITION,
                            "ReceiveEvent: subscriber registry is not installed");
    }

    try {
        const std::optional<CLIStreamManager::StreamSlot> slot =
            manager_.acquire();
        if (!slot.has_value()) {
            return grpc::Status(grpc::StatusCode::RESOURCE_EXHAUSTED,
                                "ReceiveEvent: too many concurrent streams");
        }

        CLIStream stream{manager_, *deps_.subs,
                         hng::cli::ToRuntimeInfoFilter(request), queue_capacity_};
        StreamGuard guard{stream};  // 确保任何退出路径都走 teardown()
        if (!stream.subscribe()) {
            return grpc::Status(grpc::StatusCode::UNAVAILABLE,
                                "ReceiveEvent: the engine is shutting down");
        }

        std::size_t cursor = 0;  // 消费进度只属于本次消费
        uint64_t reported  = 0;
        // 请求的 0 表示取默认值；上界只约束单条消息，不改变流的语义
        const std::size_t batch_size =
            request.batch_size() == 0
                ? kDefaultBatchSize
                : std::min<std::size_t>(request.batch_size(), kMaxBatchSize);
        for (;;) {
            // 取到多少发多少：队列一空就发送部分批，低速率下不引入等待
            hng::clisv::ReceiveEventBatch batch;
            std::size_t taken = 0;
            while (taken < batch_size) {
                hng::RuntimeEvent event{};
                if (!stream.try_pop(event, cursor)) {
                    break;
                }
                hng::cli::ToProto(event, *batch.add_records());
                ++taken;
            }
            if (taken != 0) {
                if (!WriteBatch(writer, std::move(batch))) {
                    break;  // 客户端已断开
                }
                continue;
            }
            const uint64_t dropped = stream.dropped();
            if (dropped != reported) {
                reported = dropped;
                if (!WriteStats(writer, dropped)) {
                    break;
                }
                continue;
            }
            if (stream.finished()) {
                break;
            }
            if (!stream.wait()) {
                break;  // 本任务已被取消
            }
        }
    }
    catch (const std::exception& e) {
        LOG_ERROR() << context.GetCallName() << " threw: " << e.what();
        return grpc::Status(grpc::StatusCode::INTERNAL, e.what());
    }
    return grpc::Status::OK;
}
