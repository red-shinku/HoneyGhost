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
#include <string>
#include <utility>
#include <vector>

#include <userver/components/component_context.hpp>
#include <userver/logging/log.hpp>
#include <userver/ugrpc/server/exceptions.hpp>

#include "agent/cli_server/src/cli_server.hpp"
#include "agent/cli_server/src/cli_stream.hpp"
#include "agent/cli_server/src/event_converter.hpp"
#include "agent/cli_server/src/query_handlers.hpp"
#include "agent/util/include/pipeline_stats.hpp"

namespace {

/// 请求未指定 batch_size 时每批携带的事件数
constexpr std::uint32_t kDefaultBatchSize  = 64;

/// 单批事件数的上界，防止请求方指定过大的批
constexpr std::uint32_t kMaxBatchSize      = 256;

/// 表达式节点数的上限，与 CLI 侧一致
constexpr std::size_t kMaxFilterNodes      = 128;

/// 表达式嵌套深度的上限；请求中的根节点深度为 1
constexpr std::size_t kMaxFilterDepth      = 16;

/// 单个原子的取值个数上限
constexpr std::size_t kMaxFilterAtomValues = 4096;

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

/// @brief 把流水线统计快照填进响应
void FillPipelineStats(const hng::PipelineStats& stats,
                       hng::clisv::pipeline_stats& out)
{
    for (const hng::CollectorLineStats& line : stats.collector) {
        hng::clisv::collector_line_stats* item = out.add_collector();
        item->set_line(line.line);
        item->set_consumed(line.consumed);
        item->set_consume_errors(line.consume_errors);
        item->set_channel_dropped(line.channel_dropped);
        item->set_channel_rejected(line.channel_rejected);
        item->set_reserve_failures(line.reserve_failures);
        item->set_attached(line.attached);
        item->set_polling(line.polling);
    }
    if (stats.semantic) {
        const hng::SemanticStats& source   = *stats.semantic;
        hng::clisv::semantic_stats* target = out.mutable_semantic();
        target->set_processed_file(source.processed_file);
        target->set_processed_syscall(source.processed_syscall);
        target->set_raw_file_dropped(source.raw_file_dropped);
        target->set_raw_file_rejected(source.raw_file_rejected);
        target->set_raw_syscall_dropped(source.raw_syscall_dropped);
        target->set_raw_syscall_rejected(source.raw_syscall_rejected);
        target->set_out_file_dropped(source.out_file_dropped);
        target->set_out_file_rejected(source.out_file_rejected);
        target->set_out_syscall_dropped(source.out_syscall_dropped);
        target->set_out_syscall_rejected(source.out_syscall_rejected);
    }
    if (stats.engine) {
        const hng::PipelineEngineStats& source = *stats.engine;
        hng::clisv::engine_stats* target       = out.mutable_engine();
        target->set_unsettled_events(source.unsettled_events);
        target->set_peak_cli_streams(source.peak_cli_streams);
        target->set_queue_rejected(source.queue_rejected);
        target->set_idle_waits(source.idle_waits);
        target->set_syscall_dropped(source.syscall_dropped);
        target->set_file_dropped(source.file_dropped);
    }
    hng::clisv::cli_stream_stats* cli = out.mutable_cli();
    cli->set_active(stats.cli.active);
    cli->set_peak(stats.cli.peak);
    cli->set_dropped(stats.cli.dropped);
}

/// @brief 表达式递归转换的节点预算
struct ExprBudget {
    std::size_t nodes = 0;
};

/// @brief 把 proto 的原子谓词转成 hng::FilterAtom，同时校验字段、比较方式与取值
/// @return 合法时为原子；否则为 std::nullopt 并写 error
std::optional<hng::FilterAtom> ToFilterAtom(const hng::clisv::filter_atom& atom,
                                            std::string& error)
{
    if (atom.field() == hng::clisv::FILTER_FIELD_UNSPECIFIED) {
        error = "invalid filter expression: atom field is UNSPECIFIED";
        return std::nullopt;
    }
    if (atom.compare() == hng::clisv::FILTER_COMPARE_UNSPECIFIED) {
        error = "invalid filter expression: atom compare is UNSPECIFIED";
        return std::nullopt;
    }

    hng::FilterAtom result{};
    switch (atom.field()) {
        case hng::clisv::FILTER_FIELD_TYPE:
            result.field = hng::FilterField::TYPE;
            break;
        case hng::clisv::FILTER_FIELD_KIND:
            result.field = hng::FilterField::KIND;
            break;
        case hng::clisv::FILTER_FIELD_PID:
            result.field = hng::FilterField::PID;
            break;
        case hng::clisv::FILTER_FIELD_PPID:
            result.field = hng::FilterField::PPID;
            break;
        case hng::clisv::FILTER_FIELD_ROLE_ID:
            result.field = hng::FilterField::ROLE_ID;
            break;
        case hng::clisv::FILTER_FIELD_ROLE_LABEL:
            result.field = hng::FilterField::ROLE_LABEL;
            break;
        case hng::clisv::FILTER_FIELD_CONTEXT_ID:
            result.field = hng::FilterField::CONTEXT_ID;
            break;
        case hng::clisv::FILTER_FIELD_UNSPECIFIED:
        default:
            error = "invalid filter expression: unknown atom field";
            return std::nullopt;
    }

    switch (atom.compare()) {
        case hng::clisv::FILTER_COMPARE_EQ:
            result.compare = hng::FilterCompare::EQ;
            break;
        case hng::clisv::FILTER_COMPARE_NE:
            result.compare = hng::FilterCompare::NE;
            break;
        case hng::clisv::FILTER_COMPARE_PREFIX:
            result.compare = hng::FilterCompare::PREFIX;
            break;
        case hng::clisv::FILTER_COMPARE_UNSPECIFIED:
        default:
            error = "invalid filter expression: unknown atom compare";
            return std::nullopt;
    }

    if (result.field == hng::FilterField::ROLE_LABEL) {
        if (atom.numbers_size() != 0) {
            error =
                "invalid filter expression: role label takes strings, not "
                "numbers";
            return std::nullopt;
        }
        if (atom.strings_size() == 0) {
            error = "invalid filter expression: role label requires a value";
            return std::nullopt;
        }
        if (static_cast<std::size_t>(atom.strings_size()) >
            kMaxFilterAtomValues) {
            error = "invalid filter expression: too many values in one atom";
            return std::nullopt;
        }
        for (const std::string& value : atom.strings()) {
            if (value.empty()) {
                error = "invalid filter expression: role label value is empty";
                return std::nullopt;
            }
        }
        result.strings.assign(atom.strings().begin(), atom.strings().end());
        return result;
    }

    if (result.compare == hng::FilterCompare::PREFIX) {
        error = "invalid filter expression: PREFIX is only valid for role label";
        return std::nullopt;
    }
    if (atom.strings_size() != 0) {
        error =
            "invalid filter expression: numeric field takes numbers, not strings";
        return std::nullopt;
    }
    if (atom.numbers_size() == 0) {
        error = "invalid filter expression: atom requires a value";
        return std::nullopt;
    }
    if (static_cast<std::size_t>(atom.numbers_size()) > kMaxFilterAtomValues) {
        error = "invalid filter expression: too many values in one atom";
        return std::nullopt;
    }

    for (const uint32_t value : atom.numbers()) {
        switch (result.field) {
            case hng::FilterField::TYPE:
                if (value > 3) {
                    error = "invalid filter expression: type value " +
                            std::to_string(value) + " is out of range 0..3";
                    return std::nullopt;
                }
                break;
            case hng::FilterField::KIND:
                if (value < 1 || value > 9) {
                    error = "invalid filter expression: kind value " +
                            std::to_string(value) + " is out of range 1..9";
                    return std::nullopt;
                }
                break;
            case hng::FilterField::PID:
                if (value == 0) {
                    error = "invalid filter expression: pid must be non-zero";
                    return std::nullopt;
                }
                break;
            case hng::FilterField::PPID:
            case hng::FilterField::ROLE_ID:
            case hng::FilterField::CONTEXT_ID:
            case hng::FilterField::ROLE_LABEL:
                break;
        }
    }

    result.numbers.assign(atom.numbers().begin(), atom.numbers().end());
    return result;
}

std::optional<hng::FilterExpr> ToFilterExpr(const hng::clisv::filter_expr& node,
                                            std::size_t depth, ExprBudget& budget,
                                            std::string& error);

/// @brief 转换 logic 节点：校验操作数个数后递归转换，再构造对应的表达式
std::optional<hng::FilterExpr> ToFilterLogic(
    const hng::clisv::filter_operands& node, std::size_t depth,
    ExprBudget& budget, std::string& error)
{
    const hng::clisv::FilterLogic logic = node.logic();
    switch (logic) {
        case hng::clisv::FILTER_LOGIC_AND:
        case hng::clisv::FILTER_LOGIC_OR:
        case hng::clisv::FILTER_LOGIC_NOT:
            break;
        case hng::clisv::FILTER_LOGIC_UNSPECIFIED:
            error = "invalid filter expression: logic is UNSPECIFIED";
            return std::nullopt;
        default:
            error = "invalid filter expression: unknown logic";
            return std::nullopt;
    }

    if (logic == hng::clisv::FILTER_LOGIC_NOT) {
        if (node.operands_size() != 1) {
            error = "invalid filter expression: NOT requires exactly one operand";
            return std::nullopt;
        }
    }
    else if (node.operands_size() == 0) {
        error = "invalid filter expression: AND/OR requires at least one operand";
        return std::nullopt;
    }

    if (static_cast<std::size_t>(node.operands_size()) > kMaxFilterNodes) {
        error = "invalid filter expression: more than 128 nodes";
        return std::nullopt;
    }

    std::vector<hng::FilterExpr> operands;
    operands.reserve(static_cast<std::size_t>(node.operands_size()));
    for (const hng::clisv::filter_expr& operand : node.operands()) {
        std::optional<hng::FilterExpr> converted =
            ToFilterExpr(operand, depth + 1, budget, error);
        if (!converted.has_value()) {
            return std::nullopt;
        }
        operands.push_back(std::move(*converted));
    }

    switch (logic) {
        case hng::clisv::FILTER_LOGIC_AND:
            return hng::FilterExpr::make_and(std::move(operands));
        case hng::clisv::FILTER_LOGIC_OR:
            return hng::FilterExpr::make_or(std::move(operands));
        case hng::clisv::FILTER_LOGIC_NOT:
            return hng::FilterExpr::make_not(std::move(operands.front()));
        case hng::clisv::FILTER_LOGIC_UNSPECIFIED:
        default:
            break;
    }
    return std::nullopt;
}

/// @brief 递归转换一个 filter_expr 节点
/// @param depth 本节点深度，请求中的根节点为 1
/// @param budget 跨递归共享的节点计数
/// @return 合法时为表达式；否则为 std::nullopt 并写 error
std::optional<hng::FilterExpr> ToFilterExpr(const hng::clisv::filter_expr& node,
                                            std::size_t depth, ExprBudget& budget,
                                            std::string& error)
{
    if (depth > kMaxFilterDepth) {
        error = "invalid filter expression: nesting depth exceeds 16";
        return std::nullopt;
    }
    if (++budget.nodes > kMaxFilterNodes) {
        error = "invalid filter expression: more than 128 nodes";
        return std::nullopt;
    }

    switch (node.node_case()) {
        case hng::clisv::filter_expr::kAtom: {
            std::optional<hng::FilterAtom> atom =
                ToFilterAtom(node.atom(), error);
            if (!atom.has_value()) {
                return std::nullopt;
            }
            return hng::FilterExpr::make_atom(std::move(*atom));
        }
        case hng::clisv::filter_expr::kLogic:
            return ToFilterLogic(node.logic(), depth, budget, error);
        case hng::clisv::filter_expr::NODE_NOT_SET:
            break;
    }
    error = "invalid filter expression: node is not set";
    return std::nullopt;
}

}  // namespace

std::optional<RuntimeInfoFilter> hng::cli::ToRuntimeInfoFilter(
    const hng::clisv::ReceiveEventRequest& request, std::string& error)
{
    error.clear();
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

    if (request.has_expr()) {
        ExprBudget budget;
        std::optional<hng::FilterExpr> expression =
            ToFilterExpr(request.expr(), 1, budget, error);
        if (!expression.has_value()) {
            return std::nullopt;
        }
        filter.add_expression(std::move(*expression));
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
        std::string filter_error;
        std::optional<RuntimeInfoFilter> filter =
            hng::cli::ToRuntimeInfoFilter(request, filter_error);
        if (!filter.has_value()) {
            return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, filter_error);
        }

        const std::optional<CLIStreamManager::StreamSlot> slot =
            manager_.acquire();
        if (!slot.has_value()) {
            return grpc::Status(grpc::StatusCode::RESOURCE_EXHAUSTED,
                                "ReceiveEvent: too many concurrent streams");
        }

        CLIStream stream{manager_, *deps_.subs, std::move(*filter),
                         queue_capacity_};
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

CLIRuntimeService::GetPipelineStatsResult CLIRuntimeService::GetPipelineStats(
    CallContext& context, hng::clisv::GetPipelineStatsRequest&&)
{
    return hng::cli::ToResult<hng::clisv::GetPipelineStatsResponse>(
        context.GetCallName(), [&](hng::clisv::GetPipelineStatsResponse& out) {
            if (deps_.stats == nullptr) {
                throw userver::ugrpc::server::ErrorWithStatus(
                    grpc::StatusCode::FAILED_PRECONDITION,
                    "GetPipelineStats: stats service is not installed");
            }
            hng::PipelineStats stats = deps_.stats->snapshot();
            stats.cli                = manager_.stats();
            FillPipelineStats(stats, *out.mutable_stats());
        });
}
