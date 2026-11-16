/**
 * @file pipeline_stats.hpp
 * @brief 事件流水线的运行期统计快照与查询接口
 * @author red-shinku
 * @date 2026.11.12
 */

#ifndef HNG_PIPELINE_STATS_HPP_
#define HNG_PIPELINE_STATS_HPP_

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace hng {

/**
 * @brief 单条采集线的累计计数
 * @note consumed 是已从 ringbuf 搬出的记录数，包含随后因通道满被丢弃的记录；
 *       channel_dropped/channel_rejected 是输出通道的拒收次数。
 */
struct CollectorLineStats {
    std::string line;                  ///< 线名：file、syscall 或 network
    std::uint64_t consumed       = 0;  ///< 已从 ringbuf 消费的记录数
    std::uint64_t consume_errors = 0;  ///< ring_buffer 消费返回错误的次数
    std::uint64_t channel_dropped  = 0;  ///< 输出通道满导致的拒收
    std::uint64_t channel_rejected = 0;  ///< 输出通道关闭导致的拒收
    std::uint64_t reserve_failures = 0;  ///< 内核 ringbuf 预留失败次数
    bool attached = false;              ///< 探针当前是否已挂载
    bool polling  = false;              ///< 是否退回超时轮询
};

/// @brief 语义聚合的累计计数
struct SemanticStats {
    std::uint64_t processed_file    = 0;  ///< 已转换的文件原始事件
    std::uint64_t processed_syscall = 0;  ///< 已转换的系统调用原始事件
    std::uint64_t raw_file_dropped     = 0;
    std::uint64_t raw_file_rejected    = 0;
    std::uint64_t raw_syscall_dropped  = 0;
    std::uint64_t raw_syscall_rejected = 0;
    std::uint64_t out_file_dropped     = 0;
    std::uint64_t out_file_rejected    = 0;
    std::uint64_t out_syscall_dropped  = 0;
    std::uint64_t out_syscall_rejected = 0;
};

/// @brief 运行时引擎的累计计数，与 RuntimeEngineStats 的字段一一对应
struct PipelineEngineStats {
    std::uint64_t unsettled_events = 0;
    std::uint64_t peak_cli_streams = 0;
    std::uint64_t queue_rejected   = 0;
    std::uint64_t idle_waits       = 0;
    std::uint64_t syscall_dropped  = 0;
    std::uint64_t file_dropped     = 0;
};

/// @brief CLI 订阅流的累计计数
struct CLIStreamStats {
    std::uint64_t active  = 0;  ///< 当前活跃流数
    std::uint64_t peak    = 0;  ///< 历史峰值
    std::uint64_t dropped = 0;  ///< 所有流累计的队列拒收，含已摘除的流
};

/// @brief 一次流水线统计快照；各段可能未接线
struct PipelineStats {
    std::vector<CollectorLineStats> collector;  ///< 空表示采集器未接线
    std::optional<SemanticStats> semantic;      ///< 空表示语义聚合未接线
    std::optional<PipelineEngineStats> engine;  ///< 空表示引擎未接线
    CLIStreamStats cli;
};

/**
 * @brief 流水线统计的查询接口
 * @note snapshot() 可从任意线程调用；返回值是各段计数器的非原子快照，
 *       跨段不保证同一时刻。
 */
class PipelineStatsService {
   public:
    virtual ~PipelineStatsService() = default;
    virtual PipelineStats snapshot() const = 0;
};

}  // namespace hng

#endif  // HNG_PIPELINE_STATS_HPP_
