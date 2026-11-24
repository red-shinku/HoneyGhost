/**
 * @file chain_core.hpp
 * @brief chain 段的 sink 后端：replay feeder → 语义 → 运行时引擎
 * @details
 * 无 CLI 的整链装配与窗口测量：原始通道与语义通道各一条，真实语义组件、
 * 真实运行时引擎与真实 context 维护器，控制面替身与「trace 全量种子」来自
 * test/bench/l1_control_plane.hpp。三条工作线程由 run_chain_sink() 创建、
 * 命名并按固定顺序回收；计数与线程 CPU 只取统计窗口内的增量。
 */

#ifndef HNG_TEST_BENCH_CHAIN_CORE_HPP_
#define HNG_TEST_BENCH_CHAIN_CORE_HPP_

#include "test/bench/chain_feeder.hpp"

#include <cstdint>
#include <string>

namespace bench::chain {

/// @brief chain 段的运行参数
struct ChainOptions {
    std::string trace_path;                ///< 语料路径
    double rate        = 0.0;              ///< collector 输入记录/s，0 表示全速
    int seconds        = 10;               ///< 统计窗口秒数
    int warmup_seconds = 1;                ///< 预热秒数
    int queue          = 8192;             ///< 两条通道的容量
    EventClass events  = EventClass::ALL;  ///< 回放类别
    int system_sinks   = 1;                ///< 计数系统订阅数，兼作分发计数
    double settled     = 1.0;              ///< 种子落定比例
};

/**
 * @brief 一次链测量的结果
 * @details 计数与 CPU 均为窗口末减窗口初；records/playback/malformed 是加载期
 *          的全量值，不随窗口变化。drops 分别归因到两条接缝：raw_drops 是
 *          feeder 推入原始通道被拒收的次数，sem_drops 是语义推入语义通道被
 *          拒收的次数。
 */
struct ChainSnapshot {
    double seconds                   = 0.0;  ///< 统计窗口秒数
    std::uint64_t records            = 0;    ///< 通过定长校验的记录数（加载期）
    std::uint64_t playback           = 0;    ///< 参与回放的记录数（加载期）
    std::uint64_t malformed          = 0;    ///< 定长校验失败的记录数（加载期）
    std::uint64_t consumed           = 0;    ///< feeder 已回放记录数
    /// 已回放记录中 lifecycle 类的记录数（窗口增量）
    std::uint64_t consumed_lifecycle = 0;
    std::uint64_t push_ok            = 0;    ///< feeder 成功入队次数
    std::uint64_t push_fail          = 0;    ///< feeder 被拒收次数
    std::uint64_t processed          = 0;    ///< 语义已处理数
    std::uint64_t dispatched         = 0;    ///< 引擎分发数，按系统订阅数归一
    std::uint64_t raw_drops          = 0;    ///< 原始通道拒收（语义消费不及）
    std::uint64_t sem_drops          = 0;    ///< 语义通道拒收（引擎消费不及）
    std::uint64_t raw_peak           = 0;    ///< 窗口内原始通道占用峰值
    std::uint64_t sem_peak           = 0;    ///< 窗口内语义通道占用峰值
    std::uint64_t unsettled          = 0;    ///< 引擎未落定事件数
    double feeder_cpu                = 0.0;  ///< 窗口内 feeder 线程 CPU 秒
    double semantic_cpu              = 0.0;  ///< 窗口内语义线程 CPU 秒
    double engine_cpu                = 0.0;  ///< 窗口内引擎线程 CPU 秒
};

/**
 * @brief 运行一次 sink 后端的整链测量
 * @param[in] options 语料、速率与窗口参数
 * @param[out] snapshot 窗口内的计数与 CPU 增量
 * @param[out] error 失败原因
 * @return 成功时为 true
 * @note 任何提前返回都走同一收尾：置停 feeder 并 join、停语义并 join、停引擎
 *       并 join、关闭两条通道；返回前不留下工作线程。
 * @see ChainFeeder, ChainSnapshot
 */
bool run_chain_sink(const ChainOptions& options, ChainSnapshot& snapshot,
                    std::string& error);

}  // namespace bench::chain

#endif  // HNG_TEST_BENCH_CHAIN_CORE_HPP_
