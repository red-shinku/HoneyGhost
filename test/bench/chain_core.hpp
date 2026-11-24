/**
 * @file chain_core.hpp
 * @brief chain 段的可复用整链装配：replay feeder → 语义 → 运行时引擎
 * @details
 * 原始通道与语义通道各一条，真实语义组件、真实运行时引擎与真实 context
 * 维护器，控制面替身与「trace 全量种子」来自 test/bench/l1_control_plane.hpp。
 * ChainRuntime 持有装配与三条工作线程的生命周期，窗口的起止时刻、睡眠与快照
 * 次数由调用方决定；sink 后端用 run_chain_sink() 封装，CLI 后端在子进程里直接
 * 持有 ChainRuntime 并由控制线程在窗口两端取快照。
 */

#ifndef HNG_TEST_BENCH_CHAIN_CORE_HPP_
#define HNG_TEST_BENCH_CHAIN_CORE_HPP_

#include "test/bench/chain_feeder.hpp"

#include <cstdint>
#include <memory>
#include <string>

class ContextLookupService;
class ProcessLookupService;
class RoleLookupService;
class SubscriberRegService;

namespace hng {
class PipelineStatsService;
}

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
 * @brief 某一时刻的累计快照
 * @details 计数与 CPU 是自启动以来的累计值，调用方用 window_delta() 取窗口增量。
 *          raw_peak/sem_peak 是「上一次 snapshot() 以来」的通道占用峰值：快照
 *          取走它并把采样窗口重置到当前时刻，因此窗口起点的一次快照会丢弃
 *          预热期峰值。records/playback/malformed 是加载期全量值，不随窗口变化。
 *          seconds 由调用方填写。
 */
struct ChainSnapshot {
    double seconds                       = 0.0;  ///< 统计窗口秒数（调用方填写）
    std::uint64_t records                = 0;  ///< 通过定长校验的记录数（加载期）
    std::uint64_t playback               = 0;  ///< 参与回放的记录数（加载期）
    std::uint64_t malformed              = 0;  ///< 定长校验失败的记录数（加载期）
    std::uint64_t consumed               = 0;  ///< feeder 已回放记录数
    /// 已回放记录中 lifecycle 类的记录数
    std::uint64_t consumed_lifecycle     = 0;
    std::uint64_t push_ok                = 0;  ///< feeder 成功入队次数
    std::uint64_t push_fail              = 0;  ///< feeder 被拒收次数
    std::uint64_t processed              = 0;  ///< 语义已处理数
    std::uint64_t dispatched             = 0;  ///< 引擎分发数，按系统订阅数归一
    std::uint64_t raw_drops              = 0;  ///< 原始通道拒收（语义消费不及）
    std::uint64_t sem_drops              = 0;  ///< 语义通道拒收（引擎消费不及）
    std::uint64_t raw_peak               = 0;  ///< 自上次快照以来原始通道占用峰值
    std::uint64_t sem_peak               = 0;  ///< 自上次快照以来语义通道占用峰值
    std::uint64_t unsettled              = 0;  ///< 引擎未落定事件数
    /// 引擎看到的语义通道丢弃数，与 sem_drops 是同一接缝的两种口径
    std::uint64_t engine_syscall_dropped = 0;
    std::uint64_t engine_idle_waits      = 0;    ///< 引擎空闲等待次数
    double feeder_cpu                    = 0.0;  ///< feeder 线程累计 CPU 秒
    double semantic_cpu                  = 0.0;  ///< 语义线程累计 CPU 秒
    double engine_cpu                    = 0.0;  ///< 引擎线程累计 CPU 秒
};

/**
 * @brief 整链运行期：装配、窗口快照与停机
 * @details start() 装配组件并启动 semantic/engine 两条消费线程，defer_feeder
 *          为 false 时再启动 feeder；start_feeder() 供“服务端就绪后再放行回放”
 *          的 CLI 握手使用。snapshot() 读取累计计数、线程 CPU 与自上次快照以来
 *          的通道占用峰值；stop() 按 feeder → semantic → engine 的顺序停机并
 *          关闭两条通道。窗口的起止时刻与睡眠由调用方负责。
 * @note start() 成功后才可调用 snapshot() 与各服务访问器；stop() 可重复调用，
 *       未 start() 也可安全析构。snapshot() 只应由一条线程调用：峰值取走与
 *       采样重启有副作用。CLI 子进程须在 fork 之后、创建任何线程之前构造本类。
 * @see run_chain_sink, window_delta
 */
class ChainRuntime final {
   public:
    ChainRuntime();
    ~ChainRuntime();

    ChainRuntime(const ChainRuntime&)            = delete;
    ChainRuntime& operator=(const ChainRuntime&) = delete;

    /**
     * @brief 装载语料、种子控制面替身、装配组件并启动消费线程
     * @param[in] options 语料、速率与通道参数
     * @param[out] error 失败原因
     * @param[in] defer_feeder true 时只启动语义与引擎线程，回放线程留给
     *            start_feeder()；false 时立即启动回放线程
     * @return 成功时为 true
     * @note 任何失败路径都已停机并关闭通道，返回后不再留下工作线程。
     * @see start_feeder
     */
    bool start(const ChainOptions& options, std::string& error,
               bool defer_feeder = false);

    /**
     * @brief 启动回放线程
     * @param[out] error 失败原因
     * @return 成功时为 true
     * @note 只在 start(defer_feeder=true) 之后调用且只能调用一次；回放节拍从
     *       本次调用起算，调用方应在窗口基准时刻 T0 附近调用。
     */
    bool start_feeder(std::string& error);

    /**
     * @brief 取一次累计快照
     * @param[out] snapshot 累计计数、线程 CPU 与自上次快照以来的占用峰值
     * @param[out] error 失败原因
     * @return 成功时为 true
     * @note 只应由一条线程调用；调用后峰值采样从当前时刻重新开始。
     */
    bool snapshot(ChainSnapshot& snapshot, std::string& error);

    /// @brief 停三条工作线程并关闭通道；可重复调用
    void stop();

    /// @brief 引擎的订阅登记入口，CLI 后端传给 CLIServerDeps::subs
    SubscriberRegService& subscriber_service();

    /// @brief collector/semantic/engine 三段的累计计数，供 GetPipelineStats
    hng::PipelineStatsService& stats_service();

    /// @brief 控制面角色查询替身，CLI 后端传给 CLIServerDeps::role
    RoleLookupService& role_lookup_service();

    /// @brief 控制面上下文查询替身，CLI 后端传给 CLIServerDeps::context
    ContextLookupService& context_lookup_service();

    /// @brief 控制面进程查询替身，CLI 后端传给 CLIServerDeps::process
    ProcessLookupService& process_lookup_service();

    /// @brief 语义或引擎线程是否曾抛出异常
    bool failed() const;

   private:
    struct Impl;

    std::unique_ptr<Impl> impl_;
};

/**
 * @brief 两个快照之间的窗口增量
 * @param[in] begin 窗口起点快照
 * @param[in] end 窗口终点快照
 * @return 计数与 CPU 为 end 减 begin；峰值与加载期字段取 end；seconds 置 0，
 *         由调用方填写
 */
ChainSnapshot window_delta(const ChainSnapshot& begin, const ChainSnapshot& end);

/**
 * @brief 运行一次 sink 后端的整链测量
 * @param[in] options 语料、速率与窗口参数
 * @param[out] snapshot 窗口内的计数与 CPU 增量
 * @param[out] error 失败原因
 * @return 成功时为 true
 * @note 内部使用 ChainRuntime：启动后再预热，窗口两端各取一次快照，结束时停机
 *       并关闭通道；返回前不留下工作线程。
 * @see ChainRuntime, ChainSnapshot
 */
bool run_chain_sink(const ChainOptions& options, ChainSnapshot& snapshot,
                    std::string& error);

}  // namespace bench::chain

#endif  // HNG_TEST_BENCH_CHAIN_CORE_HPP_
