#ifndef SEMANTIC_HPP
#define SEMANTIC_HPP

#include "agent/event_data/include/syscall_event.hpp"
#include "agent/util/include/component.hpp"
#include "agent/util/include/event_channel.hpp"
#include "agent/util/include/event_loop.hpp"
#include "agent/util/include/pipeline_stats.hpp"
#include "kernel/include/syscall_event_type.h"

#include <atomic>
#include <cstddef>
#include <cstdint>

namespace hng {

/**
 * @brief 原始事件是否承载未解析路径。
 * @param raw 系统调用原始事件
 * @return 文件事件且 path1_flags 或 path2_flags 含 PATH_UNRESOLVED 时为 true。
 * @note 语义层据此按事件累计 path_unresolved，每条事件至多计一次。
 * @see Semantic_syscall::transform_one, hng::SemanticStats
 */
bool has_unresolved_path(const struct syscall_event& raw);

}  // namespace hng

/**
 * @brief 系统调用事件语义化工具。
 * @details 按 hdr.subtype 分派到八种语义载荷；无状态、无队列。
 * @note 同一实例可被单线程重复调用。
 */
class Semantic_syscall {
   public:
    Semantic_syscall() = default;

    /**
     * @brief 单条系统调用原始事件 → 语义事件（纯转换）。
     * @param raw 系统调用原始事件
     * @param[out] out 语义事件；头部按 raw 填充，载荷按 hdr.subtype 构造
     */
    void transform_one(const struct syscall_event& raw,
                       hng::syscall_semantic_data& out) const;
};

/**
 * @brief 语义聚合：单线程消费系统调用原始事件通道并写入语义通道。
 * @details 线程由装配层创建；本类不持 std::thread。每轮按预算取系统调用线，
 *          取空时阻塞在事件循环上，stop() 用其停机 fd 唤醒。
 *          退出前排空输入并关闭输出通道。
 * @note 生命周期为 READY → RUNNING → STOPPED。通道读写端指针可为空，表示该线
 *       未接线；非空通道须比本对象活得更久。run() 返回前不得析构。
 * @see hng::Component, hng::EventChannel
 */
class Semantic final : public hng::Component {
   public:
    /**
     * @brief 绑定系统调用原始事件通道的读端与语义通道的写端。
     * @param raw_syscall 系统调用原始事件通道读端；未接线传 nullptr
     * @param out_syscall 系统调用语义事件通道写端；未接线传 nullptr
     * @throws std::system_error 事件循环 fd 创建失败
     */
    Semantic(hng::EventChannelReader<struct syscall_event>* raw_syscall,
             hng::EventChannelWriter<hng::syscall_semantic_data>* out_syscall);
    ~Semantic() override;

    Semantic(const Semantic&)            = delete;
    Semantic& operator=(const Semantic&) = delete;
    Semantic(Semantic&&)                 = delete;
    Semantic& operator=(Semantic&&)      = delete;

    /**
     * @brief 语义化线程入口：按预算取系统调用线，直至 stop()。
     * @pre state() 为 READY；否则立即返回且不改变状态
     * @note 退出前排空原始事件通道并关闭语义通道；不创建线程。
     */
    void run() override;
    /**
     * @brief 置停止标志并唤醒事件循环；幂等，可从任意线程调用。
     * @note 未进入 RUNNING 时直接置 STOPPED。
     */
    void stop() override;
    /**
     * @brief 当前生命周期状态。
     * @note 可从任意线程读取。
     */
    hng::ComponentState state() const override;

    /// @brief 累计计数快照；可从任意线程调用
    hng::SemanticStats stats() const;

   private:
    /// 就绪源的标识，与事件循环的停机 tag 不冲突
    static constexpr std::uint64_t kSyscallTag = 1;

    /**
     * @brief 从系统调用原始通道取至多 budget 条，转换后推入输出通道。
     * @return 处理条数
     */
    std::size_t drain_syscall(std::size_t budget);
    /**
     * @brief 把已接线通道的唤醒 fd 登记进事件循环。
     * @throws std::system_error 登记失败
     */
    void register_sources();

    Semantic_syscall syscall_tool_;
    hng::EventChannelReader<struct syscall_event>* raw_syscall_;
    hng::EventChannelWriter<hng::syscall_semantic_data>* out_syscall_;
    /// 输入等待与停机唤醒
    hng::EventLoop loop_;
    std::atomic<hng::ComponentState> lifecycle_{hng::ComponentState::READY};
    std::atomic<bool> stopped_{false};
    std::atomic<std::uint64_t> processed_syscall_{0};
    std::atomic<std::uint64_t> path_unresolved_{0};
};

#endif  // SEMANTIC_HPP
