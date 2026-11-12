#ifndef SEMANTIC_HPP
#define SEMANTIC_HPP

#include "agent/event_data/include/file_event.hpp"
#include "agent/event_data/include/syscall_event.hpp"
#include "agent/util/include/component.hpp"
#include "agent/util/include/event_channel.hpp"
#include "agent/util/include/event_loop.hpp"
#include "agent/util/include/pipeline_stats.hpp"
#include "kernel/include/files_type.h"
#include "kernel/include/syscalls_type.h"

#include <atomic>
#include <cstddef>
#include <cstdint>

/**
 * @brief 文件事件语义化工具。
 * @note 无状态、无队列；同一实例可被单线程重复调用。
 */
class Semantic_file {
   public:
    Semantic_file() = default;

    /**
     * @brief 单条文件原始事件 → 语义事件（纯转换）。
     * @param raw 文件原始事件
     * @param[out] out 语义事件；头部按 raw 填充，载荷只保留语义化文件名
     */
    void transform_one(const file_access_data& raw,
                       hng::file_semantic_data& out) const;
};

/**
 * @brief 系统调用事件语义化工具。
 * @details 按 hdr.type 分派到八种语义载荷；无状态、无队列。
 * @note 同一实例可被单线程重复调用。
 */
class Semantic_syscall {
   public:
    Semantic_syscall() = default;

    /**
     * @brief 单条系统调用原始事件 → 语义事件（纯转换）。
     * @param raw 系统调用原始事件
     * @param[out] out 语义事件；头部按 raw 填充，载荷按 hdr.type 构造
     */
    void transform_one(const struct syscall_event& raw,
                       hng::syscall_semantic_data& out) const;
};

/**
 * @brief 语义聚合：单线程消费两条原始事件通道并写入对应语义通道。
 * @details 线程由装配层创建；本类不持 std::thread。每轮按预算轮转 file 与
 *          syscall 两条线，两条都取空时阻塞在事件循环上，stop() 用其停机 fd
 *          唤醒。退出前排空输入并关闭输出通道。
 * @note 生命周期为 READY → RUNNING → STOPPED。通道读写端指针可为空，表示该线
 *       未接线；非空通道须比本对象活得更久。run() 返回前不得析构。
 * @see hng::Component, hng::EventChannel
 */
class Semantic final : public hng::Component {
   public:
    /**
     * @brief 绑定两条原始事件通道的读端与两条语义通道的写端。
     * @param raw_file 文件原始事件通道读端；未接线传 nullptr
     * @param raw_syscall 系统调用原始事件通道读端；未接线传 nullptr
     * @param out_file 文件语义事件通道写端；未接线传 nullptr
     * @param out_syscall 系统调用语义事件通道写端；未接线传 nullptr
     * @throws std::system_error 事件循环 fd 创建失败
     */
    Semantic(hng::EventChannelReader<file_access_data>* raw_file,
             hng::EventChannelReader<struct syscall_event>* raw_syscall,
             hng::EventChannelWriter<hng::file_semantic_data>* out_file,
             hng::EventChannelWriter<hng::syscall_semantic_data>* out_syscall);
    ~Semantic() override;

    Semantic(const Semantic&)            = delete;
    Semantic& operator=(const Semantic&) = delete;
    Semantic(Semantic&&)                 = delete;
    Semantic& operator=(Semantic&&)      = delete;

    /**
     * @brief 语义化线程入口：按预算轮转两条线，直至 stop()。
     * @pre state() 为 READY；否则立即返回且不改变状态
     * @note 退出前排空两条原始事件通道并关闭两条语义通道；不创建线程。
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
    static constexpr std::uint64_t kFileTag    = 1;
    static constexpr std::uint64_t kSyscallTag = 2;

    /**
     * @brief 从文件原始通道取至多 budget 条，转换后推入输出通道。
     * @return 处理条数
     */
    std::size_t drain_file(std::size_t budget);
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

    Semantic_file file_tool_;
    Semantic_syscall syscall_tool_;
    hng::EventChannelReader<file_access_data>* raw_file_;
    hng::EventChannelReader<struct syscall_event>* raw_syscall_;
    hng::EventChannelWriter<hng::file_semantic_data>* out_file_;
    hng::EventChannelWriter<hng::syscall_semantic_data>* out_syscall_;
    /// 输入等待与停机唤醒
    hng::EventLoop loop_;
    std::atomic<hng::ComponentState> lifecycle_{hng::ComponentState::READY};
    std::atomic<bool> stopped_{false};
    std::atomic<std::uint64_t> processed_file_{0};
    std::atomic<std::uint64_t> processed_syscall_{0};
};

#endif  // SEMANTIC_HPP
