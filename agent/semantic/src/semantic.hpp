#ifndef SEMANTIC_HPP
#define SEMANTIC_HPP

#include "agent/event_data/include/file_event.hpp"
#include "agent/event_data/include/syscall_event.hpp"
#include "agent/util/include/component.hpp"
#include "agent/util/include/spsc_queue.hpp"
#include "kernel/include/files_type.h"
#include "kernel/include/syscalls_type.h"

#include <atomic>
#include <cstddef>

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
 * @brief 语义聚合：单线程消费两条原始事件队列并写入对应语义队列。
 * @details 线程由装配层创建；本类不持 std::thread。每轮按预算轮转 file 与
 *          syscall 两条线，空转时休眠，stop() 后排空输入队列再退出。
 * @note 生命周期为 READY → RUNNING → STOPPED。队列指针可为空，表示该线未接线；
 *       非空队列须比本对象活得更久。run() 返回前不得析构。
 * @see hng::Component
 */
class Semantic final : public hng::Component {
   public:
    /**
     * @brief 绑定两条原始事件队列与两条语义事件队列。
     * @param raw_file 文件原始事件队列；未接线传 nullptr
     * @param raw_syscall 系统调用原始事件队列；未接线传 nullptr
     * @param out_file 文件语义事件队列；未接线传 nullptr
     * @param out_syscall 系统调用语义事件队列；未接线传 nullptr
     */
    Semantic(hng::SPSC_Queue<file_access_data>* raw_file,
             hng::SPSC_Queue<struct syscall_event>* raw_syscall,
             hng::SPSC_Queue<hng::file_semantic_data>* out_file,
             hng::SPSC_Queue<hng::syscall_semantic_data>* out_syscall);
    ~Semantic() override;

    Semantic(const Semantic&)            = delete;
    Semantic& operator=(const Semantic&) = delete;
    Semantic(Semantic&&)                 = delete;
    Semantic& operator=(Semantic&&)      = delete;

    /**
     * @brief 语义化线程入口：按预算轮转两条线，直至 stop()。
     * @pre state() 为 READY；否则立即返回且不改变状态
     * @note 退出前排空两条原始事件队列；不创建线程。
     */
    void run() override;
    /**
     * @brief 置停止标志；幂等，可从任意线程调用。
     * @note 未进入 RUNNING 时直接置 STOPPED。run() 最多在一个空闲周期后返回。
     */
    void stop() override;
    /**
     * @brief 当前生命周期状态。
     * @note 可从任意线程读取。
     */
    hng::ComponentState state() const override;

   private:
    /**
     * @brief 从文件原始队列取至多 budget 条，转换后推入输出队列。
     * @return 处理条数
     */
    std::size_t drain_file(std::size_t budget);
    /**
     * @brief 从系统调用原始队列取至多 budget 条，转换后推入输出队列。
     * @return 处理条数
     */
    std::size_t drain_syscall(std::size_t budget);

    Semantic_file file_tool_;
    Semantic_syscall syscall_tool_;
    hng::SPSC_Queue<file_access_data>* raw_file_;
    hng::SPSC_Queue<struct syscall_event>* raw_syscall_;
    hng::SPSC_Queue<hng::file_semantic_data>* out_file_;
    hng::SPSC_Queue<hng::syscall_semantic_data>* out_syscall_;
    std::atomic<hng::ComponentState> lifecycle_{hng::ComponentState::READY};
    std::atomic<bool> stopped_{false};
};

#endif  // SEMANTIC_HPP
