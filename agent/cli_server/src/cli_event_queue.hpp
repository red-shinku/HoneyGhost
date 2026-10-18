/**
 * @file cli_event_queue.hpp
 * @brief 定义一条订阅流的私有事件队列
 * @author red-shinku
 * @date 2026.10.16
 */

#ifndef HNG_CLI_EVENT_QUEUE_HPP
#define HNG_CLI_EVENT_QUEUE_HPP

#include <atomic>
#include <cstddef>
#include <cstdint>

#include <userver/engine/single_consumer_event.hpp>

#include "agent/event_data/include/runtime_event.hpp"
#include "agent/util/include/spsc_queue.hpp"

/**
 * @brief hng::SPSC_Queue 的适配：入队与唤醒、挂起、丢弃计数
 * @details 生产者是引擎线程（普通线程，非协程），消费者是持有本队列的流消费任务；
 * 生产者侧只做入队与唤醒，不带协程原语。
 * @note 唤醒是合并的：生产者只在取得[通知权]时唤醒，而通知权只在消费者取空队列
 * 之后交还。故交还之后的入队必然唤醒，而消费者挂起前的最后一次复查覆盖交还之前的
 * 入队——两侧合起来既不丢唤醒，也不产生唤醒风暴。
 */
class CLIEventQueue final {
   public:
    explicit CLIEventQueue(std::size_t capacity);

    /// @brief 入队成功则尝试唤醒消费者；队列满则丢弃并计数。
    /// 唤醒只在消费者一端设置了 `notified_` 才执行
    void push(const hng::RuntimeEvent& event);

    /// @brief 尝试取一个事件，取空则设置 `notified_`，但不会挂起
    /// @param cursor 消费游标，由调用方持有；消费者跨线程时不影响正确性
    /// @return 取到为 true；空为 false
    bool try_pop(hng::RuntimeEvent& out, std::size_t& cursor);

    /// @brief 挂起消费者，直到队列状态可能变化、超时、任务被取消
    /// @return false 本任务已结束 / 被取消，调用方必须退出循环
    /// @note 返回 true 只表示状态可能变化，调用方须重新检查全部条件
    bool wait();

    /// @brief 任意线程可调用，表示队列状态可能变化。
    /// 会唤醒消费者，不会关闭队列
    void wake();

    /// @brief 任意线程可调用：关闭队列并唤醒任务
    void close();

    /// @brief 该队列的事件流是否已结束
    bool closed() const;

    /// @brief 累计丢弃的事件数
    uint64_t dropped() const;

   private:
    hng::SPSC_Queue<hng::RuntimeEvent> queue_;
    userver::engine::SingleConsumerEvent wakeup_;
    /// 消费者的通知权；生产者取得它才唤醒
    std::atomic<bool> notified_{false};
    std::atomic<bool> closed_{false};
    std::atomic<uint64_t> dropped_{0};
};

#endif  // HNG_CLI_EVENT_QUEUE_HPP
