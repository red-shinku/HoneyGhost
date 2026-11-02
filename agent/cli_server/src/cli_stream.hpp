/**
 * @file cli_stream.hpp
 * @brief 定义 CLIStream，一路订阅流
 * @author red-shinku
 * @date 2026.10.16
 */

#ifndef HNG_CLI_STREAM_HPP
#define HNG_CLI_STREAM_HPP

#include <atomic>
#include <cstddef>
#include <cstdint>

#include "agent/cli_server/src/cli_event_queue.hpp"
#include "agent/event_data/include/runtime_info_filter.hpp"
#include "agent/runtime_engine/include/subscriber_reg_service.hpp"

class CLIStreamManager;

/**
 * @brief 一条订阅流。
 * 构造时以裸指针形式登记进 CLIStreamManager 的流表，teardown()
 * 摘除；生命周期 由持有它的 handler 栈帧唯一拥有。
 * @note 不依赖任何生成的 proto 类型：消费循环写在 handler 里，本类只提供
 * 「取 / 丢弃计数 / 已结束 / 挂起」四件事。
 * @warning 析构前必须已 teardown()，否则引擎表里会留下本对象的悬空指针
 */
class CLIStream final : public RuntimeEventSink, public UnsubscribeAck {
   public:
    CLIStream(CLIStreamManager& owner, SubscriberRegService& engine,
              RuntimeInfoFilter filter, std::size_t queue_capacity);
    ~CLIStream();

    CLIStream(const CLIStream&)            = delete;
    CLIStream& operator=(const CLIStream&) = delete;

    /// @brief 实现入队与唤醒逻辑，生产者端调用。非阻塞。
    void on_event(const hng::RuntimeEvent event) override;

    /// @brief ack 回调。由生产者端调用。
    /// @see UnsubscribeAck
    void on_unsubscribed() override;

    /// @brief 建立订阅
    /// @return 订阅命令被拒时为 false；此时既无事件也无ack
    bool subscribe();

    /// @brief 拆除这条订阅流：注销、等ack、摘表。是幂等的。
    /// @note 在消费任务上调用；内部屏蔽任务取消，故等待不会被取消打断
    /// @note 等待不需要设超时： @see UnsubscribeAck
    void teardown();

    /// @brief 消费任务：取一个事件
    bool try_pop(hng::RuntimeEvent& out, std::size_t& cursor);

    /// @brief 累计丢弃的事件数
    uint64_t dropped() const;

    /// @brief 返回本流是否已结束。
    /// @note 判据只在队列取空之后有效：队列里残留的事件应先写出去
    bool finished() const;

    /// @brief 挂起直到状态可能变化
    /// @return false = 本任务已被取消
    bool wait();

    /// @brief 任意线程可调用：要求本流停止；只置标志并唤醒
    void close();

   private:
    CLIStreamManager& owner_;
    SubscriberRegService& engine_;
    RuntimeInfoFilter filter_;
    CLIEventQueue queue_;

    /// 置为 true 后，订阅命令已进入 RuntimeEngine
    /// @see CLIStream::subscribe
    bool subscribed_ = false;

    /// ack 已到，这条订阅流的生产者一段不会再推事件
    /// @see CLIStream::on_unsubscribed
    std::atomic<bool> unsubscribed_{false};

    bool torn_down_ = false;
};

#endif  // HNG_CLI_STREAM_HPP
