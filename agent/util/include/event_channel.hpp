/**
 * @file event_channel.hpp
 * @brief 带唤醒的事件通道：环形队列、读写视图与关闭语义
 * @author red-shinku
 * @date 2026.11.01
 */

#ifndef HNG_EVENT_CHANNEL_HPP_
#define HNG_EVENT_CHANNEL_HPP_

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <utility>

#include "agent/util/include/event_wakeup.hpp"
#include "agent/util/include/spsc_queue.hpp"

namespace hng {

template <class T>
class EventChannel;

/**
 * @brief 通道写端：入队并唤醒读端
 * @details 由通道持有，调用方只借用；只允许一条线程调用。
 * @note 队列满与通道已关闭都会拒绝入队，两种拒绝分别计数。
 */
template <class T>
class EventChannelWriter {
   public:
    explicit EventChannelWriter(EventChannel<T>& channel) noexcept;

    /// @brief 入队并唤醒读端
    /// @return 已入队为 true；队列满或通道已关闭为 false
    bool push(const T& item);
    bool push(T&& item);

    /// @brief 关闭通道：此后入队一律被拒，阻塞的读端被唤醒
    /// @note 已入队元素仍可被读端取走；幂等
    void close() noexcept;

    /// @brief 累计因队列满而被拒的入队次数
    /// @note 调用方重试时每次被拒都计一次；不重试的调用方即丢失的元素数
    std::uint64_t dropped() const noexcept;

    /// @brief 累计因通道已关闭而被拒的入队次数
    std::uint64_t rejected() const noexcept;

   private:
    EventChannel<T>* channel_;
};

/**
 * @brief 通道读端：取元素并观察关闭
 * @details 由通道持有，调用方只借用；只允许一条线程调用，且必须是等待
 *          fd() 的那条线程。
 */
template <class T>
class EventChannelReader {
   public:
    explicit EventChannelReader(EventChannel<T>& channel) noexcept;

    /// @brief 取一个元素；取空时交还通知权并复查一次
    /// @return 取到为 true
    /// @note 取空的调用会消耗已发的唤醒，故 fd() 在取空之后不再就绪
    bool try_pop(T& item);

    /// @brief 供 epoll 等待的 fd
    /// @note 调用方不得关闭；读空后的复查由 try_pop 负责
    int fd() const noexcept;

    /// @brief 写端是否已关闭
    /// @note 关闭后仍可能有未取走的元素，取空才算结束
    bool closed() const noexcept;

    /// @see EventChannelWriter::dropped
    std::uint64_t dropped() const noexcept;

    /// @see EventChannelWriter::rejected
    std::uint64_t rejected() const noexcept;

   private:
    EventChannel<T>* channel_;
};

/**
 * @brief 单生产者单消费者的有界事件通道
 * @details 存储为 SPSC 环形队列，唤醒为合并唤醒的 eventfd。写端在未取满时
 *          不写 fd，故满负荷下通知路径上没有系统调用；读端取空即阻塞在
 *          fd() 上。通道由装配层持有，写端与读端分别注入上下游模块。
 * @note 关闭由写端发起，只拒绝后续入队，不丢弃已入队元素；读写两端各只允许
 *       一条线程。
 * @see EventChannelWriter, EventChannelReader, EventWakeup
 */
template <class T>
class EventChannel {
   public:
    /**
     * @brief 创建通道
     * @param capacity 容量，向上取整为 2 的幂
     * @throws std::system_error 唤醒 fd 创建失败
     */
    explicit EventChannel(std::size_t capacity);
    ~EventChannel();

    EventChannel(const EventChannel&)            = delete;
    EventChannel& operator=(const EventChannel&) = delete;

    /// @brief 写端视图
    /// @note 由装配层交给上游模块，生命周期与本对象相同
    EventChannelWriter<T>& writer() noexcept;

    /// @brief 读端视图
    /// @note 由装配层交给下游模块，生命周期与本对象相同
    EventChannelReader<T>& reader() noexcept;

    /// @brief 当前元素数
    /// @note 跨线程调用时不保证一致性，只供单线程观察
    std::size_t size() const noexcept;

    /// @brief 是否为空
    /// @note 跨线程调用时不保证一致性，只供单线程观察
    bool empty() const noexcept;

   private:
    friend class EventChannelWriter<T>;
    friend class EventChannelReader<T>;

    bool push(const T& item);
    bool push(T&& item);
    bool pop(T& item);
    void close() noexcept;
    bool closed() const noexcept;
    std::uint64_t dropped() const noexcept;
    std::uint64_t rejected() const noexcept;

    SPSC_Queue<T> ring_;
    EventWakeup wakeup_;
    std::atomic<bool> closed_{false};
    std::atomic<std::uint64_t> dropped_{0};
    std::atomic<std::uint64_t> rejected_{0};
    EventChannelWriter<T> writer_;
    EventChannelReader<T> reader_;
};

template <class T>
EventChannelWriter<T>::EventChannelWriter(EventChannel<T>& channel) noexcept
    : channel_(&channel)
{
}

template <class T>
bool EventChannelWriter<T>::push(const T& item)
{
    return channel_->push(item);
}

template <class T>
bool EventChannelWriter<T>::push(T&& item)
{
    return channel_->push(std::move(item));
}

template <class T>
void EventChannelWriter<T>::close() noexcept
{
    channel_->close();
}

template <class T>
std::uint64_t EventChannelWriter<T>::dropped() const noexcept
{
    return channel_->dropped();
}

template <class T>
std::uint64_t EventChannelWriter<T>::rejected() const noexcept
{
    return channel_->rejected();
}

template <class T>
EventChannelReader<T>::EventChannelReader(EventChannel<T>& channel) noexcept
    : channel_(&channel)
{
}

template <class T>
bool EventChannelReader<T>::try_pop(T& item)
{
    return channel_->pop(item);
}

template <class T>
int EventChannelReader<T>::fd() const noexcept
{
    return channel_->wakeup_.fd();
}

template <class T>
bool EventChannelReader<T>::closed() const noexcept
{
    return channel_->closed();
}

template <class T>
std::uint64_t EventChannelReader<T>::dropped() const noexcept
{
    return channel_->dropped();
}

template <class T>
std::uint64_t EventChannelReader<T>::rejected() const noexcept
{
    return channel_->rejected();
}

template <class T>
EventChannel<T>::EventChannel(std::size_t capacity)
    : ring_(capacity), writer_(*this), reader_(*this)
{
}

template <class T>
EventChannel<T>::~EventChannel()
{
    // 先关门再析构：此后写端不会再发起通知，读端也不再等待
    close();
}

template <class T>
EventChannelWriter<T>& EventChannel<T>::writer() noexcept
{
    return writer_;
}

template <class T>
EventChannelReader<T>& EventChannel<T>::reader() noexcept
{
    return reader_;
}

template <class T>
std::size_t EventChannel<T>::size() const noexcept
{
    return ring_.size();
}

template <class T>
bool EventChannel<T>::empty() const noexcept
{
    return ring_.empty();
}

template <class T>
bool EventChannel<T>::push(const T& item)
{
    if (closed()) {
        rejected_.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    if (!ring_.push(item)) {
        dropped_.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    wakeup_.notify();
    return true;
}

template <class T>
bool EventChannel<T>::push(T&& item)
{
    if (closed()) {
        rejected_.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    if (!ring_.push(std::move(item))) {
        dropped_.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    wakeup_.notify();
    return true;
}

template <class T>
bool EventChannel<T>::pop(T& item)
{
    if (ring_.pop(item)) {
        return true;
    }
    // 取空：交还通知权，并复查一次以捕获交还之前的入队
    wakeup_.consume();
    return ring_.pop(item);
}

template <class T>
void EventChannel<T>::close() noexcept
{
    if (closed_.exchange(true, std::memory_order_acq_rel)) {
        return;
    }
    wakeup_.notify();
}

template <class T>
bool EventChannel<T>::closed() const noexcept
{
    return closed_.load(std::memory_order_acquire);
}

template <class T>
std::uint64_t EventChannel<T>::dropped() const noexcept
{
    return dropped_.load(std::memory_order_relaxed);
}

template <class T>
std::uint64_t EventChannel<T>::rejected() const noexcept
{
    return rejected_.load(std::memory_order_relaxed);
}

}  // namespace hng

#endif  // HNG_EVENT_CHANNEL_HPP_
