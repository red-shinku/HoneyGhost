/**
 * @file notification_queue.hpp
 * @brief 多生产者、无界、可被 stop 打断的通知队列
 * @details
 * 用于推送式的通知：生产者入队即返回，消费者在自己的线程上取。角色事件、
 * 进程结构变化的速率是每秒个位数，故用互斥量与条件变量，不做无锁。
 * @author red_shinku
 * @date 2026.9.17
 */

#ifndef HNG_NOTIFICATION_QUEUE_HPP_
#define HNG_NOTIFICATION_QUEUE_HPP_

#include <condition_variable>
#include <cstddef>
#include <deque>
#include <mutex>
#include <utility>

namespace hng {

/**
 * @brief 多生产者、无界、可被 stop 打断的通知队列
 * @details
 * 入队不因容量而等待或丢弃，故生产者一侧的阻塞上界只是队列临界区的
 * 长度，与元素处理无关。
 * 停止语义是排空：stop() 之后 wait_pop 仍交出队列中剩余的元素，取空才返回
 * false——已入队的通知不会被静默丢弃。
 */
template <class T>
class NotificationQueue {
   public:
    NotificationQueue()                                    = default;

    NotificationQueue(const NotificationQueue&)            = delete;
    NotificationQueue& operator=(const NotificationQueue&) = delete;

    /// @brief 入队并立即返回
    /// @param item 待入队元素，按值移动入队
    /// @return 已入队为 true；已 stop() 时未入队并返回 false
    bool push(T item);

    /// @brief 阻塞取一个元素
    /// @param[out] item 取到的元素
    /// @return 取到为 true；已 stop() 且队列取空为 false
    bool wait_pop(T& item);

    /// @brief 非阻塞取一个元素
    /// @return 取到为 true；队列为空为 false
    bool try_pop(T& item);

    /// @brief 停止：唤醒全部等待者，此后 push 一律返回 false
    /// @note 幂等，可从任意线程调用，包括消费线程自身
    void stop();

    bool stopped() const;
    std::size_t size() const;
    bool empty() const;

   private:
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::deque<T> queue_;
    bool stopped_ = false;
};

template <class T>
bool NotificationQueue<T>::push(T item)
{
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (stopped_) {
            return false;
        }
        queue_.push_back(std::move(item));
    }
    cv_.notify_one();
    return true;
}

template <class T>
bool NotificationQueue<T>::wait_pop(T& item)
{
    std::unique_lock<std::mutex> lock(mutex_);
    cv_.wait(lock, [this] { return stopped_ || !queue_.empty(); });
    if (queue_.empty()) {
        return false;  // 已停止且取空
    }
    item = std::move(queue_.front());
    queue_.pop_front();
    return true;
}

template <class T>
bool NotificationQueue<T>::try_pop(T& item)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (queue_.empty()) {
        return false;
    }
    item = std::move(queue_.front());
    queue_.pop_front();
    return true;
}

template <class T>
void NotificationQueue<T>::stop()
{
    {
        std::lock_guard<std::mutex> lock(mutex_);
        stopped_ = true;
    }
    cv_.notify_all();
}

template <class T>
bool NotificationQueue<T>::stopped() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return stopped_;
}

template <class T>
std::size_t NotificationQueue<T>::size() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return queue_.size();
}

template <class T>
bool NotificationQueue<T>::empty() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return queue_.empty();
}

}  // namespace hng

#endif  // HNG_NOTIFICATION_QUEUE_HPP_
