/**
 * @file raw_event_queue_ss.hpp
 * @brief 单生产者单消费者（SPSC）无锁环形队列
 * @details
 *
 * 基于数组的环形缓冲区；头尾索引分别独占一个缓存行；
 * 使用轻量内存屏障（release / acquire）控制数据读写与对端索引检查的可见性。
 * 仅支持单生产者线程 + 单消费者线程。
 *
 * @author red_shinku
 * @date 2026.08.13
 */

#ifndef RAW_EVENT_QUEUE_SS_HPP
#define RAW_EVENT_QUEUE_SS_HPP

#include <atomic>
#include <cstddef>
#include <memory>

namespace hng {

// 常见架构（x86-64 / ARM64）的缓存行大小
constexpr size_t kCacheLineSize = 64;

/**
 * @brief SPSC 无锁队列
 * @tparam T 元素类型（要求可默认构造、可拷贝、可赋值）
 *
 * 设计要点：
 *  - 索引为单调递增计数器，仅在寻址时与 mask_ 按位取模，无回绕歧义；
 *  - producer_.head（写索引）与 consumer_.tail（读索引）各独占一个缓存行，
 *    避免生产者 / 消费者频繁伪共享；
 *  - 读写数据与对端索引检查之间使用 release / acquire 轻量内存屏障：
 *      - push：写数据后用 release 发布 head，保证数据写入先于 head 发布可见；
 *      - pop ：用 acquire 读取 head，保证读到发布 head 之前写入的完整数据；
 *      - push 用 acquire 读取 tail，保证消费者释放槽位后本线程才复用该槽位；
 *      - pop 用 release 发布 tail，通知生产者该槽位已消费、可复用。
 *
 */
template <class T>
class alignas(kCacheLineSize) RawEventQueue_SS {
   public:
    explicit RawEventQueue_SS(size_t capacity);
    ~RawEventQueue_SS()                                  = default;

    RawEventQueue_SS(const RawEventQueue_SS&)            = delete;
    RawEventQueue_SS& operator=(const RawEventQueue_SS&) = delete;

    bool push(const T& item);

    bool pop(T& item);

    // 以下方法跨线程调用时不保证一致性
    size_t size() const noexcept;
    bool empty() const noexcept;
    size_t capacity() const noexcept { return mask_ + 1; }

   private:
    // 生产者独占：写索引 head，单独占用一个缓存行
    struct alignas(kCacheLineSize) ProducerOnly {
        std::atomic<size_t> head{0};
    } producer_;

    // 消费者独占：读索引 tail，单独占用一个缓存行
    struct alignas(kCacheLineSize) ConsumerOnly {
        std::atomic<size_t> tail{0};
    } consumer_;

    size_t mask_;  ///< capacity - 1
    std::unique_ptr<T[]> buffer_;
};

template <class T>
RawEventQueue_SS<T>::RawEventQueue_SS(size_t capacity)
{
    if (capacity == 0) {
        capacity = 1;
    }
    // 向上取整为 2 的幂，使索引寻址可用 & mask_ 代替取模
    size_t cap = 1;
    while (cap < capacity) {
        cap <<= 1;
    }
    mask_ = cap - 1;
    buffer_.reset(new T[cap]);
}

template <class T>
bool RawEventQueue_SS<T>::push(const T& item)
{
    // 自身写索引：仅生产者更新，relaxed 即可
    const size_t head = producer_.head.load(std::memory_order_relaxed);
    // 对端读索引：acquire 屏障，保证消费者 release tail 前已完成的读操作（释放槽位）对本线程可见
    const size_t tail = consumer_.tail.load(std::memory_order_acquire);

    // 满：head - tail == capacity == mask_ + 1
    if (head - tail > mask_) {
        return false;
    }

    // 写数据后以 release 发布 head：数据写入先于 head 发布，消费者 acquire 读 head 后可见
    buffer_[head & mask_] = item;
    producer_.head.store(head + 1, std::memory_order_release);
    return true;
}

template <class T>
bool RawEventQueue_SS<T>::pop(T& item)
{
    // 自身读索引：仅消费者更新，relaxed 即可
    const size_t tail = consumer_.tail.load(std::memory_order_relaxed);
    // 对端写索引：acquire 屏障，保证读到生产者 release 发布 head 之前写入的完整数据
    const size_t head = producer_.head.load(std::memory_order_acquire);

    // 空：head == tail
    if (head == tail) {
        return false;
    }

    // acquire 已与生产者的 release 建立同步，读到的是发布 head 前的完整数据
    item = buffer_[tail & mask_];

    // release 发布 tail：通知生产者该槽位已消费、可复用
    consumer_.tail.store(tail + 1, std::memory_order_release);
    return true;
}

template <class T>
size_t RawEventQueue_SS<T>::size() const noexcept
{
    const size_t head = producer_.head.load(std::memory_order_relaxed);
    const size_t tail = consumer_.tail.load(std::memory_order_relaxed);
    return head - tail;
}

template <class T>
bool RawEventQueue_SS<T>::empty() const noexcept
{
    return size() == 0;
}

}  // namespace hng

#endif  // RAW_EVENT_QUEUE_SS_HPP
