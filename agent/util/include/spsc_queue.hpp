/**
 * @file spsc_queue.hpp
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

#ifndef SPSC_QUEUE_HPP_
#define SPSC_QUEUE_HPP_

#include <atomic>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <memory>

namespace hng {

// 常见架构（x86-64 / ARM64）的缓存行大小
constexpr size_t kCacheLineSize = 64;

namespace detail {

/// @brief 消费侧误用检出：打印诊断信息后终止进程
/// @param what 命中的检查
/// @param detail 由检出点的现场数据拼装的诊断正文
///
/// 仅在非 NDEBUG 构建被调用；Release 构建不带检查，本函数不被引用。
/// 调用点位于模板实现内，打印不出误用方的位置，定位靠调用栈。
[[noreturn]] inline void spsc_misuse_abort(const char* what, const char* detail)
{
    std::fprintf(stderr,
                 "[SPSC_Queue misuse] %s\n  %s\n"
                 "  A queue must be consumed by one pop overload only: mixing\n"
                 "  pop(T&) and pop(T&, size_t&) duplicates or skips elements.\n"
                 "  Run under a debugger to locate the call site.\n",
                 what, detail);
    std::abort();
}

}  // namespace detail

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
class alignas(kCacheLineSize) SPSC_Queue {
   public:
    explicit SPSC_Queue(size_t capacity);
    ~SPSC_Queue()                            = default;

    SPSC_Queue(const SPSC_Queue&)            = delete;
    SPSC_Queue& operator=(const SPSC_Queue&) = delete;

    bool push(const T& item);
    bool push(T&& item);

    /// @brief 取一个元素
    /// @param[out] item 取到的元素
    /// @warning 调用者可能跨线程时，不应该使用这个 pop
    bool pop(T& item);

    /// @brief 取一个元素，消费游标的权威由调用方持有。
    /// 调用者可能跨线程时使用该版本的 pop。
    /// @param[out] item 取到的元素
    /// @param[in,out] cursor 消费游标：已取出的元素数，调用方持有，初值 0；
    ///                       取到元素时自增
    /// @return 取到为 true；空为 false
    ///
    /// @note 这时consumer_.tail 仅作为对生产者的已发布水位。
    bool pop(T& item, size_t& cursor);

    // 以下方法跨线程调用时不保证一致性
    size_t size() const noexcept;
    bool empty() const noexcept;
    size_t capacity() const noexcept { return mask_ + 1; }

   private:
    struct alignas(kCacheLineSize) ProducerOnly {
        std::atomic<size_t> head{0};
    } producer_;

    struct alignas(kCacheLineSize) ConsumerOnly {
        std::atomic<size_t> tail{0};
        // 本队列是否已被「外置游标」方式消费过（误用检出用，非 NDEBUG
        // 构建才读写）。 置于 consumer 独占的缓存行内，不随 NDEBUG
        // 增删成员，以免改变对象布局。
        bool cursor_mode = false;
    } consumer_;

    size_t mask_;  ///< capacity - 1
    std::unique_ptr<T[]> buffer_;
};

template <class T>
SPSC_Queue<T>::SPSC_Queue(size_t capacity)
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
bool SPSC_Queue<T>::push(const T& item)
{
    const size_t head = producer_.head.load(std::memory_order_relaxed);
    const size_t tail = consumer_.tail.load(std::memory_order_acquire);

    // 满：head - tail == capacity == mask_ + 1
    if (head - tail > mask_) {
        return false;
    }

    // 写数据后以 release 发布 head：数据写入先于 head 发布，消费者 acquire 读
    // head 后可见
    buffer_[head & mask_] = item;
    producer_.head.store(head + 1, std::memory_order_release);
    return true;
}

template <class T>
bool SPSC_Queue<T>::push(T&& item)
{
    const size_t head = producer_.head.load(std::memory_order_relaxed);
    const size_t tail = consumer_.tail.load(std::memory_order_acquire);

    // 判断队列是否满
    if (head - tail > mask_) {
        return false;
    }

    // 写数据后以 release 发布 head：数据写入先于 head 发布，消费者 acquire 读
    // head 后可见
    buffer_[head & mask_] = std::move(item);
    producer_.head.store(head + 1, std::memory_order_release);
    return true;
}

template <class T>
bool SPSC_Queue<T>::pop(T& item)
{
    // 自身读索引：仅消费者更新，relaxed 即可
    const size_t tail = consumer_.tail.load(std::memory_order_relaxed);
    // 对端写索引：acquire 屏障，保证读到生产者 release 发布 head
    // 之前写入的完整数据
    const size_t head = producer_.head.load(std::memory_order_acquire);
#ifndef NDEBUG
    if (consumer_.cursor_mode) {
        char detail[160];
        std::snprintf(detail, sizeof(detail),
                      "queue=%p: bare pop advances the published index "
                      "(tail=%zu, head=%zu) but not the caller's cursor",
                      static_cast<const void*>(this), tail, head);
        detail::spsc_misuse_abort(
            "pop(T&) called on a queue already consumed via pop(T&, size_t&)",
            detail);
    }
#endif

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
bool SPSC_Queue<T>::pop(T& item, size_t& cursor)
{
    // 游标：调用方持有、单消费者独占，直接读取即可
    const size_t tail = cursor;
    // 对端写索引：acquire 屏障，保证读到生产者 release 发布 head
    // 之前写入的完整数据
    const size_t head = producer_.head.load(std::memory_order_acquire);
#ifndef NDEBUG
    consumer_.cursor_mode  = true;

    // 不变式：本重载每次成功取元素都让游标与水位同步前进，故调用方持有的游标
    // 必与水位相等；不等即说明混用把水位推到了游标之前，或游标不是本队列的进度。
    // 检查必须在空判之前：混用后队列恰空时，空判会直接返回而漏检
    const size_t published = consumer_.tail.load(std::memory_order_relaxed);
    if (cursor != published) {
        char detail[192];
        std::snprintf(detail, sizeof(detail),
                      "queue=%p: cursor=%zu, published tail=%zu, head=%zu",
                      static_cast<const void*>(this), cursor, published, head);
        detail::spsc_misuse_abort(
            "cursor out of sync with the queue's published consumer index",
            detail);
    }
#endif

    // 空：head == tail
    if (head == tail) {
        return false;
    }

    item   = buffer_[tail & mask_];

    // 推进游标，并以 release 发布 tail，使内部水位与游标同步
    cursor = tail + 1;
    consumer_.tail.store(cursor, std::memory_order_release);
    return true;
}

template <class T>
size_t SPSC_Queue<T>::size() const noexcept
{
    const size_t head = producer_.head.load(std::memory_order_relaxed);
    const size_t tail = consumer_.tail.load(std::memory_order_relaxed);
    return head - tail;
}

template <class T>
bool SPSC_Queue<T>::empty() const noexcept
{
    return size() == 0;
}

}  // namespace hng

#endif  // SPSC_QUEUE_HPP_
