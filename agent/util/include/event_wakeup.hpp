/**
 * @file event_wakeup.hpp
 * @brief 合并唤醒：eventfd 与通知权交接
 * @author red-shinku
 * @date 2026.11.01
 */

#ifndef HNG_EVENT_WAKEUP_HPP_
#define HNG_EVENT_WAKEUP_HPP_

#include <sys/eventfd.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <cstdint>
#include <system_error>

namespace hng {

/**
 * @brief 合并唤醒：写端只在取得通知权时写 eventfd
 * @details 写端与读端各只允许一条线程调用。读端把数据源取空后调用 consume()
 *          交还通知权，此后的入队必然写 fd；读端未取空期间写端不写 fd，故未
 *          取空的稳态下通知路径上没有系统调用。
 * @note consume() 之后必须复查数据源：在交还通知权之前入队的数据不会写 fd，
 *       只能由这次复查捕获。一次 consume() 与一次并发 notify() 可能留下一次
 *       多余的 fd 就绪，代价是一次 epoll 返回，不丢唤醒、不丢数据。
 */
class EventWakeup {
   public:
    /**
     * @brief 创建唤醒 fd
     * @throws std::system_error eventfd 创建失败
     */
    EventWakeup();
    ~EventWakeup();

    EventWakeup(const EventWakeup&)            = delete;
    EventWakeup& operator=(const EventWakeup&) = delete;

    /// @brief 供 epoll 等待的 fd
    /// @note 调用方不得关闭，生命周期由本对象持有
    int fd() const noexcept;

    /// @brief 通知读端：仅当本次取得通知权时写 fd
    /// @note 写失败只丢一次唤醒，不影响已入队的数据
    void notify() noexcept;

    /// @brief 读数清零并交还通知权
    /// @note 只能在数据源取空之后调用，调用后须复查数据源
    void consume() noexcept;

   private:
    /// true：已写 fd 且读端尚未取空
    std::atomic<bool> pending_{false};
    int fd_ = -1;
};

inline EventWakeup::EventWakeup() : fd_(::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK))
{
    if (fd_ < 0) {
        throw std::system_error(errno, std::generic_category(),
                                "eventfd for EventWakeup");
    }
}

inline EventWakeup::~EventWakeup()
{
    if (fd_ >= 0) {
        ::close(fd_);
    }
}

inline int EventWakeup::fd() const noexcept { return fd_; }

inline void EventWakeup::notify() noexcept
{
    if (pending_.exchange(true, std::memory_order_acq_rel)) {
        return;
    }
    const std::uint64_t one = 1;
    (void)::write(fd_, &one, sizeof(one));
}

inline void EventWakeup::consume() noexcept
{
    std::uint64_t value = 0;
    // 一次读即清零计数；无通知时返回 EAGAIN，同样是一次系统调用。
    (void)::read(fd_, &value, sizeof(value));
    pending_.store(false, std::memory_order_release);
}

}  // namespace hng

#endif  // HNG_EVENT_WAKEUP_HPP_
