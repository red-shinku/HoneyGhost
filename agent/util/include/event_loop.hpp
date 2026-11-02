/**
 * @file event_loop.hpp
 * @brief 多源就绪等待：epoll 与停机唤醒
 * @author red-shinku
 * @date 2026.11.01
 */

#ifndef HNG_EVENT_LOOP_HPP_
#define HNG_EVENT_LOOP_HPP_

#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <system_error>

namespace hng {

/**
 * @brief 多源就绪等待：一个 epoll 实例、一个停机 fd
 * @details 调用方把各唤醒源的 fd 以非 kStopTag 的 tag 登记，随后在 wait() 上
 *          阻塞；任一源就绪或 request_stop() 被调用即返回。只允许一条线程
 *          wait()，可在任意线程 request_stop()。
 * @note 登记的 fd 仍由各自的所有者持有与关闭；本对象不关闭它们。
 */
class EventLoop {
   public:
    /// @brief 停机源的 tag，不与调用方的 tag 冲突
    static constexpr std::uint64_t kStopTag = ~static_cast<std::uint64_t>(0);

    /// @brief 一条就绪源
    struct Ready {
        std::uint64_t tag = 0;
    };

    /**
     * @brief 创建 epoll 实例与停机 fd，并把停机 fd 以 kStopTag 登记
     * @throws std::system_error 创建或登记失败
     */
    EventLoop();
    ~EventLoop();

    EventLoop(const EventLoop&)            = delete;
    EventLoop& operator=(const EventLoop&) = delete;

    /// @brief 当前可登记源的上限
    static constexpr std::size_t capacity() { return kMaxSources; }

    /// @brief 登记一个唤醒源
    /// @param fd 唤醒源 fd，由调用方持有；不可为负
    /// @param tag 就绪时报告的标识，不可为 kStopTag
    /// @throws std::invalid_argument fd 为负或 tag 为 kStopTag
    /// @throws std::system_error epoll 登记失败或已登记的源达到上限
    void add(int fd, std::uint64_t tag);

    /// @brief 等待任一源就绪
    /// @param[out] out 就绪源，槽位数不得少于 capacity
    /// @param[in] capacity out 的槽位数
    /// @param[in] timeout_ms 等待上限，负值为不限
    /// @return 写入的源数；超时或被信号打断为 0
    /// @throws std::system_error epoll_wait 失败
    /// @note 返回 0 只表示本次没有就绪源，调用方须重新检查自己的条件
    std::size_t wait(Ready* out, std::size_t capacity, int timeout_ms = -1);

    /// @brief 要求等待方返回：写停机 fd
    /// @note 幂等，可从任意线程调用
    void request_stop() noexcept;

    /// @brief 停机源 fd
    /// @note 供调用方在 wait() 返回后识别 kStopTag 之外的使用场景
    int stop_fd() const noexcept;

   private:
    /// @brief 登记一个唤醒源，不做参数校验
    /// @throws std::system_error epoll 登记失败或已登记的源达到上限
    void add_impl(int fd, std::uint64_t tag);

    static constexpr std::size_t kMaxSources = 8;

    int epoll_fd_                            = -1;
    int stop_fd_                             = -1;
    std::size_t registered_                  = 0;
    bool stop_requested_                     = false;
    epoll_event events_[kMaxSources];
};

inline EventLoop::EventLoop()
    : epoll_fd_(::epoll_create1(EPOLL_CLOEXEC)),
      stop_fd_(::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK))
{
    if (epoll_fd_ < 0) {
        const int error = errno;
        if (stop_fd_ >= 0) {
            ::close(stop_fd_);
        }
        throw std::system_error(error, std::generic_category(),
                                "epoll_create1 for EventLoop");
    }
    if (stop_fd_ < 0) {
        const int error = errno;
        ::close(epoll_fd_);
        throw std::system_error(error, std::generic_category(),
                                "eventfd for EventLoop stop");
    }
    add_impl(stop_fd_, kStopTag);
}

inline EventLoop::~EventLoop()
{
    if (stop_fd_ >= 0) {
        ::close(stop_fd_);
    }
    if (epoll_fd_ >= 0) {
        ::close(epoll_fd_);
    }
}

inline void EventLoop::add(int fd, std::uint64_t tag)
{
    if (fd < 0) {
        throw std::invalid_argument("EventLoop::add: negative fd");
    }
    if (tag == kStopTag) {
        throw std::invalid_argument("EventLoop::add: kStopTag is reserved");
    }
    add_impl(fd, tag);
}

inline void EventLoop::add_impl(int fd, std::uint64_t tag)
{
    if (registered_ >= kMaxSources) {
        throw std::system_error(
            std::make_error_code(std::errc::too_many_files_open),
            "EventLoop::add: source table full");
    }
    epoll_event event{};
    event.events   = EPOLLIN;
    event.data.u64 = tag;
    if (::epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, fd, &event) != 0) {
        throw std::system_error(errno, std::generic_category(),
                                "epoll_ctl for EventLoop");
    }
    ++registered_;
}

inline std::size_t EventLoop::wait(Ready* out, std::size_t capacity,
                                   int timeout_ms)
{
    if (out == nullptr || capacity == 0) {
        return 0;
    }
    const std::size_t slots = std::min(capacity, kMaxSources);
    const int ready =
        ::epoll_wait(epoll_fd_, events_, static_cast<int>(slots), timeout_ms);
    if (ready < 0) {
        if (errno == EINTR) {
            return 0;
        }
        throw std::system_error(errno, std::generic_category(),
                                "epoll_wait for EventLoop");
    }
    for (int i = 0; i < ready; ++i) {
        out[i].tag = events_[i].data.u64;
    }
    return static_cast<std::size_t>(ready);
}

inline void EventLoop::request_stop() noexcept
{
    if (stop_requested_) {
        return;
    }
    stop_requested_         = true;
    const std::uint64_t one = 1;
    (void)::write(stop_fd_, &one, sizeof(one));
}

inline int EventLoop::stop_fd() const noexcept { return stop_fd_; }

}  // namespace hng

#endif  // HNG_EVENT_LOOP_HPP_
