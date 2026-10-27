/**
 * @file collector.cc
 * @brief 采集聚合的 epoll 驱动与停机实现。
 */
#include "agent/collector/include/collector.hpp"

#include <cerrno>
#include <cstdint>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <unistd.h>
#include <unordered_map>
#include <utility>
#include <vector>

namespace {

/// 每条线在单次 epoll 就绪后最多消费的记录数
constexpr std::size_t kBudgetPerLine = 256;

/// 停机 eventfd 或某条线的 epoll fd 不可用时的等待上限
constexpr int kFallbackTimeoutMs     = 100;

}  // namespace

Collector::Collector(std::vector<std::unique_ptr<CollectorType>> lines)
    : stop_event_fd_(::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK))
{
    lines_.reserve(lines.size());
    for (auto& line : lines) {
        if (line) {
            lines_.push_back(std::move(line));
        }
    }
}

Collector::~Collector()
{
    if (stop_event_fd_ >= 0) {
        ::close(stop_event_fd_);
    }
}

bool Collector::prepare()
{
    if (lifecycle_.load(std::memory_order_acquire) !=
        hng::ComponentState::CONSTRUCTED) {
        return false;
    }
    for (auto& line : lines_) {
        if (!line->prepare()) {
            return false;
        }
    }
    return true;
}

bool Collector::attach()
{
    if (lifecycle_.load(std::memory_order_acquire) !=
        hng::ComponentState::CONSTRUCTED) {
        return false;
    }
    for (auto& line : lines_) {
        if (!line->attach()) {
            for (auto& attached : lines_) {
                attached->detach();
            }
            return false;
        }
    }
    hng::ComponentState expected = hng::ComponentState::CONSTRUCTED;
    if (!lifecycle_.compare_exchange_strong(expected,
                                            hng::ComponentState::READY)) {
        for (auto& attached : lines_) {
            attached->detach();
        }
        return false;
    }
    return true;
}

bool Collector::init()
{
    if (!prepare()) {
        return false;
    }
    return attach();
}

std::vector<int> Collector::role_filter_map_fds() const
{
    std::vector<int> fds;
    fds.reserve(lines_.size());
    for (const auto& line : lines_) {
        const int fd = line->role_filter_map_fd();
        if (fd >= 0) {
            fds.push_back(fd);
        }
    }
    return fds;
}

void Collector::run()
{
    hng::ComponentState expected = hng::ComponentState::READY;
    if (!lifecycle_.compare_exchange_strong(expected,
                                            hng::ComponentState::RUNNING)) {
        return;
    }

    const int epoll_fd = ::epoll_create1(EPOLL_CLOEXEC);
    if (epoll_fd < 0) {
        for (auto& line : lines_) {
            line->detach();
            while (line->consume(kBudgetPerLine) > 0) {
            }
        }
        lifecycle_.store(hng::ComponentState::STOPPED, std::memory_order_release);
        return;
    }

    bool stop_fd_added = false;
    if (stop_event_fd_ >= 0) {
        epoll_event event{};
        event.events  = EPOLLIN;
        event.data.fd = stop_event_fd_;
        stop_fd_added =
            ::epoll_ctl(epoll_fd, EPOLL_CTL_ADD, stop_event_fd_, &event) == 0;
    }

    // fd → 采集线；epoll_ctl 失败或没有 epoll fd 的线退回超时轮询。
    std::unordered_map<int, CollectorType*> by_fd;
    std::vector<CollectorType*> polled_lines;
    for (auto& line : lines_) {
        const int fd = line->epoll_fd();
        if (fd < 0) {
            polled_lines.push_back(line.get());
            continue;
        }
        epoll_event event{};
        event.events  = EPOLLIN;
        event.data.fd = fd;
        if (::epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event) == 0) {
            by_fd.emplace(fd, line.get());
        }
        else {
            polled_lines.push_back(line.get());
        }
    }

    const int max_events = static_cast<int>(by_fd.size()) + 1;
    std::vector<epoll_event> events(static_cast<std::size_t>(max_events));
    const int timeout =
        (stop_fd_added && polled_lines.empty()) ? -1 : kFallbackTimeoutMs;

    while (!stopped_.load(std::memory_order_acquire)) {
        const int ready =
            ::epoll_wait(epoll_fd, events.data(), max_events, timeout);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (ready == 0) {
            for (CollectorType* line : polled_lines) {
                (void)line->consume(kBudgetPerLine);
            }
            continue;
        }
        for (int i = 0; i < ready; ++i) {
            const int fd = events[i].data.fd;
            if (fd == stop_event_fd_) {
                stopped_.store(true, std::memory_order_release);
                break;
            }
            auto line = by_fd.find(fd);
            if (line == by_fd.end()) {
                continue;
            }
            if ((events[i].events & (EPOLLERR | EPOLLHUP)) != 0 ||
                line->second->consume(kBudgetPerLine) < 0) {
                ::epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, nullptr);
                by_fd.erase(line);
            }
        }
    }

    ::close(epoll_fd);

    // 先摘探针，避免排空期间再产生新事件；随后逐线排空 ringbuf。
    for (auto& line : lines_) {
        line->detach();
    }
    for (auto& line : lines_) {
        while (line->consume(kBudgetPerLine) > 0) {
        }
    }

    lifecycle_.store(hng::ComponentState::STOPPED, std::memory_order_release);
}

void Collector::stop()
{
    stopped_.store(true, std::memory_order_release);
    if (stop_event_fd_ >= 0) {
        const std::uint64_t one = 1;
        const ssize_t written   = ::write(stop_event_fd_, &one, sizeof(one));
        (void)written;
    }
    hng::ComponentState current = lifecycle_.load(std::memory_order_acquire);
    while (current != hng::ComponentState::RUNNING &&
           !lifecycle_.compare_exchange_weak(current,
                                             hng::ComponentState::STOPPED)) {
    }
}

hng::ComponentState Collector::state() const
{
    return lifecycle_.load(std::memory_order_acquire);
}
