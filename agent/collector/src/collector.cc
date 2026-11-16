/**
 * @file collector.cc
 * @brief 采集聚合的 epoll 驱动与停机实现。
 */
#include "agent/collector/src/collector.hpp"
#include "agent/util/include/log.hpp"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <cerrno>
#include <cstdint>
#include <cstring>
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

const char* state_name(hng::ComponentState state) noexcept
{
    switch (state) {
        case hng::ComponentState::CONSTRUCTED:
            return "CONSTRUCTED";
        case hng::ComponentState::READY:
            return "READY";
        case hng::ComponentState::RUNNING:
            return "RUNNING";
        case hng::ComponentState::STOPPED:
            return "STOPPED";
    }
    return "UNKNOWN";
}

}  // namespace

namespace hng::detail {

std::uint64_t ReadPercpuCounter(int fd) noexcept
{
    if (fd < 0) {
        return 0;
    }
    const int cpus = ::libbpf_num_possible_cpus();
    if (cpus <= 0) {
        return 0;
    }
    std::vector<std::uint64_t> values(static_cast<std::size_t>(cpus), 0);
    const std::uint32_t key = 0;
    if (::bpf_map_lookup_elem(fd, &key, values.data()) != 0) {
        return 0;
    }
    std::uint64_t total = 0;
    for (const std::uint64_t value : values) {
        total += value;
    }
    return total;
}

}  // namespace hng::detail

Collector::Collector(std::vector<std::unique_ptr<CollectorType>> lines)
{
    stop_event_fd_ = ::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (stop_event_fd_ < 0) {
        const int error = errno;
        HNG_LOG_ERROR(
            "collector stop eventfd creation failed: {}; using {} ms polling",
            std::strerror(error), kFallbackTimeoutMs);
    }
    lines_.reserve(lines.size());
    for (auto& line : lines) {
        if (line) {
            lines_.push_back(std::move(line));
        }
    }
    HNG_LOG_INFO("collector created: {} event line(s)", lines_.size());
    if (lines_.empty()) {
        HNG_LOG_WARN(
            "collector has no event lines; run() will only wait for stop");
    }
    HNG_LOG_DEBUG("collector stop eventfd: {}", stop_event_fd_);
}

Collector::~Collector()
{
    if (stop_event_fd_ >= 0) {
        ::close(stop_event_fd_);
    }
}

bool Collector::prepare()
{
    const hng::ComponentState state = lifecycle_.load(std::memory_order_acquire);
    if (state != hng::ComponentState::CONSTRUCTED) {
        HNG_LOG_WARN("collector prepare ignored: state is {}", state_name(state));
        return false;
    }
    HNG_LOG_DEBUG("collector preparing {} event lines", lines_.size());
    for (std::size_t i = 0; i < lines_.size(); ++i) {
        HNG_LOG_DEBUG("collector preparing line {}", i);
        if (!lines_[i]->prepare()) {
            HNG_LOG_ERROR("collector prepare failed at line {}; aborting", i);
            return false;
        }
        HNG_LOG_DEBUG("collector line {} prepared", i);
    }
    HNG_LOG_INFO("collector prepared: {} event line(s)", lines_.size());
    return true;
}

bool Collector::attach()
{
    const hng::ComponentState state = lifecycle_.load(std::memory_order_acquire);
    if (state != hng::ComponentState::CONSTRUCTED) {
        HNG_LOG_WARN("collector attach ignored: state is {}", state_name(state));
        return false;
    }
    std::size_t attached = 0;
    for (std::size_t i = 0; i < lines_.size(); ++i) {
        HNG_LOG_DEBUG("collector attaching line {}", i);
        if (!lines_[i]->attach()) {
            HNG_LOG_ERROR(
                "collector attach failed at line {}; detaching {} lines", i,
                attached);
            for (auto& line : lines_) {
                line->detach();
            }
            return false;
        }
        ++attached;
        HNG_LOG_DEBUG("collector line {} attached", i);
    }
    hng::ComponentState expected = hng::ComponentState::CONSTRUCTED;
    if (!lifecycle_.compare_exchange_strong(expected,
                                            hng::ComponentState::READY)) {
        HNG_LOG_WARN(
            "collector attach aborted: state changed to {}; detaching {} lines",
            state_name(expected), attached);
        for (auto& line : lines_) {
            line->detach();
        }
        return false;
    }
    HNG_LOG_INFO("collector ready: {} event line(s) attached", attached);
    return true;
}

bool Collector::init()
{
    HNG_LOG_DEBUG("collector init requested");
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

std::vector<hng::CollectorLineStats> Collector::stats() const
{
    std::vector<hng::CollectorLineStats> snapshot;
    snapshot.reserve(lines_.size());
    for (const auto& line : lines_) {
        hng::CollectorLineStats stats = line->stats();
        stats.reserve_failures =
            hng::detail::ReadPercpuCounter(line->reserve_failures_fd());
        snapshot.push_back(std::move(stats));
    }
    return snapshot;
}

void Collector::run()
{
    hng::ComponentState expected = hng::ComponentState::READY;
    if (!lifecycle_.compare_exchange_strong(expected,
                                            hng::ComponentState::RUNNING)) {
        HNG_LOG_WARN("collector run ignored: state is {}", state_name(expected));
        return;
    }

    HNG_LOG_INFO("collector running: {} event line(s)", lines_.size());

    const int epoll_fd = ::epoll_create1(EPOLL_CLOEXEC);
    if (epoll_fd < 0) {
        const int error = errno;
        HNG_LOG_ERROR(
            "collector epoll_create1 failed: {}; detaching and stopping",
            std::strerror(error));
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
        if (!stop_fd_added) {
            const int error = errno;
            HNG_LOG_WARN(
                "collector stop eventfd epoll add failed: {}; using {} ms "
                "polling",
                std::strerror(error), kFallbackTimeoutMs);
        }
    }
    else {
        HNG_LOG_DEBUG("collector stop eventfd unavailable; using {} ms polling",
                      kFallbackTimeoutMs);
    }

    // fd → 采集线；epoll_ctl 失败或没有 epoll fd 的线退回超时轮询。
    std::unordered_map<int, CollectorType*> by_fd;
    std::vector<CollectorType*> polled_lines;
    for (std::size_t i = 0; i < lines_.size(); ++i) {
        const int fd = lines_[i]->epoll_fd();
        if (fd < 0) {
            HNG_LOG_WARN("collector line {} has no epoll fd; using {} ms polling",
                         i, kFallbackTimeoutMs);
            lines_[i]->mark_polling();
            polled_lines.push_back(lines_[i].get());
            continue;
        }
        epoll_event event{};
        event.events  = EPOLLIN;
        event.data.fd = fd;
        if (::epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event) == 0) {
            by_fd.emplace(fd, lines_[i].get());
            HNG_LOG_DEBUG("collector line {} epoll fd {}", i, fd);
        }
        else {
            const int error = errno;
            HNG_LOG_WARN(
                "collector line {} epoll add failed: {}; using {} ms polling", i,
                std::strerror(error), kFallbackTimeoutMs);
            lines_[i]->mark_polling();
            polled_lines.push_back(lines_[i].get());
        }
    }

    const int max_events = static_cast<int>(by_fd.size()) + 1;
    std::vector<epoll_event> events(static_cast<std::size_t>(max_events));
    const int timeout =
        (stop_fd_added && polled_lines.empty()) ? -1 : kFallbackTimeoutMs;
    HNG_LOG_DEBUG(
        "collector wait: {} epoll lines, {} polled lines, timeout {} ms",
        by_fd.size(), polled_lines.size(), timeout);

    while (!stopped_.load(std::memory_order_acquire)) {
        const int ready =
            ::epoll_wait(epoll_fd, events.data(), max_events, timeout);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            const int error = errno;
            HNG_LOG_ERROR("collector epoll_wait failed: {}; stopping",
                          std::strerror(error));
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
                HNG_LOG_DEBUG("collector stop event received");
                stopped_.store(true, std::memory_order_release);
                break;
            }
            auto line = by_fd.find(fd);
            if (line == by_fd.end()) {
                continue;
            }
            const std::uint32_t event_mask = events[i].events;
            if ((event_mask & (EPOLLERR | EPOLLHUP)) != 0) {
                HNG_LOG_WARN(
                    "collector line epoll error (events 0x{:x}); detaching",
                    event_mask);
                line->second->detach();
                ::epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, nullptr);
                by_fd.erase(line);
                continue;
            }
            const int consumed = line->second->consume(kBudgetPerLine);
            if (consumed < 0) {
                HNG_LOG_ERROR("collector line consume failed: {}; detaching",
                              std::strerror(-consumed));
                line->second->detach();
                ::epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, nullptr);
                by_fd.erase(line);
            }
        }
    }

    ::close(epoll_fd);

    // 先摘探针，避免排空期间再产生新事件；随后逐线排空 ringbuf。
    std::size_t drained = 0;
    for (std::size_t i = 0; i < lines_.size(); ++i) {
        lines_[i]->detach();
        HNG_LOG_DEBUG("collector line {} detached", i);
    }
    for (std::size_t i = 0; i < lines_.size(); ++i) {
        int consumed = 0;
        while ((consumed = lines_[i]->consume(kBudgetPerLine)) > 0) {
            drained += static_cast<std::size_t>(consumed);
        }
        if (consumed < 0) {
            HNG_LOG_ERROR("collector final drain failed at line {}: {}", i,
                          std::strerror(-consumed));
        }
    }
    HNG_LOG_INFO("collector stopped: drained {} record(s)", drained);

    lifecycle_.store(hng::ComponentState::STOPPED, std::memory_order_release);
}

void Collector::stop()
{
    if (lifecycle_.load(std::memory_order_acquire) ==
        hng::ComponentState::STOPPED) {
        HNG_LOG_DEBUG("collector stop ignored: already stopped");
        return;
    }
    if (stopped_.exchange(true, std::memory_order_acq_rel)) {
        HNG_LOG_DEBUG("collector stop ignored: already requested");
        return;
    }

    const hng::ComponentState before = lifecycle_.load(std::memory_order_acquire);
    HNG_LOG_INFO("collector stop requested: state {}", state_name(before));

    if (stop_event_fd_ >= 0) {
        const std::uint64_t one = 1;
        const ssize_t written   = ::write(stop_event_fd_, &one, sizeof(one));
        if (written < 0) {
            const int error = errno;
            HNG_LOG_ERROR("collector stop eventfd write failed: {}",
                          std::strerror(error));
        }
        else if (written != static_cast<ssize_t>(sizeof(one))) {
            HNG_LOG_WARN("collector stop eventfd wrote {} bytes, expected {}",
                         written, sizeof(one));
        }
    }
    else {
        HNG_LOG_DEBUG("collector stop eventfd unavailable; waiting for timeout");
    }

    hng::ComponentState current = before;
    while (current != hng::ComponentState::RUNNING &&
           !lifecycle_.compare_exchange_weak(current,
                                             hng::ComponentState::STOPPED)) {
    }
    if (current != hng::ComponentState::RUNNING &&
        lifecycle_.load(std::memory_order_acquire) ==
            hng::ComponentState::STOPPED) {
        HNG_LOG_INFO("collector stopped before run: state {}",
                     state_name(before));
    }
}

hng::ComponentState Collector::state() const
{
    return lifecycle_.load(std::memory_order_acquire);
}
