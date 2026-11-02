/**
 * @file test_collector_aggregate.cc
 * @brief 采集聚合的 epoll 唤醒、按线预算、停机与排空，无 libbpf / 无特权。
 */
#include "agent/collector/src/collector.hpp"

#include <sys/eventfd.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace {

int checks = 0;
#define REQUIRE(expression)                                                   \
    do {                                                                      \
        ++checks;                                                             \
        if (!(expression))                                                    \
            throw std::runtime_error(std::string(#expression) + " at line " + \
                                     std::to_string(__LINE__));               \
    } while (false)

template <class Pred>
bool wait_until(Pred done, int timeout_ms = 2000)
{
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        if (done()) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return done();
}

/// 以 eventfd 模拟 ringbuf：produce() 唤醒 epoll，consume() 按预算取事件。
class FakeLine final : public CollectorType {
   public:
    FakeLine() : wake_fd_(::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK)) {}
    ~FakeLine() override
    {
        if (wake_fd_ >= 0) {
            ::close(wake_fd_);
        }
    }

    void produce(int count)
    {
        pending_.fetch_add(count);
        signal();
    }

    bool prepare() override
    {
        if (prepared_) {
            return false;
        }
        prepared_ = true;
        return true;
    }

    bool attach() override
    {
        if (!prepared_ || attached_) {
            return false;
        }
        attached_ = true;
        return true;
    }

    bool init() override { return prepare() && attach(); }

    void detach() override
    {
        attached_ = false;
        detached_ = true;
    }

    int consume(std::size_t budget) override
    {
        ++consume_calls_;
        if (!attached_ && !detached_) {
            return 0;
        }
        std::uint64_t value = 0;
        while (::read(wake_fd_, &value, sizeof(value)) > 0) {
        }
        const int available = pending_.load();
        const int take      = std::min(available, static_cast<int>(budget));
        if (take == 0) {
            return 0;
        }
        pending_.fetch_sub(take);
        consumed_.fetch_add(take);
        if (available > take) {
            signal();
        }
        return take;
    }

    int epoll_fd() const noexcept override { return wake_fd_; }
    int role_filter_map_fd() const noexcept override { return -1; }

    int consumed() const { return consumed_.load(); }
    int consume_calls() const { return consume_calls_.load(); }
    bool detached() const { return detached_; }

   private:
    void signal()
    {
        const std::uint64_t one = 1;
        const ssize_t written   = ::write(wake_fd_, &one, sizeof(one));
        (void)written;
    }

    int wake_fd_;
    std::atomic<int> pending_{0};
    std::atomic<int> consumed_{0};
    std::atomic<int> consume_calls_{0};
    bool prepared_ = false;
    bool attached_ = false;
    bool detached_ = false;
};

void run_epoll_and_stop()
{
    auto first_owner  = std::make_unique<FakeLine>();
    auto second_owner = std::make_unique<FakeLine>();
    FakeLine* first   = first_owner.get();
    FakeLine* second  = second_owner.get();

    std::vector<std::unique_ptr<CollectorType>> lines;
    lines.push_back(std::move(first_owner));
    lines.push_back(std::move(second_owner));
    Collector collector(std::move(lines));

    REQUIRE(collector.state() == hng::ComponentState::CONSTRUCTED);
    REQUIRE(collector.prepare());
    REQUIRE(collector.attach());
    REQUIRE(collector.state() == hng::ComponentState::READY);
    REQUIRE(!collector.attach());
    REQUIRE(collector.role_filter_map_fds().empty());

    std::thread thread([&collector] { collector.run(); });

    first->produce(3);
    REQUIRE(wait_until([first] { return first->consumed() == 3; }));
    second->produce(2);
    REQUIRE(wait_until([second] { return second->consumed() == 2; }));

    // 热点线本次只取预算，另一条线仍能在同一轮/下一轮被服务。
    first->produce(300);
    second->produce(1);
    REQUIRE(wait_until([first] { return first->consumed() == 303; }));
    REQUIRE(wait_until([second] { return second->consumed() == 3; }));

    // 停机前刚提交的事件由 run() 的尾部排空消费。
    first->produce(7);
    second->produce(4);
    collector.stop();
    thread.join();
    REQUIRE(collector.state() == hng::ComponentState::STOPPED);
    REQUIRE(first->detached() && second->detached());
    REQUIRE(first->consumed() == 310);
    REQUIRE(second->consumed() == 7);
}

void stop_before_run()
{
    auto owner     = std::make_unique<FakeLine>();
    FakeLine* line = owner.get();
    std::vector<std::unique_ptr<CollectorType>> lines;
    lines.push_back(std::move(owner));
    Collector collector(std::move(lines));
    REQUIRE(collector.init());
    collector.stop();
    REQUIRE(collector.state() == hng::ComponentState::STOPPED);
    collector.run();  // 已停止：不进入消费
    REQUIRE(line->consume_calls() == 0);
}

}  // namespace

int main()
{
    try {
        run_epoll_and_stop();
        stop_before_run();
        std::printf("PASS: collector aggregate, %d checks\n", checks);
        return 0;
    }
    catch (const std::exception& error) {
        std::fprintf(stderr, "FAIL: %s\n", error.what());
        return 1;
    }
}
