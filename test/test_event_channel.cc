/**
 * @file test_event_channel.cc
 * @brief EventChannel / EventLoop 的入队、唤醒交接、丢弃计数与关闭语义
 * @details 数据面跨线程通信原语：合并唤醒、取空交还通知权、关闭后拒绝写入。
 *          无 IO / 无特权。
 */

#include "agent/util/include/event_channel.hpp"
#include "agent/util/include/event_loop.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
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

/// 单线程语义：次序、容量、满丢弃计数、取空交还通知权
void single_thread_semantics()
{
    hng::EventChannel<int> channel(4);
    hng::EventChannelWriter<int>& writer = channel.writer();
    hng::EventChannelReader<int>& reader = channel.reader();

    REQUIRE(channel.empty());
    int value = 0;
    REQUIRE(!reader.try_pop(value));
    REQUIRE(!reader.try_pop(value));

    for (int i = 0; i < 4; ++i) {
        REQUIRE(writer.push(i));
    }
    REQUIRE(!writer.push(4));
    REQUIRE(writer.dropped() == 1);
    REQUIRE(writer.rejected() == 0);
    REQUIRE(channel.size() == 4);

    for (int i = 0; i < 4; ++i) {
        REQUIRE(reader.try_pop(value));
        REQUIRE(value == i);
    }
    REQUIRE(!reader.try_pop(value));
    REQUIRE(writer.dropped() == 1);
}

/// 关闭：拒绝写入并计数，已入队元素仍可读出，读端可见 closed()
void close_rejects_writes()
{
    hng::EventChannel<int> channel(4);
    hng::EventChannelWriter<int>& writer = channel.writer();
    hng::EventChannelReader<int>& reader = channel.reader();

    REQUIRE(writer.push(7));
    REQUIRE(!reader.closed());
    writer.close();
    REQUIRE(reader.closed());
    REQUIRE(!writer.push(8));
    REQUIRE(writer.rejected() == 1);
    REQUIRE(reader.rejected() == 1);

    int value = 0;
    REQUIRE(reader.try_pop(value));
    REQUIRE(value == 7);
    REQUIRE(!reader.try_pop(value));
}

/// 跨线程唤醒：合并唤醒与不丢唤醒，且唤醒次数远少于事件数
void wake_is_merged_and_lossless()
{
    constexpr int kEvents = 20000;
    hng::EventChannel<int> channel(64);

    std::atomic<std::size_t> received{0};
    std::atomic<std::size_t> wakeups{0};

    std::thread consumer([&channel, &received, &wakeups] {
        hng::EventLoop loop;
        loop.add(channel.reader().fd(), 1);
        hng::EventLoop::Ready ready[hng::EventLoop::capacity()];

        for (;;) {
            int value         = 0;
            std::size_t batch = 0;
            while (batch < 64 && channel.reader().try_pop(value)) {
                ++batch;
            }
            received.fetch_add(batch);
            if (batch != 0) {
                continue;
            }
            // 关闭且取空是本轮结束的唯一判据
            if (channel.reader().closed()) {
                return;
            }
            if (loop.wait(ready, hng::EventLoop::capacity()) != 0) {
                wakeups.fetch_add(1);
            }
        }
    });

    for (int i = 0; i < kEvents; ++i) {
        while (!channel.writer().push(i)) {
            std::this_thread::yield();  // 满：等读端让出槽位
        }
    }
    channel.writer().close();

    consumer.join();

    REQUIRE(received.load() == static_cast<std::size_t>(kEvents));
    // 生产方在满时重试，故元素全部入队；被拒次数随背压发生
    REQUIRE(channel.writer().rejected() == 0);
    // 合并唤醒：一次唤醒覆盖一批事件，唤醒次数远少于事件数。并发起止不定，
    // 读端可能全程未进入等待，故不要求唤醒次数为正；空闲→忙的一次唤醒由
    // blocked_reader_wakes_once 断言。
    REQUIRE(wakeups.load() * 4 < static_cast<std::size_t>(kEvents));
}

/// 事件循环：多个源按 tag 报告就绪，停机 fd 可唤醒等待方
void event_loop_reports_tags()
{
    hng::EventChannel<int> first(4);
    hng::EventChannel<int> second(4);

    hng::EventLoop loop;
    loop.add(first.reader().fd(), 11);
    loop.add(second.reader().fd(), 22);

    hng::EventLoop::Ready ready[hng::EventLoop::capacity()];
    REQUIRE(loop.wait(ready, hng::EventLoop::capacity(), 0) == 0);

    REQUIRE(second.writer().push(1));
    REQUIRE(loop.wait(ready, hng::EventLoop::capacity(), 1000) == 1);
    REQUIRE(ready[0].tag == 22);

    int value = 0;
    REQUIRE(second.reader().try_pop(value));
    // 取空才消耗唤醒，故读端必须在取空之后才回到等待
    REQUIRE(!second.reader().try_pop(value));

    REQUIRE(first.writer().push(2));
    REQUIRE(loop.wait(ready, hng::EventLoop::capacity(), 1000) == 1);
    REQUIRE(ready[0].tag == 11);
    REQUIRE(first.reader().try_pop(value));
    REQUIRE(!first.reader().try_pop(value));

    loop.request_stop();
    REQUIRE(loop.wait(ready, hng::EventLoop::capacity(), 1000) == 1);
    REQUIRE(ready[0].tag == hng::EventLoop::kStopTag);
}

/// 空闲：阻塞的读端由入队唤醒，取空后再次阻塞（不空转）
void blocked_reader_wakes_once()
{
    hng::EventChannel<int> channel(4);

    std::atomic<std::size_t> wakeups{0};
    std::atomic<int> last{0};
    std::atomic<bool> done{false};

    std::thread consumer([&] {
        hng::EventLoop loop;
        loop.add(channel.reader().fd(), 1);
        hng::EventLoop::Ready ready[hng::EventLoop::capacity()];
        while (!done.load()) {
            int value = 0;
            if (channel.reader().try_pop(value)) {
                last.store(value);
            }
            else {
                const std::size_t count =
                    loop.wait(ready, hng::EventLoop::capacity(), 100);
                if (count != 0) {
                    wakeups.fetch_add(1);
                }
            }
        }
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    REQUIRE(wakeups.load() == 0);  // 无入队时不得被反复唤醒

    REQUIRE(channel.writer().push(42));
    REQUIRE(wait_until([&last] { return last.load() == 42; }));
    REQUIRE(wakeups.load() == 1);

    done.store(true);
    consumer.join();
}

}  // namespace

int main()
{
    try {
        single_thread_semantics();
        close_rejects_writes();
        wake_is_merged_and_lossless();
        event_loop_reports_tags();
        blocked_reader_wakes_once();
        std::printf("PASS: event channel, %d checks\n", checks);
        return 0;
    }
    catch (const std::exception& error) {
        std::fprintf(stderr, "FAIL: %s\n", error.what());
        return 1;
    }
}
