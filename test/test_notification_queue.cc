/**
 * @file test_notification_queue.cc
 * @brief 通知队列的单元测试
 * @details
 * 覆盖 hng::NotificationQueue：
 *  - 单生产者下的出入队顺序与非阻塞取；
 *  - 空队列上 wait_pop 阻塞，push 后被唤醒；
 *  - 多生产者并发入队不丢元素；
 *  - 停止语义：幂等、停后排空、停后 push 被拒；
 *  - run 之前 stop 时 wait_pop 立即返回；
 *  - 并发 push / pop / stop 后「入队成功数 == 取出数」（供 TSAN 构建复验）。
 * @author red_shinku
 * @date 2026.9.17
 */

#include "agent/util/include/notification_queue.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <future>
#include <thread>
#include <vector>

namespace {

int g_fail = 0;

#define CHECK(cond, msg)                                                         \
    do {                                                                         \
        if (!(cond)) {                                                           \
            ++g_fail;                                                            \
            std::fprintf(stderr, "[FAIL] %s:%d  %s\n", __FILE__, __LINE__, msg); \
        }                                                                        \
    } while (0)

void run_fifo_and_try_pop()
{
    hng::NotificationQueue<int> queue;
    CHECK(queue.empty() && queue.size() == 0 && !queue.stopped(),
          "新队列应为空且未停止");

    int item = 0;
    CHECK(!queue.try_pop(item), "空队列上 try_pop 应返回 false");

    for (int i = 1; i <= 3; ++i) {
        CHECK(queue.push(i), "未停止时入队应成功");
    }
    CHECK(queue.size() == 3, "size 应为已入队元素数");
    CHECK(queue.try_pop(item) && item == 1, "应先出队最早入队的元素");
    CHECK(queue.try_pop(item) && item == 2, "出队应保持顺序");
    CHECK(queue.try_pop(item) && item == 3, "出队应保持顺序");
    CHECK(!queue.try_pop(item), "取空后 try_pop 应返回 false");
}

void run_wait_pop_blocks()
{
    hng::NotificationQueue<int> queue;
    std::atomic<int> got{-1};

    std::thread consumer([&queue, &got] {
        int item = 0;
        if (queue.wait_pop(item)) {
            got.store(item);
        }
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    CHECK(got.load() == -1, "空队列上 wait_pop 应阻塞");
    CHECK(queue.push(7), "入队应成功");
    consumer.join();
    CHECK(got.load() == 7, "push 后 wait_pop 应取到该元素");
}

void run_many_producers()
{
    hng::NotificationQueue<int> queue;
    constexpr int kProducers = 4;
    constexpr int kEach      = 250;

    // 子线程内只累加原子，断言留到 join 之后（CHECK 不是线程安全的）
    std::atomic<int> rejected{0};
    std::vector<std::thread> producers;
    for (int t = 0; t < kProducers; ++t) {
        producers.emplace_back([&queue, &rejected, t] {
            for (int i = 0; i < kEach; ++i) {
                if (!queue.push(t * kEach + i)) {
                    rejected.fetch_add(1, std::memory_order_relaxed);
                }
            }
        });
    }
    for (std::thread& producer : producers) {
        producer.join();
    }

    CHECK(rejected.load() == 0, "未停止时入队不应被拒");
    CHECK(queue.size() == static_cast<std::size_t>(kProducers * kEach),
          "多生产者入队不应丢元素");

    std::vector<int> seen(static_cast<std::size_t>(kProducers * kEach), 0);
    int item          = 0;
    std::size_t count = 0;
    while (queue.try_pop(item)) {
        ++count;
        if (item >= 0 && item < static_cast<int>(seen.size())) {
            seen[static_cast<std::size_t>(item)] += 1;
        }
    }
    CHECK(count == static_cast<std::size_t>(kProducers * kEach),
          "应取出全部入队元素");
    bool each_once = true;
    for (int hit : seen) {
        each_once = each_once && hit == 1;
    }
    CHECK(each_once, "每个元素应恰好出现一次");
}

void run_stop_semantics()
{
    // 停后排空：已入队的元素仍能取出，取空才返回 false
    hng::NotificationQueue<int> queue;
    CHECK(queue.push(1) && queue.push(2), "未停止时入队应成功");
    queue.stop();
    queue.stop();  // 幂等
    CHECK(queue.stopped(), "stop 后应处于停止态");

    int item = 0;
    CHECK(queue.wait_pop(item) && item == 1, "stop 后应仍交出已入队的元素");
    CHECK(queue.wait_pop(item) && item == 2, "stop 后应仍交出已入队的元素");
    CHECK(!queue.wait_pop(item), "取空后 wait_pop 应返回 false");

    // 停后 push 被拒且不入队
    const std::size_t size_before = queue.size();
    CHECK(!queue.push(3), "stop 后入队应返回 false");
    CHECK(queue.size() == size_before, "被拒的入队不得进入队列");

    // run 之前 stop：wait_pop 立即返回
    hng::NotificationQueue<int> stopped_queue;
    stopped_queue.stop();
    std::packaged_task<bool()> task([&stopped_queue] {
        int out = 0;
        return stopped_queue.wait_pop(out);
    });
    std::future<bool> done = task.get_future();
    std::thread worker(std::move(task));
    const bool returned =
        done.wait_for(std::chrono::seconds(5)) == std::future_status::ready;
    CHECK(returned, "stop 之后 wait_pop 应立即返回");
    if (returned) {
        CHECK(!done.get(), "stop 之后的 wait_pop 应返回 false");
        worker.join();
    }
    else {
        worker.detach();  // 卡住的线程不能 join，交由进程退出兜底
    }
}

void run_concurrent_push_pop_stop()
{
    hng::NotificationQueue<int> queue;
    constexpr int kProducers = 4;

    std::atomic<uint64_t> pushed{0};
    std::atomic<uint64_t> consumed{0};
    std::atomic<bool> keep_pushing{true};

    std::thread consumer([&queue, &consumed] {
        int item = 0;
        while (queue.wait_pop(item)) {
            consumed.fetch_add(1, std::memory_order_relaxed);
        }
    });

    std::vector<std::thread> producers;
    for (int t = 0; t < kProducers; ++t) {
        producers.emplace_back([&queue, &pushed, &keep_pushing, t] {
            while (keep_pushing.load(std::memory_order_relaxed)) {
                if (queue.push(t)) {
                    pushed.fetch_add(1, std::memory_order_relaxed);
                }
            }
        });
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    queue.stop();
    keep_pushing.store(false, std::memory_order_relaxed);
    for (std::thread& producer : producers) {
        producer.join();
    }
    consumer.join();

    CHECK(pushed.load() > 0, "停止前应有元素入队");
    CHECK(consumed.load() == pushed.load(), "排空后取出的元素数应等于入队成功数");
    CHECK(queue.empty(), "停止排空后队列应为空");
}

}  // namespace

int main()
{
    run_fifo_and_try_pop();
    run_wait_pop_blocks();
    run_many_producers();
    run_stop_semantics();
    run_concurrent_push_pop_stop();

    if (g_fail) {
        std::fprintf(stderr, "TOTAL FAILURES: %d\n", g_fail);
        return 1;
    }
    std::printf("ALL PASS\n");
    return 0;
}
