/**
 * @file test_spsc_queue.cc
 * @brief SPSC 无锁队列的单元测试
 * @details
 * 覆盖 hng::SPSC_Queue：
 *  - 基本出入队、判满与 FIFO 顺序；
 *  - 内部游标与外置游标两个重载在空 / 满边界上行为一致；
 *  - 外置游标取空后生产者仍能写满容量（游标写回内部水位）；
 *  - 外置游标随消费者迁移到另一条线程后继续推进，不重不漏；
 *  - 单生产者单消费者并发下「入队数 == 取出数」且顺序不乱（供 TSAN 构建复验）。
 * @author red_shinku
 * @date 2026.10.13
 */

#include "agent/util/include/spsc_queue.hpp"

#include <atomic>
#include <cstddef>
#include <cstdio>
#include <thread>

namespace {

int g_fail = 0;

#define CHECK(cond, msg)                                                         \
    do {                                                                         \
        if (!(cond)) {                                                           \
            ++g_fail;                                                            \
            std::fprintf(stderr, "[FAIL] %s:%d  %s\n", __FILE__, __LINE__, msg); \
        }                                                                        \
    } while (0)

constexpr size_t kCapacity    = 4;
constexpr size_t kBigCapacity = 8;
constexpr int kBigItems       = 50000;

void run_basic_push_pop()
{
    hng::SPSC_Queue<int> queue(kCapacity);
    CHECK(queue.capacity() == kCapacity && queue.empty() && queue.size() == 0,
          "新队列应为空且容量为请求值");

    int item = 0;
    CHECK(!queue.pop(item), "空队列上 pop 应返回 false");

    for (size_t i = 0; i < kCapacity; ++i) {
        CHECK(queue.push(static_cast<int>(i)), "未满时入队应成功");
    }
    CHECK(!queue.push(9), "满队列上入队应返回 false");
    CHECK(queue.size() == kCapacity, "size 应为已入队元素数");

    for (size_t i = 0; i < kCapacity; ++i) {
        CHECK(queue.pop(item) && item == static_cast<int>(i),
              "出队应保持 FIFO 顺序");
    }
    CHECK(!queue.pop(item), "取空后 pop 应返回 false");
    CHECK(queue.empty(), "取空后队列应为空");
}

void run_cursor_matches_internal_cursor()
{
    // 同一串元素分别走两个重载：返回值、元素、空判行为应逐步一致
    hng::SPSC_Queue<int> by_internal(kCapacity);
    hng::SPSC_Queue<int> by_cursor(kCapacity);
    for (size_t i = 0; i < kCapacity - 1; ++i) {
        CHECK(by_internal.push(static_cast<int>(i)) &&
                  by_cursor.push(static_cast<int>(i)),
              "同一串元素应能分别入两个队列");
    }

    size_t cursor = 0;
    for (size_t i = 0; i < kCapacity - 1; ++i) {
        int plain = -1;
        int cased = -1;
        const bool ok_plain = by_internal.pop(plain);
        const bool ok_cased = by_cursor.pop(cased, cursor);
        CHECK(ok_plain == ok_cased && plain == cased && cased == static_cast<int>(i),
              "两个重载应取到相同元素");
        CHECK(cursor == i + 1, "游标应等于已取元素数");
    }

    int plain = -1;
    int cased = -1;
    CHECK(!by_internal.pop(plain) && !by_cursor.pop(cased, cursor),
          "取空后两个重载都应返回 false");
    CHECK(cursor == kCapacity - 1, "取空不得推进游标");
}

void run_cursor_publish_frees_slots()
{
    // 外置游标取空后，生产者应能再次写满整个容量：
    // 游标未写回内部水位时，生产者会永远判满
    hng::SPSC_Queue<int> queue(kCapacity);
    size_t cursor = 0;
    int item      = 0;
    constexpr int kRounds = 3;
    for (int round = 0; round < kRounds; ++round) {
        for (size_t i = 0; i < kCapacity; ++i) {
            CHECK(queue.push(round * static_cast<int>(kCapacity) +
                             static_cast<int>(i)),
                  "取空后应能重新写满容量");
        }
        CHECK(!queue.push(-1), "容量用尽时应判满");

        for (size_t i = 0; i < kCapacity; ++i) {
            CHECK(queue.pop(item, cursor) &&
                      item == round * static_cast<int>(kCapacity) +
                                  static_cast<int>(i),
                  "出队应保持 FIFO 顺序");
        }
        CHECK(!queue.pop(item, cursor), "取空后应返回 false");
    }
    CHECK(cursor == kCapacity * kRounds, "游标应累计到已取元素总数");
}

void run_cursor_survives_thread_migration()
{
    // 消费进度在游标上：消费者换一条线程继续推进时应不重不漏
    hng::SPSC_Queue<int> queue(kBigCapacity);
    constexpr size_t kPushed = 6;
    for (size_t i = 0; i < kPushed; ++i) {
        CHECK(queue.push(static_cast<int>(i)), "入队应成功");
    }

    size_t cursor = 0;
    int item      = 0;
    CHECK(queue.pop(item, cursor) && item == 0, "同线程应先取到首元素");

    // 子线程内不做断言（CHECK 不是线程安全的），结果留到 join 之后比对
    int seen[kBigCapacity] = {0};
    size_t taken           = 0;
    std::thread consumer([&queue, &cursor, &seen, &taken] {
        int out = 0;
        while (taken < kPushed && queue.pop(out, cursor)) {
            seen[taken] = out;
            ++taken;
        }
    });
    consumer.join();

    CHECK(taken == kPushed - 1, "迁移线程应取到剩余的全部元素");
    bool ordered = true;
    for (size_t i = 0; i < taken; ++i) {
        ordered = ordered && seen[i] == static_cast<int>(i + 1);
    }
    CHECK(ordered, "迁移线程应按原顺序取到剩余元素");
    CHECK(cursor == kPushed, "游标应累计到全部已取元素数");

    // 取空后生产者应能重新写满
    for (size_t i = 0; i < kBigCapacity; ++i) {
        CHECK(queue.push(static_cast<int>(i)), "取空后应能重新写满容量");
    }
    CHECK(!queue.push(0), "容量用尽时应判满");
}

void run_concurrent_push_pop()
{
    // 生产者按序入队且从不丢（满则重试），消费者用外置游标按序取出
    hng::SPSC_Queue<int> queue(kBigCapacity);
    std::atomic<int> pushed{0};

    int last              = -1;
    bool ordered          = true;
    size_t consumed       = 0;
    size_t cursor         = 0;

    std::thread consumer([&queue, &cursor, &last, &ordered, &consumed] {
        int out = 0;
        while (consumed < static_cast<size_t>(kBigItems)) {
            if (!queue.pop(out, cursor)) {
                std::this_thread::yield();
                continue;
            }
            ordered = ordered && out == last + 1;
            last    = out;
            ++consumed;
        }
    });

    std::thread producer([&queue, &pushed] {
        for (int i = 0; i < kBigItems; ++i) {
            while (!queue.push(i)) {
                std::this_thread::yield();
            }
            pushed.fetch_add(1, std::memory_order_relaxed);
        }
    });

    producer.join();
    consumer.join();

    CHECK(pushed.load() == kBigItems, "生产者应把全部元素入队");
    CHECK(consumed == static_cast<size_t>(kBigItems), "取出的元素数应等于入队数");
    CHECK(ordered, "取出顺序应与入队顺序一致");
    CHECK(cursor == static_cast<size_t>(kBigItems) && queue.empty(),
          "游标与队列应同步推进到取空");
}

}  // namespace

int main()
{
    run_basic_push_pop();
    run_cursor_matches_internal_cursor();
    run_cursor_publish_frees_slots();
    run_cursor_survives_thread_migration();
    run_concurrent_push_pop();

    if (g_fail) {
        std::fprintf(stderr, "TOTAL FAILURES: %d\n", g_fail);
        return 1;
    }
    std::printf("ALL PASS\n");
    return 0;
}
