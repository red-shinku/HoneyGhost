/**
 * @file test_deferred_relation_table.cc
 * @brief 延迟关系表的单元测试
 * @details
 * 覆盖 hng::DeferredRelationTable：
 *  - defer / take 与字段保持；
 *  - 同一等待方重复暂存保留首条；
 *  - 同一锚点多条按入表顺序取出；
 *  - cancel 与索引清理；
 *  - 容量上限与容量为 0；
 *  - ttl 过期（显式时间点）与 ttl 为 0；
 *  - take / cancel / expire 后同一等待方可再次暂存。
 * @author red_shinku
 * @date 2026.10.23
 */

#include "agent/util/include/deferred_relation_table.hpp"

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <utility>
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

using Table = hng::DeferredRelationTable<std::uint64_t, std::uint64_t,
                                         std::uint32_t>;
using Result = Table::Result;

hng::RelationTimePoint at_ms(std::int64_t ms)
{
    return hng::RelationTimePoint{} + std::chrono::milliseconds(ms);
}

void run_defer_and_take()
{
    Table table;
    CHECK(table.empty() && table.size() == 0, "新表应为空");

    CHECK(table.take(2).empty(), "无条目的锚点应返回空");

    CHECK(table.defer(1, 10, 100, at_ms(0)) == Result::DEFERRED,
          "首次暂存应返回 DEFERRED");
    CHECK(!table.empty() && table.size() == 1, "size 应为关系条数");

    std::vector<Table::Entry> taken = table.take(1);
    CHECK(taken.size() == 1, "take 应返回该锚点的全部条目");
    if (taken.size() == 1) {
        CHECK(taken[0].anchor == 1 && taken[0].waiter == 10 &&
                  taken[0].action == 100,
              "取出的条目应保持字段");
    }
    CHECK(table.empty() && table.size() == 0, "take 后条目应被删除");
    CHECK(table.take(1).empty(), "重复 take 应返回空");
}

void run_duplicate_waiter()
{
    Table table;
    CHECK(table.defer(1, 9, 100, at_ms(0)) == Result::DEFERRED,
          "首次暂存应返回 DEFERRED");
    CHECK(table.defer(2, 9, 200, at_ms(1)) == Result::DUPLICATE,
          "同一等待方换锚点暂存应返回 DUPLICATE");
    CHECK(table.size() == 1, "重复暂存不得增加条目");

    const std::vector<Table::Entry> first = table.take(1);
    CHECK(first.size() == 1 && first[0].anchor == 1 && first[0].action == 100,
          "应保留首条及其锚点");
    CHECK(table.take(2).empty(), "被拒的锚点不应有条目");
}

void run_same_anchor_order()
{
    Table table;
    CHECK(table.defer(7, 1, 11, at_ms(0)) == Result::DEFERRED, "暂存应成功");
    CHECK(table.defer(7, 2, 22, at_ms(1)) == Result::DEFERRED, "暂存应成功");
    CHECK(table.defer(8, 3, 33, at_ms(2)) == Result::DEFERRED, "暂存应成功");
    CHECK(table.size() == 3, "size 应为关系条数");

    const std::vector<Table::Entry> taken = table.take(7);
    CHECK(taken.size() == 2, "take 应取出该锚点的全部条目");
    if (taken.size() == 2) {
        CHECK(taken[0].waiter == 1 && taken[1].waiter == 2,
              "take 应按入表顺序返回");
    }
    CHECK(table.size() == 1, "take 不得删除其他锚点的条目");
    CHECK(table.take(8).size() == 1, "其他锚点的条目应仍可取出");
}

void run_cancel()
{
    Table table;
    CHECK(table.defer(1, 10, 100, at_ms(0)) == Result::DEFERRED, "暂存应成功");
    CHECK(table.defer(1, 11, 110, at_ms(1)) == Result::DEFERRED, "暂存应成功");
    CHECK(table.defer(2, 12, 120, at_ms(2)) == Result::DEFERRED, "暂存应成功");

    const std::optional<Table::Entry> cancelled = table.cancel(10);
    CHECK(cancelled.has_value() && cancelled->anchor == 1 &&
              cancelled->waiter == 10 && cancelled->action == 100,
          "cancel 应返回被删除的条目");
    CHECK(table.size() == 2, "cancel 只删除一条");
    CHECK(!table.cancel(10).has_value(), "再次取消应返回空");
    CHECK(!table.cancel(99).has_value(), "未知等待方取消应返回空");

    const std::vector<Table::Entry> taken = table.take(1);
    CHECK(taken.size() == 1 && taken[0].waiter == 11,
          "cancel 不应影响同锚点的其他条目");
    CHECK(table.take(2).size() == 1, "cancel 不应影响其他锚点的条目");

    CHECK(table.defer(3, 10, 130, at_ms(3)) == Result::DEFERRED,
          "cancel 后同一等待方可再次暂存");
}

void run_capacity()
{
    hng::DeferredRelationOptions options;
    options.capacity = 2;
    Table table(options);

    CHECK(table.defer(1, 1, 11, at_ms(0)) == Result::DEFERRED, "暂存应成功");
    CHECK(table.defer(2, 2, 22, at_ms(1)) == Result::DEFERRED, "暂存应成功");
    CHECK(table.defer(3, 3, 33, at_ms(2)) == Result::FULL,
          "达到容量上限应返回 FULL");
    CHECK(table.size() == 2, "FULL 不得插入条目");
    CHECK(table.take(3).empty(), "FULL 的锚点不应有条目");

    const std::vector<Table::Entry> first = table.take(1);
    CHECK(first.size() == 1 && first[0].waiter == 1, "已入表条目应保留");

    options.capacity = 0;
    Table empty_table(options);
    CHECK(empty_table.defer(1, 1, 11, at_ms(0)) == Result::FULL,
          "容量为 0 时任何暂存都应返回 FULL");
    CHECK(empty_table.empty(), "容量为 0 时表应保持为空");
}

void run_ttl_expire()
{
    hng::DeferredRelationOptions options;
    options.ttl = std::chrono::milliseconds(1000);
    Table table(options);

    CHECK(table.defer(1, 10, 100, at_ms(0)) == Result::DEFERRED, "暂存应成功");
    CHECK(table.defer(1, 11, 110, at_ms(500)) == Result::DEFERRED,
          "暂存应成功");
    CHECK(table.defer(2, 12, 120, at_ms(900)) == Result::DEFERRED,
          "暂存应成功");

    CHECK(table.expire(at_ms(1000)).empty(), "恰好等于 ttl 不应过期");
    CHECK(table.size() == 3, "未过期时条目应保留");

    std::vector<Table::Entry> expired = table.expire(at_ms(1001));
    CHECK(expired.size() == 1 && expired[0].waiter == 10 &&
              expired[0].anchor == 1,
          "应从最旧条目开始清理超过 ttl 的条目");
    CHECK(table.size() == 2, "过期条目应被删除");

    CHECK(table.defer(1, 10, 130, at_ms(1001)) == Result::DEFERRED,
          "过期清理后同一等待方可再次暂存");

    expired = table.expire(at_ms(1600));
    CHECK(expired.size() == 1 && expired[0].waiter == 11,
          "只应清理已超过 ttl 的条目");

    expired = table.expire(at_ms(2002));
    CHECK(expired.size() == 2, "应按入表顺序清理全部过期条目");
    if (expired.size() == 2) {
        CHECK(expired[0].waiter == 12 && expired[1].waiter == 10,
              "expire 应按入表顺序返回");
    }
    CHECK(table.empty(), "全部过期后表应为空");
    CHECK(table.take(2).empty(), "过期清理应清理锚点索引");
}

void run_ttl_disabled()
{
    hng::DeferredRelationOptions options;
    options.ttl = std::chrono::milliseconds(0);
    Table table(options);

    CHECK(table.defer(1, 10, 100, at_ms(0)) == Result::DEFERRED, "暂存应成功");
    CHECK(table.expire(at_ms(1'000'000)).empty(), "ttl 为 0 时不应过期");
    CHECK(table.size() == 1, "ttl 为 0 时条目应保留");
    CHECK(table.take(1).size() == 1, "ttl 为 0 时条目应仍可取出");
}

void run_redefer_after_take()
{
    Table table;
    CHECK(table.defer(1, 10, 100, at_ms(0)) == Result::DEFERRED, "暂存应成功");
    CHECK(table.take(1).size() == 1, "take 应取出条目");
    CHECK(table.defer(1, 10, 200, at_ms(1)) == Result::DEFERRED,
          "take 后同一等待方可再次暂存");

    const std::vector<Table::Entry> taken = table.take(1);
    CHECK(taken.size() == 1 && taken[0].action == 200, "应取到新动作");
}

}  // namespace

int main()
{
    run_defer_and_take();
    run_duplicate_waiter();
    run_same_anchor_order();
    run_cancel();
    run_capacity();
    run_ttl_expire();
    run_ttl_disabled();
    run_redefer_after_take();

    if (g_fail) {
        std::fprintf(stderr, "TOTAL FAILURES: %d\n", g_fail);
        return 1;
    }
    std::printf("ALL PASS\n");
    return 0;
}
