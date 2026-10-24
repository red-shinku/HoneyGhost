/**
 * @file test_tombstone_table.cc
 * @brief 墓碑表的单元测试
 * @details
 * 覆盖 hng::TombstoneTable：
 *  - add 首次为准、同身份重复不覆盖；
 *  - find 命中 / 未命中；
 *  - 超过 ttl 后 find 返回空、就地清除并可重新 add；
 *  - 容量满时按入表顺序淘汰最旧条目；
 *  - expire 的清除数量与顺序；
 *  - ttl 为 0 与容量为 0。
 * @author red_shinku
 * @date 2026.10.23
 */

#include "agent/util/include/tombstone_table.hpp"

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <optional>

namespace {

int g_fail = 0;

#define CHECK(cond, msg)                                                         \
    do {                                                                         \
        if (!(cond)) {                                                           \
            ++g_fail;                                                            \
            std::fprintf(stderr, "[FAIL] %s:%d  %s\n", __FILE__, __LINE__, msg); \
        }                                                                        \
    } while (0)

struct Info {
    std::uint32_t context_id = 0;
};

using Table = hng::TombstoneTable<std::uint64_t, Info>;

hng::RelationTimePoint at_ms(std::int64_t ms)
{
    return hng::RelationTimePoint{} + std::chrono::milliseconds(ms);
}

void run_first_record_wins()
{
    Table table;
    CHECK(table.size() == 0, "新表应为空");

    CHECK(table.add(1, Info{100}, at_ms(0)), "首次记录应返回 true");
    CHECK(!table.add(1, Info{200}, at_ms(1)),
          "同身份未过期时重复记录应返回 false");
    CHECK(table.size() == 1, "重复记录不得增加条目");

    const std::optional<Info> found = table.find(1, at_ms(2));
    CHECK(found.has_value() && found->context_id == 100,
          "重复记录不得覆盖首条的 Info");

    CHECK(!table.find(2, at_ms(2)).has_value(), "未记录的身份应返回空");
}

void run_expire_on_find()
{
    hng::TombstoneOptions options;
    options.ttl = std::chrono::milliseconds(1000);
    Table table(options);

    CHECK(table.add(1, Info{10}, at_ms(0)), "首次记录应返回 true");
    CHECK(table.find(1, at_ms(1000)).has_value(), "恰好等于 ttl 不应过期");

    CHECK(!table.find(1, at_ms(1001)).has_value(),
          "超过 ttl 的墓碑应视为不存在");
    CHECK(table.size() == 0, "find 应就地清除过期条目");

    CHECK(table.add(1, Info{20}, at_ms(1001)), "过期后同身份可重新记录");
    const std::optional<Info> found = table.find(1, at_ms(1002));
    CHECK(found.has_value() && found->context_id == 20,
          "重新记录后应返回新的 Info");
}

void run_capacity_eviction()
{
    hng::TombstoneOptions options;
    options.capacity = 2;
    options.ttl      = std::chrono::milliseconds(0);
    Table table(options);

    CHECK(table.add(1, Info{10}, at_ms(0)), "首次记录应返回 true");
    CHECK(table.add(2, Info{20}, at_ms(1)), "首次记录应返回 true");
    CHECK(table.add(3, Info{30}, at_ms(2)),
          "容量满时应淘汰最旧条目并记录新身份");
    CHECK(table.size() == 2, "淘汰后条目数应等于容量");

    CHECK(!table.find(1, at_ms(3)).has_value(), "最旧条目应被淘汰");
    const std::optional<Info> second = table.find(2, at_ms(3));
    const std::optional<Info> third  = table.find(3, at_ms(3));
    CHECK(second.has_value() && second->context_id == 20, "较新条目应保留");
    CHECK(third.has_value() && third->context_id == 30, "新条目应保留");

    CHECK(!table.add(2, Info{99}, at_ms(4)),
          "已存在但不在淘汰端时应返回 false");
    const std::optional<Info> unchanged = table.find(2, at_ms(4));
    CHECK(unchanged.has_value() && unchanged->context_id == 20,
          "已存在的条目不得被覆盖");
    CHECK(table.size() == 2, "被拒的记录不得改变条目数");
}

void run_expire_count()
{
    hng::TombstoneOptions options;
    options.capacity = 8;
    options.ttl      = std::chrono::milliseconds(1000);
    Table table(options);

    CHECK(table.add(1, Info{10}, at_ms(0)), "首次记录应返回 true");
    CHECK(table.add(2, Info{20}, at_ms(500)), "首次记录应返回 true");
    CHECK(table.add(3, Info{30}, at_ms(900)), "首次记录应返回 true");

    CHECK(table.expire(at_ms(1300)) == 1, "应只清除最旧的过期条目");
    CHECK(table.size() == 2, "未过期条目应保留");
    CHECK(!table.find(1, at_ms(1301)).has_value(), "已清除的条目应查不到");
    CHECK(table.find(2, at_ms(1301)).has_value(), "未过期条目应仍可查到");
    CHECK(table.find(3, at_ms(1301)).has_value(), "未过期条目应仍可查到");

    CHECK(table.expire(at_ms(1600)) == 1, "应清除下一个过期条目");
    CHECK(table.expire(at_ms(2000)) == 1, "应清除最后一个过期条目");
    CHECK(table.expire(at_ms(2001)) == 0, "无过期条目时应返回 0");
    CHECK(table.size() == 0, "全部过期后表应为空");
}

void run_ttl_disabled()
{
    hng::TombstoneOptions options;
    options.ttl = std::chrono::milliseconds(0);
    Table table(options);

    CHECK(table.add(1, Info{10}, at_ms(0)), "首次记录应返回 true");
    const std::optional<Info> found = table.find(1, at_ms(1'000'000));
    CHECK(found.has_value() && found->context_id == 10,
          "ttl 为 0 时不应按时间过期");
    CHECK(table.expire(at_ms(1'000'000)) == 0, "ttl 为 0 时 expire 应返回 0");
    CHECK(table.size() == 1, "ttl 为 0 时条目应保留");
}

void run_zero_capacity()
{
    hng::TombstoneOptions options;
    options.capacity = 0;
    Table table(options);

    CHECK(!table.add(1, Info{10}, at_ms(0)), "容量为 0 时不应记录");
    CHECK(table.size() == 0, "容量为 0 时表应保持为空");
    CHECK(!table.find(1, at_ms(1)).has_value(), "容量为 0 时不应查到内容");
}

}  // namespace

int main()
{
    run_first_record_wins();
    run_expire_on_find();
    run_capacity_eviction();
    run_expire_count();
    run_ttl_disabled();
    run_zero_capacity();

    if (g_fail) {
        std::fprintf(stderr, "TOTAL FAILURES: %d\n", g_fail);
        return 1;
    }
    std::printf("ALL PASS\n");
    return 0;
}
