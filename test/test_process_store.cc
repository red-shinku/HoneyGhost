/**
 * @file test_process_store.cc
 * @brief 进程树与墓碑存储层的单元测试
 * @details
 * 单线程直接调用 ProcessStore，不建队列、不起线程：
 *  - 注册：新身份插入、同身份幂等重放、墓碑拒收的迟到 ADD；
 *  - pid 复用：旧身份退役并交还，父计数不虚增；
 *  - 退出：有记录实删、有子进程转虚拟根、无记录与重复退出只写墓碑；
 *  - 虚拟根：子退出递减计数、归零驱逐、驱逐不额外交出身份；
 *  - 镜像：实进程、虚拟根、同 pid 新实例不误写；
 *  - 查询：双表优先级、resolve 取最新虚拟根；
 *  - 分片：同分片与跨分片的父子计数；
 *  - 统计：累计与当前值；
 *  - 墓碑：TTL 懒清除，各写入口的早退路径同样清理。
 * @author red_shinku
 * @date 2026.10.24
 */

#include "agent/control_plane/src/process_store.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <functional>

namespace {

int g_fail = 0;

#define CHECK(cond, msg)                                                         \
    do {                                                                         \
        if (!(cond)) {                                                           \
            ++g_fail;                                                            \
            std::fprintf(stderr, "[FAIL] %s:%d  %s\n", __FILE__, __LINE__, msg); \
        }                                                                        \
    } while (0)

using Kind = ProcessChange::Kind;

hng::Process proc(uint32_t pid, uint64_t start)
{
    return hng::Process{pid, start};
}

hng::ProcessMessage msg(uint32_t pid, uint64_t start, uint32_t ppid,
                        uint64_t ppid_start)
{
    hng::event_head ehead{};
    ehead.pid             = pid;
    ehead.pid_start_time  = start;
    ehead.ppid            = ppid;
    ehead.ppid_start_time = ppid_start;
    return hng::ProcessMessage(ehead);
}

/// 可控时钟：只随测试推进，供墓碑寿命用例
struct FakeClock {
    hng::RelationTimePoint now{};
};

ProcessStoreOptions timed_options(FakeClock& clock)
{
    ProcessStoreOptions options;
    options.tombstones.ttl = std::chrono::milliseconds(100);
    options.now            = [&clock] { return clock.now; };
    return options;
}

constexpr std::size_t kShardCount = 32;

/// 从 from 起找第一个落在指定分片的 pid
uint32_t pid_in_shard(std::size_t shard, uint32_t from)
{
    for (uint32_t pid = from;; ++pid) {
        if (std::hash<uint32_t>{}(pid) % kShardCount == shard) {
            return pid;
        }
    }
}

void run_insert_and_idempotent()
{
    ProcessStore store;

    const ProcessChange first = store.add(msg(100, 1000, 10, 100));
    CHECK(first.kind == Kind::ADDED, "新身份应插入");
    CHECK(first.child == proc(100, 1000), "应带上新进程身份");
    CHECK(first.parent == proc(10, 100), "应带上事件的父进程身份");
    CHECK(!first.exited.has_value(), "插入不应报退出");
    CHECK(store.lookup(proc(100, 1000)).has_value(), "插入后应可查");
    CHECK(!store.lookup(proc(100, 9999)).has_value(),
          "同 pid 不同 start_time 应失配");
    CHECK(!store.lookup(proc(101, 1000)).has_value(), "未注册的 pid 应失配");
    CHECK(store.stats().parent_missing == 1, "父身份缺失应计数");

    const ProcessChange replay = store.add(msg(100, 1000, 10, 100));
    CHECK(replay.kind == Kind::NONE, "同身份重放应为 NONE");
    CHECK(!replay.exited.has_value(), "重放不应报退出");
    CHECK(store.stats().parent_missing == 1, "重放不得更新父计数");

    // 未登记退出写墓碑，随后的 ADD 被拒
    const ProcessChange gone = store.remove(proc(200, 2000));
    CHECK(gone.kind == Kind::REMOVED, "未登记退出仍为 REMOVED");
    CHECK(gone.exited.has_value() && *gone.exited == proc(200, 2000),
          "未登记退出应交出本次身份");
    CHECK(store.is_exited(proc(200, 2000)), "未登记退出应写墓碑");

    const ProcessChange late = store.add(msg(200, 2000, 10, 100));
    CHECK(late.kind == Kind::NONE, "墓碑拒收的 ADD 应为 NONE");
    CHECK(!late.exited.has_value(), "墓碑拒收不应报退出");
    CHECK(!store.lookup(proc(200, 2000)).has_value(), "迟到 ADD 不得插入");
    CHECK(store.stats().stale_add == 1, "迟到 ADD 应计数");
}

void run_pid_reuse()
{
    ProcessStore store;
    store.add(msg(200, 2000, 0, 0));

    const ProcessChange reused = store.add(msg(200, 2001, 0, 0));
    CHECK(reused.kind == Kind::ADDED, "pid 复用应插入新实例");
    CHECK(reused.child == proc(200, 2001), "应带上新实例身份");
    CHECK(reused.exited.has_value() && *reused.exited == proc(200, 2000),
          "应交出被替换的旧实例身份");
    CHECK(!store.lookup(proc(200, 2000)).has_value(), "旧实例应被顶掉");
    CHECK(store.lookup(proc(200, 2001)).has_value(), "新实例应可查");
    CHECK(store.is_exited(proc(200, 2000)), "旧实例应可查到墓碑");
    CHECK(!store.is_exited(proc(200, 2001)), "新实例不得命中旧墓碑");
    CHECK(store.stats().pid_reused == 1, "pid 复用应计数");

    // 旧实例有存活子进程：退役时转入虚拟根
    store.add(msg(300, 3000, 0, 0));
    store.add(msg(301, 3001, 300, 3000));
    const auto old_real = store.lookup(proc(300, 3000));
    CHECK(old_real.has_value() && old_real->child_count == 1,
          "旧实例孩子计数应为 1");

    const ProcessChange over = store.add(msg(300, 3002, 0, 0));
    CHECK(over.exited.has_value() && *over.exited == proc(300, 3000),
          "应交出有子进程的旧实例身份");
    const auto old_virtual = store.lookup(proc(300, 3000));
    CHECK(
        old_virtual.has_value() && old_virtual->kind == hng::ProcessKind::VIRTUAL,
        "有子进程的旧实例应转入虚拟根");
    CHECK(store.lookup(proc(300, 3002)).has_value(), "新实例应可查");
    CHECK(store.stats().pid_reused == 2, "两次 pid 复用都应计数");
}

void run_exit_paths()
{
    ProcessStore store;

    // 有记录、无子进程：实删
    store.add(msg(100, 1000, 0, 0));
    const ProcessChange gone = store.remove(proc(100, 1000));
    CHECK(gone.kind == Kind::REMOVED, "有记录退出应为 REMOVED");
    CHECK(gone.exited.has_value() && *gone.exited == proc(100, 1000),
          "应交出本次身份");
    CHECK(!store.lookup(proc(100, 1000)).has_value(), "退出后应失配");
    CHECK(store.is_exited(proc(100, 1000)), "退出应写墓碑");

    // 子进程退出递减父计数，父进程随后退出
    store.add(msg(200, 2000, 0, 0));
    store.add(msg(201, 2001, 200, 2000));
    auto parent = store.lookup(proc(200, 2000));
    CHECK(parent.has_value() && parent->child_count == 1, "父进程孩子计数应为 1");
    store.remove(proc(201, 2001));
    parent = store.lookup(proc(200, 2000));
    CHECK(parent.has_value() && parent->child_count == 0,
          "子进程退出应递减父计数");
    store.remove(proc(200, 2000));
    CHECK(!store.lookup(proc(200, 2000)).has_value(), "父进程应可正常退出");

    // 无记录退出：只写墓碑，仍交还身份
    const ProcessChange unknown = store.remove(proc(777, 7777));
    CHECK(unknown.kind == Kind::REMOVED, "无记录退出仍为 REMOVED");
    CHECK(unknown.exited.has_value() && *unknown.exited == proc(777, 7777),
          "无记录退出应按本次身份交还");
    CHECK(store.stats().tombstone_depth == 4, "四次退出应各写一条墓碑");

    // 重复退出：仍交还身份，墓碑不新增
    const ProcessChange again = store.remove(proc(100, 1000));
    CHECK(again.kind == Kind::REMOVED, "重复退出仍为 REMOVED");
    CHECK(again.exited.has_value() && *again.exited == proc(100, 1000),
          "重复退出应按身份交还");
    CHECK(store.stats().tombstone_depth == 4, "重复退出不得新增墓碑");
}

void run_vroot()
{
    ProcessStore store;
    store.add(msg(400, 4000, 0, 0));
    store.add(msg(401, 4001, 400, 4000));
    store.add(msg(402, 4002, 400, 4000));

    const ProcessChange exited = store.remove(proc(400, 4000));
    CHECK(exited.exited.has_value() && *exited.exited == proc(400, 4000),
          "退役应交出本身份");
    auto vroot = store.lookup(proc(400, 4000));
    CHECK(vroot.has_value() && vroot->kind == hng::ProcessKind::VIRTUAL &&
              vroot->child_count == 2,
          "有子进程的退出应转入虚拟根");

    // 一个子进程退出：计数递减，虚拟根保留
    const ProcessChange child_one = store.remove(proc(401, 4001));
    CHECK(child_one.exited.has_value() && *child_one.exited == proc(401, 4001),
          "子进程退出只交出子进程自身");
    vroot = store.lookup(proc(400, 4000));
    CHECK(vroot.has_value() && vroot->child_count == 1, "虚拟根计数应递减");

    // 最后一个子进程退出：虚拟根驱逐，不额外交出身份
    const ProcessChange child_two = store.remove(proc(402, 4002));
    CHECK(child_two.exited.has_value() && *child_two.exited == proc(402, 4002),
          "驱逐虚拟根不得追加身份");
    CHECK(!store.lookup(proc(400, 4000)).has_value(), "虚拟根归零应被驱逐");
    CHECK(!store.resolve(400).has_value(), "驱逐后 resolve 应返回空");
    CHECK(store.stats().tombstone_depth == 3, "驱逐不新增墓碑");
}

void run_image()
{
    ProcessStore store;

    // 实进程
    store.add(msg(500, 5000, 0, 0));
    store.update_image(proc(500, 5000), "/bin/bash");
    auto record = store.lookup(proc(500, 5000));
    CHECK(record.has_value() && record->exe == "/bin/bash" &&
              record->kind == hng::ProcessKind::REAL,
          "实进程镜像应更新");

    // 转虚拟根后保留最后镜像
    store.add(msg(600, 6000, 0, 0));
    store.add(msg(601, 6001, 600, 6000));
    store.update_image(proc(600, 6000), "/usr/bin/python3");
    store.remove(proc(600, 6000));
    record = store.lookup(proc(600, 6000));
    CHECK(record.has_value() && record->kind == hng::ProcessKind::VIRTUAL &&
              record->exe == "/usr/bin/python3",
          "转虚拟根应保留最后镜像");

    // 迟到更新命中虚拟根
    store.update_image(proc(600, 6000), "/usr/bin/perl");
    record = store.lookup(proc(600, 6000));
    CHECK(record.has_value() && record->exe == "/usr/bin/perl",
          "虚拟根应接受迟到更新");

    // 同 pid 的新实例不受旧实例的更新影响
    store.add(msg(600, 6002, 0, 0));
    store.update_image(proc(600, 6000), "/late");
    record = store.lookup(proc(600, 6002));
    CHECK(record.has_value() && record->exe.empty(),
          "旧实例的迟到更新不得命中新实例");
    record = store.lookup(proc(600, 6000));
    CHECK(record.has_value() && record->exe == "/late",
          "迟到更新应落到旧实例的虚拟根");

    // 都不命中则丢弃
    store.update_image(proc(999, 9990), "/nowhere");
    CHECK(!store.lookup(proc(999, 9990)).has_value(),
          "未命中的镜像更新不得插入记录");
}

void run_lookup_resolve()
{
    ProcessStore store;
    CHECK(!store.resolve(0).has_value(), "pid 0 应返回空");
    CHECK(!store.resolve(777).has_value(), "未注册 pid 应返回空");

    store.add(msg(700, 7000, 0, 0));
    CHECK(store.resolve(700) == proc(700, 7000), "实进程应可解析");

    // 双表：同一 pid 的旧实例在虚拟根，新实例在实进程树
    store.add(msg(701, 7010, 700, 7000));
    store.remove(proc(700, 7000));
    store.add(msg(700, 7002, 0, 0));
    const auto old_root = store.lookup(proc(700, 7000));
    CHECK(old_root.has_value() && old_root->kind == hng::ProcessKind::VIRTUAL,
          "虚拟根旧实例应可查");
    CHECK(store.lookup(proc(700, 7002)).has_value(), "实进程新实例应可查");
    CHECK(store.resolve(700) == proc(700, 7002), "实进程树应优先");

    // 同一 pid 的多个虚拟根实例：resolve 取最新的
    store.add(msg(800, 8000, 0, 0));
    store.add(msg(801, 8010, 800, 8000));
    store.remove(proc(800, 8000));
    store.add(msg(800, 8002, 0, 0));
    store.add(msg(802, 8020, 800, 8002));
    store.remove(proc(800, 8002));
    CHECK(store.lookup(proc(800, 8000)).has_value(), "较早的虚拟根实例应保留");
    CHECK(store.lookup(proc(800, 8002)).has_value(), "较新的虚拟根实例应保留");
    CHECK(store.resolve(800) == proc(800, 8002), "resolve 应取最新的虚拟根实例");
}

void run_shard_boundary()
{
    ProcessStore store;
    const uint32_t parent       = 900;
    const std::size_t shard     = std::hash<uint32_t>{}(parent) % kShardCount;
    const uint32_t same_shard   = pid_in_shard(shard, 1000);
    const uint32_t other_shard  = pid_in_shard((shard + 1) % kShardCount, 2000);

    const uint64_t parent_start = static_cast<uint64_t>(parent) * 10;
    const uint64_t same_start   = static_cast<uint64_t>(same_shard) * 10;
    const uint64_t other_start  = static_cast<uint64_t>(other_shard) * 10;

    store.add(msg(parent, parent_start, 0, 0));

    store.add(msg(same_shard, same_start, parent, parent_start));
    auto p = store.lookup(proc(parent, parent_start));
    CHECK(p.has_value() && p->child_count == 1, "同分片子进程应计入父计数");
    store.remove(proc(same_shard, same_start));
    p = store.lookup(proc(parent, parent_start));
    CHECK(p.has_value() && p->child_count == 0, "同分片子进程退出应递减父计数");

    store.add(msg(other_shard, other_start, parent, parent_start));
    p = store.lookup(proc(parent, parent_start));
    CHECK(p.has_value() && p->child_count == 1, "跨分片子进程应计入父计数");
    store.remove(proc(other_shard, other_start));
    p = store.lookup(proc(parent, parent_start));
    CHECK(p.has_value() && p->child_count == 0, "跨分片子进程退出应递减父计数");
}

void run_stats()
{
    ProcessStore store;
    const ProcessManagerStats empty = store.stats();
    CHECK(empty.pid_reused == 0 && empty.stale_add == 0 &&
              empty.parent_missing == 0 && empty.tombstone_depth == 0,
          "新表统计应为零");

    store.add(msg(910, 9100, 55, 550));  // 父身份缺失
    CHECK(store.stats().parent_missing == 1, "父缺失应累计");
    store.add(msg(911, 9110, 0, 0));  // 森林根
    CHECK(store.stats().parent_missing == 1, "森林根不应计父缺失");

    store.remove(proc(912, 9120));
    CHECK(store.stats().tombstone_depth == 1, "墓碑深度应为当前值");

    store.add(msg(910, 9101, 0, 0));  // pid 复用
    CHECK(store.stats().pid_reused == 1, "pid 复用应累计");
    store.add(msg(910, 9100, 0, 0));  // 旧身份已有墓碑
    CHECK(store.stats().stale_add == 1, "迟到 ADD 应累计");
    CHECK(store.stats().tombstone_depth == 2, "退役写墓碑，拒收不新增");
}

void run_tombstone_expiry()
{
    FakeClock clock;
    ProcessStore store(timed_options(clock));

    store.remove(proc(920, 9200));
    CHECK(store.stats().tombstone_depth == 1, "退出应写墓碑");
    CHECK(store.is_exited(proc(920, 9200)), "墓碑应命中");
    CHECK(!store.is_exited(proc(921, 9210)), "未记录身份不应命中");

    clock.now += std::chrono::milliseconds(101);
    CHECK(!store.is_exited(proc(920, 9200)), "过期墓碑不应命中");
    CHECK(store.stats().tombstone_depth == 0, "查询应就地清除过期墓碑");

    // 写入口在返回前懒清除
    store.remove(proc(922, 9220));
    CHECK(store.stats().tombstone_depth == 1, "退出应写墓碑");
    clock.now += std::chrono::milliseconds(101);
    store.add(msg(923, 9230, 0, 0));
    CHECK(store.stats().tombstone_depth == 0, "写入口应在返回前清除过期墓碑");

    // 墓碑拒收的早退路径同样清理
    store.remove(proc(924, 9240));
    clock.now += std::chrono::milliseconds(60);
    store.remove(proc(925, 9250));
    clock.now                    += std::chrono::milliseconds(50);
    const ProcessChange rejected  = store.add(msg(925, 9250, 0, 0));
    CHECK(rejected.kind == Kind::NONE, "未过期墓碑应拒收 ADD");
    CHECK(store.stats().tombstone_depth == 1, "墓碑拒收的早退路径也应清理过期项");

    // 镜像未命中的早退路径同样清理
    clock.now += std::chrono::milliseconds(100);
    store.update_image(proc(999, 9990), "/nowhere");
    CHECK(store.stats().tombstone_depth == 0,
          "镜像未命中的早退路径也应清理过期项");
}

}  // namespace

int main()
{
    run_insert_and_idempotent();
    run_pid_reuse();
    run_exit_paths();
    run_vroot();
    run_image();
    run_lookup_resolve();
    run_shard_boundary();
    run_stats();
    run_tombstone_expiry();

    if (g_fail) {
        std::fprintf(stderr, "TOTAL FAILURES: %d\n", g_fail);
        return 1;
    }
    std::printf("ALL PASS\n");
    return 0;
}
