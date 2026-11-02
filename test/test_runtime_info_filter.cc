/**
 * @file test_runtime_info_filter.cc
 * @brief RuntimeInfoFilter 的单元测试
 * @details
 * 覆盖过滤器的维度语义（纯值对象，无 IO / 无特权）：
 *  - 默认构造为全选，且可拷贝；
 *  - 进程维度只比 pid，同 pid 不同 start_time 仍命中；
 *  - 角色 / 上下文 / 事件类型维度按集合成员判定；
 *  - 角色维度含 roleID 与 roleLabel 两组，两组之间取并集；
 *  - 维度之内取并集（命中任一成员即可），维度之间取交集；
 *  - 空集合与未设置的维度一样表示不限；
 *  - set_role({0}, {}) / set_context({0}) 只命中未落定的信息，而非不限；
 *  - 未落定的事件不带标签，不会被非空的标签集合命中。
 * @author red-shinku
 * @date 2026.10.10
 */

#include "agent/event_data/include/runtime_info_filter.hpp"

#include <cstdio>

namespace {

int g_fail = 0;

#define CHECK(cond, msg)                                                         \
    do {                                                                         \
        if (!(cond)) {                                                           \
            ++g_fail;                                                            \
            std::fprintf(stderr, "[FAIL] %s:%d  %s\n", __FILE__, __LINE__, msg); \
        }                                                                        \
    } while (0)

hng::RuntimeInformation make_info(uint32_t pid, uint64_t start_time,
                                  hng::EventType etype, uint32_t roleID,
                                  uint32_t contextID,
                                  hng::role_label_t roleLabel = {})
{
    return hng::RuntimeInformation{hng::Process{pid, start_time}, etype, roleID,
                                   roleLabel, contextID};
}

void run_take_all()
{
    const RuntimeInfoFilter take_all;
    CHECK(take_all.should_take(
              make_info(1, 10, hng::EventType::SYSCALL_EVENT, 0, 0)),
          "全选过滤器应命中未落定的信息");
    CHECK(take_all.should_take(
              make_info(99, 12345, hng::EventType::IPC_EVENT, 7, 8)),
          "全选过滤器应命中任意信息");
}

void run_empty_dimension_is_unlimited()
{
    // 显式设成空集合与不设置等价：该维度不限
    const RuntimeInfoFilter filter = RuntimeInfoFilter{}
                                         .set_process({})
                                         .set_role({}, {})
                                         .set_context({})
                                         .set_etype({});
    CHECK(filter.should_take(make_info(1, 10, hng::EventType::IPC_EVENT, 7, 8)),
          "空集合维度不应参与判定");
}

void run_process_dimension()
{
    RuntimeInfoFilter filter;
    filter.set_process({100, 200});
    CHECK(
        filter.should_take(make_info(100, 500, hng::EventType::FILE_EVENT, 1, 2)),
        "pid 在集合中应命中");
    CHECK(
        filter.should_take(make_info(200, 999, hng::EventType::FILE_EVENT, 1, 2)),
        "集合内任一 pid 都应命中（并集）");
    CHECK(
        filter.should_take(make_info(100, 501, hng::EventType::FILE_EVENT, 1, 2)),
        "进程维度只比 pid，start_time 不同仍应命中");
    CHECK(!filter.should_take(
              make_info(101, 500, hng::EventType::FILE_EVENT, 1, 2)),
          "pid 不在集合中不应命中");
}

void run_role_dimension()
{
    RuntimeInfoFilter filter;
    filter.set_role({42, 43}, {});
    CHECK(filter.should_take(
              make_info(1, 10, hng::EventType::SYSCALL_EVENT, 42, 0)),
          "角色在集合中应命中");
    CHECK(filter.should_take(
              make_info(1, 10, hng::EventType::SYSCALL_EVENT, 43, 0)),
          "集合内任一角色都应命中（并集）");
    CHECK(!filter.should_take(
              make_info(1, 10, hng::EventType::SYSCALL_EVENT, 44, 0)),
          "角色不在集合中不应命中");
}

void run_role_label_dimension()
{
    // roleID 与 roleLabel 同属角色维度：两组取并集
    RuntimeInfoFilter filter;
    filter.set_role({42}, {"nginx:1.25"});

    CHECK(filter.should_take(
              make_info(1, 10, hng::EventType::SYSCALL_EVENT, 42, 0, "")),
          "roleID 命中应通过");
    CHECK(filter.should_take(make_info(1, 10, hng::EventType::SYSCALL_EVENT, 43,
                                       0, "nginx:1.25")),
          "roleLabel 命中应通过：两组是并集");
    CHECK(!filter.should_take(
              make_info(1, 10, hng::EventType::SYSCALL_EVENT, 43, 0, "redis:7")),
          "两组都不命中则不应通过");
    CHECK(!filter.should_take(
              make_info(1, 10, hng::EventType::SYSCALL_EVENT, 43, 0, "")),
          "未落定的事件不带标签，不应被标签集合命中");
}

void run_role_label_only()
{
    // 只设标签：按 roleID 不限，但未落定的事件仍不命中
    RuntimeInfoFilter filter;
    filter.set_role({}, {"nginx:1.25"});

    CHECK(filter.should_take(make_info(1, 10, hng::EventType::SYSCALL_EVENT, 999,
                                       0, "nginx:1.25")),
          "只设标签时按标签命中");
    CHECK(!filter.should_take(
              make_info(1, 10, hng::EventType::SYSCALL_EVENT, 999, 0, "")),
          "只设标签时不命中未落定");
}

void run_context_dimension()
{
    RuntimeInfoFilter filter;
    filter.set_context({9});
    CHECK(
        filter.should_take(make_info(1, 10, hng::EventType::SYSCALL_EVENT, 0, 9)),
        "上下文在集合中应命中");
    CHECK(!filter.should_take(
              make_info(1, 10, hng::EventType::SYSCALL_EVENT, 0, 0)),
          "上下文不在集合中不应命中");
}

void run_etype_dimension()
{
    RuntimeInfoFilter filter;
    filter.set_etype({hng::EventType::FILE_EVENT, hng::EventType::SYSCALL_EVENT});
    CHECK(filter.should_take(make_info(1, 10, hng::EventType::FILE_EVENT, 0, 0)),
          "事件类型在集合中应命中");
    CHECK(
        filter.should_take(make_info(1, 10, hng::EventType::SYSCALL_EVENT, 0, 0)),
        "集合内任一事件类型都应命中（并集）");
    CHECK(!filter.should_take(make_info(1, 10, hng::EventType::IPC_EVENT, 0, 0)),
          "事件类型不在集合中不应命中");
}

void run_dimensions_are_intersected()
{
    RuntimeInfoFilter filter;
    filter.set_process({7}).set_role({3}, {}).set_context({5}).set_etype(
        {hng::EventType::FILE_EVENT});

    CHECK(filter.should_take(make_info(7, 70, hng::EventType::FILE_EVENT, 3, 5)),
          "四个维度全中应命中");
    CHECK(!filter.should_take(make_info(8, 70, hng::EventType::FILE_EVENT, 3, 5)),
          "仅进程不符即不命中");
    CHECK(!filter.should_take(make_info(7, 70, hng::EventType::FILE_EVENT, 4, 5)),
          "仅角色不符即不命中");
    CHECK(!filter.should_take(make_info(7, 70, hng::EventType::FILE_EVENT, 3, 6)),
          "仅上下文不符即不命中");
    CHECK(!filter.should_take(
              make_info(7, 70, hng::EventType::SYSCALL_EVENT, 3, 5)),
          "仅事件类型不符即不命中");
}

void run_zero_is_literal()
{
    // roleID / contextID 的 0 是「未落定」哨兵，按键值比较而非「不限」
    RuntimeInfoFilter filter;
    filter.set_role({0}, {});
    CHECK(filter.should_take(
              make_info(1, 10, hng::EventType::SYSCALL_EVENT, 0, 77)),
          "set_role({0}) 应命中未落定的角色");
    CHECK(!filter.should_take(
              make_info(1, 10, hng::EventType::SYSCALL_EVENT, 3, 77)),
          "set_role({0}) 不应命中已落定的角色");
}

void run_copyable()
{
    RuntimeInfoFilter filter;
    filter.set_role({3}, {}).set_etype({hng::EventType::SYSCALL_EVENT});

    const RuntimeInfoFilter copy = filter;
    CHECK(copy.should_take(make_info(1, 10, hng::EventType::SYSCALL_EVENT, 3, 0)),
          "拷贝应保持各维度");
    CHECK(!copy.should_take(make_info(1, 10, hng::EventType::FILE_EVENT, 3, 0)),
          "拷贝应保持各维度（事件类型）");
}

}  // namespace

int main()
{
    run_take_all();
    run_empty_dimension_is_unlimited();
    run_process_dimension();
    run_role_dimension();
    run_role_label_dimension();
    run_role_label_only();
    run_context_dimension();
    run_etype_dimension();
    run_dimensions_are_intersected();
    run_zero_is_literal();
    run_copyable();

    if (g_fail) {
        std::fprintf(stderr, "TOTAL FAILURES: %d\n", g_fail);
        return 1;
    }
    std::printf("ALL PASS\n");
    return 0;
}
