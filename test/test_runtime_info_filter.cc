/**
 * @file test_runtime_info_filter.cc
 * @brief RuntimeInfoFilter 的单元测试
 * @details
 * 覆盖过滤器的维度语义（纯值对象，无 IO / 无特权）：
 *  - 默认构造为全选，且可拷贝；
 *  - 进程维度按 (pid, pid_start_time) 判等，同 pid 不同 start_time 不命中；
 *  - 角色 / 上下文 / 事件类型维度按字面量相等判定；
 *  - 多维度之间是「与」，任一不命中则整体不命中；
 *  - set_role(0) / set_context(0) 只命中未落定的信息，而非不限。
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
                                  uint32_t contextID)
{
    return hng::RuntimeInformation{hng::Process{pid, start_time}, etype, roleID,
                                   contextID};
}

void run_take_all()
{
    const RuntimeInfoFilter take_all;
    CHECK(take_all.should_take(make_info(1, 10, hng::EventType::SYSCALL_EVENT, 0,
                                         0)),
          "全选过滤器应命中未落定的信息");
    CHECK(take_all.should_take(
              make_info(99, 12345, hng::EventType::IPC_EVENT, 7, 8)),
          "全选过滤器应命中任意信息");
}

void run_process_dimension()
{
    RuntimeInfoFilter filter;
    filter.set_process(hng::Process{100, 500});
    CHECK(filter.should_take(
              make_info(100, 500, hng::EventType::FILE_EVENT, 1, 2)),
          "进程两个字段均相等才命中");
    CHECK(!filter.should_take(
              make_info(100, 501, hng::EventType::FILE_EVENT, 1, 2)),
          "同 pid 而 start_time 不同是另一个进程实体，不应命中");
    CHECK(!filter.should_take(
              make_info(101, 500, hng::EventType::FILE_EVENT, 1, 2)),
          "pid 不同不应命中");
}

void run_role_dimension()
{
    RuntimeInfoFilter filter;
    filter.set_role(42);
    CHECK(filter.should_take(
              make_info(1, 10, hng::EventType::SYSCALL_EVENT, 42, 0)),
          "角色相等应命中");
    CHECK(!filter.should_take(
              make_info(1, 10, hng::EventType::SYSCALL_EVENT, 43, 0)),
          "角色不等不应命中");
}

void run_context_dimension()
{
    RuntimeInfoFilter filter;
    filter.set_context(9);
    CHECK(filter.should_take(
              make_info(1, 10, hng::EventType::SYSCALL_EVENT, 0, 9)),
          "上下文相等应命中");
    CHECK(!filter.should_take(
              make_info(1, 10, hng::EventType::SYSCALL_EVENT, 0, 0)),
          "上下文不等不应命中");
}

void run_etype_dimension()
{
    RuntimeInfoFilter filter;
    filter.set_etype(hng::EventType::FILE_EVENT);
    CHECK(filter.should_take(
              make_info(1, 10, hng::EventType::FILE_EVENT, 0, 0)),
          "事件类型相等应命中");
    CHECK(!filter.should_take(
              make_info(1, 10, hng::EventType::SYSCALL_EVENT, 0, 0)),
          "事件类型不等不应命中");
}

void run_and_composition()
{
    const hng::Process proc{7, 70};
    RuntimeInfoFilter filter;
    filter.set_process(proc).set_role(3).set_context(5).set_etype(
        hng::EventType::FILE_EVENT);

    CHECK(filter.should_take(
              make_info(7, 70, hng::EventType::FILE_EVENT, 3, 5)),
          "四个维度全中应命中");
    CHECK(!filter.should_take(
              make_info(7, 70, hng::EventType::FILE_EVENT, 3, 6)),
          "仅上下文不符即不命中");
    CHECK(!filter.should_take(
              make_info(7, 70, hng::EventType::FILE_EVENT, 4, 5)),
          "仅角色不符即不命中");
    CHECK(!filter.should_take(
              make_info(7, 71, hng::EventType::FILE_EVENT, 3, 5)),
          "仅进程不符即不命中");
    CHECK(!filter.should_take(
              make_info(7, 70, hng::EventType::SYSCALL_EVENT, 3, 5)),
          "仅事件类型不符即不命中");
}

void run_zero_is_literal()
{
    // roleID / contextID 的 0 是「未落定」哨兵，按字面量比较而非「不限」
    RuntimeInfoFilter filter;
    filter.set_role(0);
    CHECK(filter.should_take(
              make_info(1, 10, hng::EventType::SYSCALL_EVENT, 0, 77)),
          "set_role(0) 应命中未落定的角色");
    CHECK(!filter.should_take(
              make_info(1, 10, hng::EventType::SYSCALL_EVENT, 3, 77)),
          "set_role(0) 不应命中已落定的角色");
}

void run_copyable()
{
    RuntimeInfoFilter filter;
    filter.set_role(3).set_etype(hng::EventType::SYSCALL_EVENT);

    const RuntimeInfoFilter copy = filter;
    CHECK(copy.should_take(
              make_info(1, 10, hng::EventType::SYSCALL_EVENT, 3, 0)),
          "拷贝应保持各维度");
    CHECK(!copy.should_take(make_info(1, 10, hng::EventType::FILE_EVENT, 3, 0)),
          "拷贝应保持各维度（事件类型）");
}

}  // namespace

int main()
{
    run_take_all();
    run_process_dimension();
    run_role_dimension();
    run_context_dimension();
    run_etype_dimension();
    run_and_composition();
    run_zero_is_literal();
    run_copyable();

    if (g_fail) {
        std::fprintf(stderr, "TOTAL FAILURES: %d\n", g_fail);
        return 1;
    }
    std::printf("ALL PASS\n");
    return 0;
}
