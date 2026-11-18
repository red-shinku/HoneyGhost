/**
 * @file test_runtime_packaging.cc
 * @brief RuntimePackaging 的单元测试
 * @details
 * 覆盖单条包装路径（纯转换，无 IO / 无特权）：
 *  - 进程身份取自事件头的 (pid, pid_start_time)，与 ppid 无关；
 *  - 父进程身份取自事件头的 (ppid, ppid_start_time)，与主体进程互不影响；
 *  - 事件来源恒为 SYSCALL_EVENT；
 *  - 语义子类型取自事件头的 subtype（PROCESS..KERNEL），不由载荷 variant
 * 下标推导；
 *  - roleID / contextID 原样透传，0（未落定）不被改写、不视为异常；
 *  - 载荷被完整搬运：头部与内层载荷均可从产物中取回；
 *  - 源事件以右值传入时同样保留载荷。
 * @author red-shinku
 * @date 2026.10.10
 */

#include "agent/runtime_engine/src/runtime_packaging.hpp"

#include <cstdint>
#include <cstdio>
#include <utility>
#include <variant>

namespace {

int g_fail = 0;

#define CHECK(cond, msg)                                                         \
    do {                                                                         \
        if (!(cond)) {                                                           \
            ++g_fail;                                                            \
            std::fprintf(stderr, "[FAIL] %s:%d  %s\n", __FILE__, __LINE__, msg); \
        }                                                                        \
    } while (0)

hng::syscall_semantic_data make_syscall(uint32_t pid, uint64_t pid_start_time,
                                        uint32_t ppid, uint64_t ppid_start_time)
{
    hng::syscall_semantic_data ev;
    ev.head.pid             = pid;
    ev.head.pid_start_time  = pid_start_time;
    ev.head.ppid            = ppid;
    ev.head.ppid_start_time = ppid_start_time;
    ev.head.type            = hng::EventType::SYSCALL_EVENT;
    ev.head.subtype         = UNKNOWN_EVENT;
    return ev;
}

const hng::syscall_semantic_data& syscall_of(const hng::RuntimeEvent& event)
{
    return event.data;
}

void run_syscall_identity_and_type()
{
    hng::syscall_semantic_data src = make_syscall(1001, 555, 900, 111);
    src.head.subtype               = PROCESS_EVENT;
    src.data.emplace<hng::process_semantic_data>();

    const hng::RuntimeEvent event =
        RuntimePackaging::pack(src, 7, "nginx:1.25", 33);

    CHECK(event.runtimeInfo.process.pid == 1001, "进程身份应取事件头的 pid");
    CHECK(event.runtimeInfo.process.pid_start_time == 555,
          "进程身份应取事件头的 pid_start_time");
    CHECK(event.runtimeInfo.etype == hng::EventType::SYSCALL_EVENT,
          "事件来源应恒为 SYSCALL_EVENT");
    CHECK(event.runtimeInfo.subtype == PROCESS_EVENT,
          "语义子类型应取事件头的 subtype");
    CHECK(event.runtimeInfo.roleID == 7 && event.runtimeInfo.contextID == 33,
          "归属应按入参透传");
    CHECK(event.runtimeInfo.roleLabel == "nginx:1.25", "角色标签应按入参透传");
    CHECK(event.data.head.pid == 1001, "头部应随载荷一并搬运");
}

void run_syscall_payload_kinds()
{
    // 内层换成别的载荷，事件来源仍是 SYSCALL_EVENT
    hng::syscall_semantic_data src = make_syscall(3, 30, 1, 10);
    src.head.subtype               = EXEC_EVENT;
    auto& exec_payload             = src.data.emplace<hng::exec_semantic_data>();
    exec_payload.set_semantic_filename("/bin/sh");
    exec_payload.set_syscall_name("execve");

    const hng::RuntimeEvent event =
        RuntimePackaging::pack(std::move(src), 0, "", 4);

    CHECK(event.runtimeInfo.etype == hng::EventType::SYSCALL_EVENT,
          "内层 exec 载荷仍应推出 SYSCALL_EVENT");
    CHECK(event.runtimeInfo.subtype == EXEC_EVENT, "语义子类型应取事件头的 EXEC");
    const hng::syscall_semantic_data& packed = syscall_of(event);
    CHECK(packed.data.index() == 1, "内层载荷应保持为 exec");
    const hng::exec_semantic_data& exec_packed =
        std::get<hng::exec_semantic_data>(packed.data);
    CHECK(exec_packed.semantic_filename() == "/bin/sh", "内层载荷内容应被搬运");
    CHECK(exec_packed.syscall_name() == "execve", "内层载荷内容应被搬运");
}

void run_unsettled_ids()
{
    hng::syscall_semantic_data src = make_syscall(5, 50, 1, 10);
    src.data.emplace<hng::process_semantic_data>();

    const hng::RuntimeEvent event = RuntimePackaging::pack(src, 0, "", 0);

    CHECK(event.runtimeInfo.roleID == 0 && event.runtimeInfo.contextID == 0,
          "未落定（0）应原样透传");
    CHECK(event.runtimeInfo.roleLabel.empty(), "未落定时角色标签为空");
}

void run_payload_carried_by_value()
{
    hng::syscall_semantic_data src = make_syscall(6, 60, 1, 10);
    auto& payload = src.data.emplace<hng::process_semantic_data>();
    payload.set_exit_code(-11);
    payload.set_syscall_name("exit_group");

    const hng::RuntimeEvent event =
        RuntimePackaging::pack(std::move(src), 9, "tool:1", 9);

    const hng::syscall_semantic_data& packed = syscall_of(event);
    CHECK(packed.head.pid == 6 && packed.head.pid_start_time == 60,
          "头部应随载荷一并搬运");
    const hng::process_semantic_data& proc_packed =
        std::get<hng::process_semantic_data>(packed.data);
    CHECK(proc_packed.exit_code() == -11, "退出码应被搬运");
    CHECK(proc_packed.syscall_name() == "exit_group", "系统调用名应被搬运");
}

void run_parent_from_head()
{
    hng::syscall_semantic_data src = make_syscall(1001, 555, 900, 111);
    src.data.emplace<hng::process_semantic_data>();

    const hng::RuntimeEvent event = RuntimePackaging::pack(src, 0, "", 0);

    CHECK(event.runtimeInfo.parent.pid == 900, "父进程 pid 应取事件头的 ppid");
    CHECK(event.runtimeInfo.parent.pid_start_time == 111,
          "父进程 start_time 应取事件头的 ppid_start_time");
    CHECK(event.runtimeInfo.process.pid == 1001 &&
              event.runtimeInfo.process.pid_start_time == 555,
          "父进程字段不应影响主体进程");
}

/// @brief 打包一条已填 subtype 的 syscall 事件并核对 subtype 与 etype
void check_syscall_subtype(const hng::syscall_semantic_data& src,
                           enum syscall_event_type expected, const char* msg)
{
    const hng::RuntimeEvent event = RuntimePackaging::pack(src, 0, "", 0);
    CHECK(event.runtimeInfo.subtype == expected, msg);
    CHECK(event.runtimeInfo.etype == hng::EventType::SYSCALL_EVENT,
          "内层载荷变化不应影响 etype");
}

void run_syscall_event_subtypes()
{
    hng::syscall_semantic_data src = make_syscall(9, 90, 1, 10);

    src.head.subtype               = PROCESS_EVENT;
    src.data.emplace<hng::process_semantic_data>();
    check_syscall_subtype(src, PROCESS_EVENT, "第 1 个载荷应为 PROCESS");

    src.head.subtype = EXEC_EVENT;
    src.data.emplace<hng::exec_semantic_data>();
    check_syscall_subtype(src, EXEC_EVENT, "第 2 个载荷应为 EXEC");

    src.head.subtype = CREDENTIAL_EVENT;
    src.data.emplace<hng::credential_semantic_data>();
    check_syscall_subtype(src, CREDENTIAL_EVENT, "第 3 个载荷应为 CREDENTIAL");

    src.head.subtype = NAMESPACE_EVENT;
    src.data.emplace<hng::namespace_semantic_data>();
    check_syscall_subtype(src, NAMESPACE_EVENT, "第 4 个载荷应为 NAMESPACE");

    src.head.subtype = FILE_EVENT;
    src.data.emplace<hng::file_syscall_semantic_data>();
    check_syscall_subtype(src, FILE_EVENT, "第 5 个载荷应为 FILE");

    src.head.subtype = MEMORY_EVENT;
    src.data.emplace<hng::memory_semantic_data>();
    check_syscall_subtype(src, MEMORY_EVENT, "第 6 个载荷应为 MEMORY");

    src.head.subtype = NETWORK_EVENT;
    src.data.emplace<hng::network_syscall_semantic_data>();
    check_syscall_subtype(src, NETWORK_EVENT, "第 7 个载荷应为 NETWORK");

    src.head.subtype = KERNEL_EVENT;
    src.data.emplace<hng::kernel_semantic_data>();
    check_syscall_subtype(src, KERNEL_EVENT, "第 8 个载荷应为 KERNEL");
}

void run_subtype_not_derived_from_index()
{
    // 头里的数值与载荷变体故意错位：产物必须原样保留头里的值
    hng::syscall_semantic_data src = make_syscall(10, 100, 1, 10);
    src.head.subtype               = KERNEL_EVENT;
    src.data.emplace<hng::process_semantic_data>();

    const hng::RuntimeEvent event = RuntimePackaging::pack(src, 0, "", 0);
    CHECK(event.runtimeInfo.subtype == KERNEL_EVENT,
          "subtype 不应由变体下标推出");
    CHECK(event.data.data.index() == 0, "载荷本身不应被改写");
}

void run_event_subtype_values()
{
    CHECK(static_cast<uint8_t>(UNKNOWN_EVENT) == 0, "UNKNOWN_EVENT 取 0");
    CHECK(static_cast<uint8_t>(PROCESS_EVENT) == 1, "PROCESS_EVENT 取 1");
    CHECK(static_cast<uint8_t>(EXEC_EVENT) == 2, "EXEC_EVENT 取 2");
    CHECK(static_cast<uint8_t>(CREDENTIAL_EVENT) == 3, "CREDENTIAL_EVENT 取 3");
    CHECK(static_cast<uint8_t>(NAMESPACE_EVENT) == 4, "NAMESPACE_EVENT 取 4");
    CHECK(static_cast<uint8_t>(FILE_EVENT) == 5, "FILE_EVENT 取 5");
    CHECK(static_cast<uint8_t>(MEMORY_EVENT) == 6, "MEMORY_EVENT 取 6");
    CHECK(static_cast<uint8_t>(NETWORK_EVENT) == 7, "NETWORK_EVENT 取 7");
    CHECK(static_cast<uint8_t>(KERNEL_EVENT) == 8, "KERNEL_EVENT 取 8");
}

}  // namespace

int main()
{
    run_syscall_identity_and_type();
    run_syscall_payload_kinds();
    run_parent_from_head();
    run_syscall_event_subtypes();
    run_subtype_not_derived_from_index();
    run_event_subtype_values();
    run_unsettled_ids();
    run_payload_carried_by_value();

    if (g_fail) {
        std::fprintf(stderr, "TOTAL FAILURES: %d\n", g_fail);
        return 1;
    }
    std::printf("ALL PASS\n");
    return 0;
}
