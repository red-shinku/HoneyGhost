/**
 * @file test_runtime_packaging.cc
 * @brief RuntimePackaging 的单元测试
 * @details
 * 覆盖两条包装路径（纯转换，无 IO / 无特权）：
 *  - 进程身份取自事件头的 (pid, pid_start_time)，与 ppid 无关；
 *  - 事件类型由载荷 variant 索引推出：syscall / file 两类分别落到
 *    SYSCALL_EVENT / FILE_EVENT，且与 syscall 内部的八种载荷无关；
 *  - roleID / contextID 原样透传，0（未落定）不被改写、不视为异常；
 *  - 载荷被完整搬运：头部与内层载荷均可从产物中取回；
 *  - 源事件以右值传入时同样保留载荷。
 * @author red-shinku
 * @date 2026.10.10
 */

#include "agent/runtime_engine/src/runtime_packaging.hpp"

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
    return ev;
}

hng::file_semantic_data make_file(uint32_t pid, uint64_t pid_start_time)
{
    hng::file_semantic_data ev;
    ev.head.pid             = pid;
    ev.head.pid_start_time  = pid_start_time;
    ev.head.ppid            = 0;
    ev.head.ppid_start_time = 0;
    ev.head.type            = hng::EventType::FILE_EVENT;
    return ev;
}

const hng::syscall_semantic_data& syscall_of(const hng::RuntimeEvent& event)
{
    return std::get<hng::syscall_semantic_data>(event.data);
}

void run_syscall_identity_and_type()
{
    hng::syscall_semantic_data src = make_syscall(1001, 555, 900, 111);
    src.data.emplace<hng::process_semantic_data>();

    const hng::RuntimeEvent event =
        RuntimePackaging::pack(src, 7, "nginx:1.25", 33);

    CHECK(event.runtimeInfo.process.pid == 1001, "进程身份应取事件头的 pid");
    CHECK(event.runtimeInfo.process.pid_start_time == 555,
          "进程身份应取事件头的 pid_start_time");
    CHECK(event.runtimeInfo.etype == hng::EventType::SYSCALL_EVENT,
          "syscall 载荷应推出 SYSCALL_EVENT");
    CHECK(event.runtimeInfo.roleID == 7 && event.runtimeInfo.contextID == 33,
          "归属应按入参透传");
    CHECK(event.runtimeInfo.roleLabel == "nginx:1.25", "角色标签应按入参透传");
    CHECK(event.data.index() == 0, "syscall 载荷应落在 variant 的第 0 项");
}

void run_file_identity_and_type()
{
    hng::file_semantic_data src = make_file(2002, 888);
    src.data.set_semantic_filename("/usr/bin/tool");
    src.data.set_comm("bash");

    const hng::RuntimeEvent event = RuntimePackaging::pack(src, 1, "redis:7", 2);

    CHECK(event.runtimeInfo.roleLabel == "redis:7", "文件事件也应带角色标签");

    CHECK(event.runtimeInfo.process.pid == 2002, "文件事件的进程身份应取事件头");
    CHECK(event.runtimeInfo.process.pid_start_time == 888,
          "文件事件的进程身份应取事件头");
    CHECK(event.runtimeInfo.etype == hng::EventType::FILE_EVENT,
          "文件载荷应推出 FILE_EVENT");
    CHECK(event.data.index() == 1, "文件载荷应落在 variant 的第 1 项");

    const hng::file_semantic_data& packed =
        std::get<hng::file_semantic_data>(event.data);
    CHECK(packed.data.semantic_filename() == "/usr/bin/tool",
          "载荷的语义化路径应被搬运");
    CHECK(packed.data.comm() == "bash", "载荷的进程名应被搬运");
}

void run_syscall_payload_kinds()
{
    // 内层换成别的载荷，事件类型仍由外层 variant 索引决定
    hng::syscall_semantic_data src = make_syscall(3, 30, 1, 10);
    auto& exec_payload             = src.data.emplace<hng::exec_semantic_data>();
    exec_payload.set_semantic_filename("/bin/sh");
    exec_payload.set_syscall_name("execve");

    const hng::RuntimeEvent event =
        RuntimePackaging::pack(std::move(src), 0, "", 4);

    CHECK(event.runtimeInfo.etype == hng::EventType::SYSCALL_EVENT,
          "内层 exec 载荷仍应推出 SYSCALL_EVENT");
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

}  // namespace

int main()
{
    run_syscall_identity_and_type();
    run_file_identity_and_type();
    run_syscall_payload_kinds();
    run_unsettled_ids();
    run_payload_carried_by_value();

    if (g_fail) {
        std::fprintf(stderr, "TOTAL FAILURES: %d\n", g_fail);
        return 1;
    }
    std::printf("ALL PASS\n");
    return 0;
}
