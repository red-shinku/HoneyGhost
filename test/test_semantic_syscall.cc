/**
 * @file test_semantic_syscall.cc
 * @brief 系统调用语义化表驱动单元测试
 * @details
 * 按 hdr.type 的八类事件各一张表，经公开纯转换接口 transform_one 断言输出
 * 语义事件：variant 类型、关键字段、syscall_name 字符串，以及 exec 的
 * filename 路径语义化与 credential 的 union→oneof 归位。
 *
 * @author red_shinku
 * @date 2026.08.17
 */

#include "agent/semantic/include/semantic.hpp"
#include "kernel/include/syscalls_type.h"

#include <fcntl.h>
#include <netinet/in.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/socket.h>

#include <cstdio>
#include <cstring>
#include <string>
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

// ---- 队列往返辅助 ----

/**
 * @brief 单条原始事件 → 语义事件（经公开纯转换接口 transform_one）
 */
void run_one(const struct syscall_event& raw, hng::syscall_semantic_data& out)
{
    hng::SPSC_Queue<struct syscall_event> in_queue(8);
    hng::SPSC_Queue<hng::syscall_semantic_data> out_queue(8);
    Semantic_syscall sem(in_queue, out_queue);
    sem.transform_one(raw, out);
}

/**
 * @brief 填充原始事件的身份头部与 syscall 名/类型
 */
void fill_head(struct syscall_event& raw, enum syscall_event_name name,
               enum syscall_event_type type)
{
    raw.hdr.head.pid             = 1234;
    raw.hdr.head.pid_start_time  = 111;
    raw.hdr.head.ppid            = 100;
    raw.hdr.head.ppid_start_time = 222;
    raw.hdr.name                 = name;
    raw.hdr.type                 = type;
}

/**
 * @brief 断言身份头部原样搬运
 */
void check_head(const hng::syscall_semantic_data& out)
{
    CHECK(out.head.pid == 1234, "head pid");
    CHECK(out.head.pid_start_time == 111, "head pid_start_time");
    CHECK(out.head.ppid == 100, "head ppid");
    CHECK(out.head.ppid_start_time == 222, "head ppid_start_time");
    CHECK(out.head.type == hng::EventType::SYSCALL_EVENT, "head type");
}

// ---- 进程生命周期 ----

struct ProcessCase {
    enum syscall_event_name name;
    __u64 clone_flags;
    __s32 exit_code;
    const char* name_str;
};

constexpr ProcessCase kProcessCases[] = {
    {SYSCALL_EVENT_FORK, 0, 0, "fork"},
    {SYSCALL_EVENT_CLONE, 0x00000100, 0, "clone"},  // CLONE_VM
    {SYSCALL_EVENT_VFORK, 0, 0, "vfork"},
    {SYSCALL_EVENT_EXIT_GROUP, 0, -1, "exit_group"},
};

void run_process()
{
    for (const ProcessCase& c : kProcessCases) {
        struct syscall_event raw = {};
        fill_head(raw, c.name, PROCESS_EVENT);
        raw.process_event.clone_flags = c.clone_flags;
        raw.process_event.exit_code   = c.exit_code;

        hng::syscall_semantic_data out;
        run_one(raw, out);
        check_head(out);
        const auto* d = std::get_if<hng::process_semantic_data>(&out.data);
        CHECK(d != nullptr, "process variant type");
        if (!d) {
            continue;
        }
        CHECK(d->clone_flags() == c.clone_flags, "process clone_flags");
        CHECK(d->exit_code() == c.exit_code, "process exit_code");
        CHECK(d->syscall_name() == c.name_str, "process syscall_name");
    }
}

// ---- 执行事件 ----

struct ExecCase {
    enum syscall_event_name name;
    const char* filename;
    const char* argv0;
    __u32 flags;
    const char* expect_sem;
    const char* name_str;
};

constexpr ExecCase kExecCases[] = {
    {SYSCALL_EVENT_EXECVE, "/bin/ls", "ls", 0, "/bin/ls", "execve"},
    {SYSCALL_EVENT_EXECVE, "/tmp/abc123def456", "tmpbin", 0, "/tmp/*", "execve"},
    {SYSCALL_EVENT_EXECVEAT, "/proc/1234/cmdline", "p", 0x100, "/proc/{pid}/**",
     "execveat"},
};

void run_exec()
{
    for (const ExecCase& c : kExecCases) {
        struct syscall_event raw = {};
        fill_head(raw, c.name, EXEC_EVENT);
        std::strncpy(raw.exec_event.filename, c.filename,
                     sizeof(raw.exec_event.filename) - 1);
        std::strncpy(raw.exec_event.argv0, c.argv0,
                     sizeof(raw.exec_event.argv0) - 1);
        raw.exec_event.flags = c.flags;

        hng::syscall_semantic_data out;
        run_one(raw, out);
        check_head(out);
        const auto* d = std::get_if<hng::exec_semantic_data>(&out.data);
        CHECK(d != nullptr, "exec variant type");
        if (!d) {
            continue;
        }
        CHECK(d->semantic_filename() == c.expect_sem, "exec semantic_filename");
        CHECK(d->argv0() == c.argv0, "exec argv0");
        CHECK(d->flags() == c.flags, "exec flags");
        CHECK(d->syscall_name() == c.name_str, "exec syscall_name");
    }
}

// ---- 权限变更 ----

struct CredentialCase {
    enum syscall_event_name name;
    __u32 uid, gid;
    __u64 cap_eff, cap_perm, cap_inh;
    const char* name_str;
};

constexpr CredentialCase kCredentialCases[] = {
    {SYSCALL_EVENT_SETUID, 1000, 0, 0, 0, 0, "setuid"},
    {SYSCALL_EVENT_SETGID, 0, 2000, 0, 0, 0, "setgid"},
    {SYSCALL_EVENT_CAPSET, 0, 0, 0x1, 0x2, 0x4, "capset"},
};

void run_credential()
{
    for (const CredentialCase& c : kCredentialCases) {
        struct syscall_event raw = {};
        fill_head(raw, c.name, CREDENTIAL_EVENT);
        switch (c.name) {
            case SYSCALL_EVENT_SETUID:
                raw.credential_event.setuid.uid = c.uid;
                break;
            case SYSCALL_EVENT_SETGID:
                raw.credential_event.setgid.gid = c.gid;
                break;
            case SYSCALL_EVENT_CAPSET:
                raw.credential_event.capset.effective   = c.cap_eff;
                raw.credential_event.capset.permitted   = c.cap_perm;
                raw.credential_event.capset.inheritable = c.cap_inh;
                break;
            default:
                break;
        }

        hng::syscall_semantic_data out;
        run_one(raw, out);
        check_head(out);
        const auto* d = std::get_if<hng::credential_semantic_data>(&out.data);
        CHECK(d != nullptr, "credential variant type");
        if (!d) {
            continue;
        }
        CHECK(d->syscall_name() == c.name_str, "credential syscall_name");
        if (c.name == SYSCALL_EVENT_SETUID) {
            CHECK(d->has_setuid_uid() && d->setuid_uid() == c.uid,
                  "credential setuid uid");
        }
        else if (c.name == SYSCALL_EVENT_SETGID) {
            CHECK(d->has_setgid_gid() && d->setgid_gid() == c.gid,
                  "credential setgid gid");
        }
        else {
            CHECK(d->has_capset(), "credential capset branch");
            if (d->has_capset()) {
                CHECK(d->capset().effective() == c.cap_eff,
                      "credential capset effective");
                CHECK(d->capset().permitted() == c.cap_perm,
                      "credential capset permitted");
                CHECK(d->capset().inheritable() == c.cap_inh,
                      "credential capset inheritable");
            }
        }
    }
}

// ---- 命名空间 ----

struct NamespaceCase {
    enum syscall_event_name name;
    __u32 ns_type;
    __u64 flags;
    const char* name_str;
};

constexpr NamespaceCase kNamespaceCases[] = {
    // 0x40000000 = CLONE_NEWNET
    {SYSCALL_EVENT_UNSHARE, 0x40000000, 0x40000000, "unshare"},
    {SYSCALL_EVENT_SETNS, 0x40000000, 0, "setns"},
};

void run_namespace()
{
    for (const NamespaceCase& c : kNamespaceCases) {
        struct syscall_event raw = {};
        fill_head(raw, c.name, NAMESPACE_EVENT);
        raw.namespace_event.ns_type = c.ns_type;
        raw.namespace_event.flags   = c.flags;

        hng::syscall_semantic_data out;
        run_one(raw, out);
        check_head(out);
        const auto* d = std::get_if<hng::namespace_semantic_data>(&out.data);
        CHECK(d != nullptr, "namespace variant type");
        if (!d) {
            continue;
        }
        CHECK(d->ns_type() == c.ns_type, "namespace ns_type");
        CHECK(d->flags() == c.flags, "namespace flags");
        CHECK(d->syscall_name() == c.name_str, "namespace syscall_name");
    }
}

// ---- 文件系统调用 ----

struct FileCase {
    enum syscall_event_name name;
    __u32 flags;
    __u32 mode;
    const char* name_str;
};

constexpr FileCase kFileCases[] = {
    {SYSCALL_EVENT_OPEN, O_CREAT | O_WRONLY | O_TRUNC, 0644, "open"},
    {SYSCALL_EVENT_RENAMEAT2, 1 /* RENAME_NOREPLACE */, 0, "renameat2"},
    {SYSCALL_EVENT_UNLINK, 0, 0, "unlink"},
};

void run_file()
{
    for (const FileCase& c : kFileCases) {
        struct syscall_event raw = {};
        fill_head(raw, c.name, FILE_EVENT);
        raw.file_event.flags = c.flags;
        raw.file_event.mode  = c.mode;

        hng::syscall_semantic_data out;
        run_one(raw, out);
        check_head(out);
        const auto* d = std::get_if<hng::file_syscall_semantic_data>(&out.data);
        CHECK(d != nullptr, "file variant type");
        if (!d) {
            continue;
        }
        CHECK(d->flags() == c.flags, "file flags");
        CHECK(d->mode() == c.mode, "file mode");
        CHECK(d->syscall_name() == c.name_str, "file syscall_name");
    }
}

// ---- 内存操作 ----

struct MemoryCase {
    enum syscall_event_name name;
    __u64 prot;
    __u64 flags;
    const char* name_str;
};

constexpr MemoryCase kMemoryCases[] = {
    {SYSCALL_EVENT_MMAP, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
     "mmap"},
    {SYSCALL_EVENT_MPROTECT, PROT_EXEC, 0, "mprotect"},
};

void run_memory()
{
    for (const MemoryCase& c : kMemoryCases) {
        struct syscall_event raw = {};
        fill_head(raw, c.name, MEMORY_EVENT);
        raw.memory_event.prot  = c.prot;
        raw.memory_event.flags = c.flags;

        hng::syscall_semantic_data out;
        run_one(raw, out);
        check_head(out);
        const auto* d = std::get_if<hng::memory_semantic_data>(&out.data);
        CHECK(d != nullptr, "memory variant type");
        if (!d) {
            continue;
        }
        CHECK(d->prot() == c.prot, "memory prot");
        CHECK(d->flags() == c.flags, "memory flags");
        CHECK(d->syscall_name() == c.name_str, "memory syscall_name");
    }
}

// ---- 网络连接 ----

struct NetworkCase {
    enum syscall_event_name name;
    __u32 family;
    __u32 type;
    __u32 protocol;
    const char* name_str;
};

constexpr NetworkCase kNetworkCases[] = {
    {SYSCALL_EVENT_SOCKET, AF_INET, SOCK_STREAM, IPPROTO_TCP, "socket"},
    {SYSCALL_EVENT_CONNECT, AF_INET6, 0, 0, "connect"},
    {SYSCALL_EVENT_BIND, AF_UNIX, 0, 0, "bind"},
};

void run_network()
{
    for (const NetworkCase& c : kNetworkCases) {
        struct syscall_event raw = {};
        fill_head(raw, c.name, NETWORK_EVENT);
        raw.network_event.family   = c.family;
        raw.network_event.type     = c.type;
        raw.network_event.protocol = c.protocol;

        hng::syscall_semantic_data out;
        run_one(raw, out);
        check_head(out);
        const auto* d =
            std::get_if<hng::network_syscall_semantic_data>(&out.data);
        CHECK(d != nullptr, "network variant type");
        if (!d) {
            continue;
        }
        CHECK(d->family() == c.family, "network family");
        CHECK(d->type() == c.type, "network type");
        CHECK(d->protocol() == c.protocol, "network protocol");
        CHECK(d->syscall_name() == c.name_str, "network syscall_name");
    }
}

// ---- 内核操作 ----

struct KernelCase {
    enum syscall_event_name name;
    __u32 command;
    __u64 arg;
    const char* name_str;
};

constexpr KernelCase kKernelCases[] = {
    {SYSCALL_EVENT_PTRACE, PTRACE_PEEKDATA, 999, "ptrace"},
    {SYSCALL_EVENT_BPF, 0, 4096, "bpf"},  // 0 = BPF_MAP_CREATE
};

void run_kernel()
{
    for (const KernelCase& c : kKernelCases) {
        struct syscall_event raw = {};
        fill_head(raw, c.name, KERNEL_EVENT);
        raw.kernel_event.command = c.command;
        raw.kernel_event.arg     = c.arg;

        hng::syscall_semantic_data out;
        run_one(raw, out);
        check_head(out);
        const auto* d = std::get_if<hng::kernel_semantic_data>(&out.data);
        CHECK(d != nullptr, "kernel variant type");
        if (!d) {
            continue;
        }
        CHECK(d->command() == c.command, "kernel command");
        CHECK(d->arg() == c.arg, "kernel arg");
        CHECK(d->syscall_name() == c.name_str, "kernel syscall_name");
    }
}

}  // namespace

int main()
{
    run_process();
    run_exec();
    run_credential();
    run_namespace();
    run_file();
    run_memory();
    run_network();
    run_kernel();

    if (g_fail) {
        std::fprintf(stderr, "TOTAL FAILURES: %d\n", g_fail);
        return 1;
    }
    std::printf(
        "ALL PASS (process=%zu exec=%zu credential=%zu namespace=%zu file=%zu "
        "memory=%zu network=%zu kernel=%zu)\n",
        sizeof(kProcessCases) / sizeof(ProcessCase),
        sizeof(kExecCases) / sizeof(ExecCase),
        sizeof(kCredentialCases) / sizeof(CredentialCase),
        sizeof(kNamespaceCases) / sizeof(NamespaceCase),
        sizeof(kFileCases) / sizeof(FileCase),
        sizeof(kMemoryCases) / sizeof(MemoryCase),
        sizeof(kNetworkCases) / sizeof(NetworkCase),
        sizeof(kKernelCases) / sizeof(KernelCase));
    return 0;
}
