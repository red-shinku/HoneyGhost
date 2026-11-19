/**
 * @file test_semantic_syscall.cc
 * @brief 系统调用语义化表驱动单元测试
 * @details
 * 按 hdr.subtype 的九类事件各一张表，经公开纯转换接口 transform_one 断言输出
 * 语义事件：variant 类型、关键字段、syscall_name 字符串，以及 exec 的
 * image 归一化 / 语义化、invoked 原样搬运、credential 按 kind 分派的
 * requested / capset 展开与通用事件头字段搬运。
 *
 * @author red_shinku
 * @date 2026.08.17
 */

#include "agent/semantic/src/semantic.hpp"
#include "kernel/include/syscall_event_type.h"

#include <fcntl.h>
#include <netinet/in.h>
#include <sys/mman.h>
#include <sys/prctl.h>
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

// ---- 纯转换辅助 ----

/**
 * @brief 单条原始事件 → 语义事件（经公开纯转换接口 transform_one）
 */
void run_one(const struct syscall_event& raw, hng::syscall_semantic_data& out)
{
    Semantic_syscall sem;
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
    raw.hdr.head.uid             = 1000;
    raw.hdr.head.euid            = 0;
    raw.hdr.head.mnt_ns          = 4026532222;
    raw.hdr.head.ret             = 0;
    std::memset(raw.hdr.head.comm, 0, sizeof(raw.hdr.head.comm));
    std::strncpy(raw.hdr.head.comm, "bash", sizeof(raw.hdr.head.comm) - 1);
    raw.hdr.name    = name;
    raw.hdr.subtype = type;
}

/**
 * @brief 断言身份头部与语义子类型原样搬运
 */
void check_head(const struct syscall_event& raw,
                const hng::syscall_semantic_data& out)
{
    CHECK(out.head.pid == 1234, "head pid");
    CHECK(out.head.pid_start_time == 111, "head pid_start_time");
    CHECK(out.head.ppid == 100, "head ppid");
    CHECK(out.head.ppid_start_time == 222, "head ppid_start_time");
    CHECK(out.head.type == hng::EventType::SYSCALL_EVENT, "head type");
    CHECK(out.head.subtype == raw.hdr.subtype, "head subtype");
    CHECK(out.head.uid == 1000, "head uid");
    CHECK(out.head.euid == 0, "head euid");
    CHECK(out.head.mnt_ns == 4026532222, "head mnt_ns");
    CHECK(out.head.ret == 0, "head ret");
    CHECK(out.head.comm == "bash", "head comm");
}

// ---- 进程生命周期 ----

struct ProcessCase {
    enum syscall_event_name name;
    __s32 exit_code;
    const char* name_str;
    __u8 derived_flags      = 0;
    __s32 exit_signal       = 0;
    const char* old_comm    = "";
    const char* new_comm    = "";
    const char* cgroup_path = "";
    __u32 target_pid        = 0;
};

constexpr ProcessCase kProcessCases[] = {
    {SYSCALL_EVENT_FORK, 0, "fork"},
    {SYSCALL_EVENT_CLONE, 0, "clone"},  // 枚举保留，诞生事件统一归 "fork"
    {SYSCALL_EVENT_VFORK, 0, "vfork"},
    {SYSCALL_EVENT_EXIT_GROUP, -1, "exit_group", 0, 9},
    // 进程诞生派生位：共享地址空间 + CLONE_PARENT
    {SYSCALL_EVENT_FORK, 0, "fork", 0x3},
    // task_rename 携带改名前后进程名
    {SYSCALL_EVENT_TASK_RENAME, 0, "task_rename", 0, 0, "bash", "nginx"},
    // cgroup_attach_task 携带目标 cgroup 路径与被迁移的 pid
    {SYSCALL_EVENT_CGROUP_ATTACH_TASK, 0, "cgroup_attach_task", 0, 0, "", "",
     "/system.slice/nginx.service", 4242},
    // task_rename 携带被改名任务的 pid
    {SYSCALL_EVENT_TASK_RENAME, 0, "task_rename", 0, 0, "bash", "nginx", "",
     4243},
};

void run_process()
{
    for (const ProcessCase& c : kProcessCases) {
        struct syscall_event raw = {};
        fill_head(raw, c.name, PROCESS_EVENT);
        raw.process_event.exit_code     = c.exit_code;
        raw.process_event.derived_flags = c.derived_flags;
        raw.process_event.exit_signal   = c.exit_signal;
        std::strncpy(raw.process_event.old_comm, c.old_comm,
                     sizeof(raw.process_event.old_comm) - 1);
        std::strncpy(raw.process_event.new_comm, c.new_comm,
                     sizeof(raw.process_event.new_comm) - 1);
        std::strncpy(raw.process_event.cgroup_path, c.cgroup_path,
                     sizeof(raw.process_event.cgroup_path) - 1);
        raw.process_event.target_pid = c.target_pid;

        hng::syscall_semantic_data out;
        run_one(raw, out);
        check_head(raw, out);
        const auto* d = std::get_if<hng::process_semantic_data>(&out.data);
        CHECK(d != nullptr, "process variant type");
        if (!d) {
            continue;
        }
        CHECK(d->exit_code() == c.exit_code, "process exit_code");
        CHECK(d->derived_flags() == c.derived_flags, "process derived_flags");
        CHECK(d->exit_signal() == c.exit_signal, "process exit_signal");
        CHECK(d->old_comm() == c.old_comm, "process old_comm");
        CHECK(d->new_comm() == c.new_comm, "process new_comm");
        CHECK(d->cgroup_path() == c.cgroup_path, "process cgroup_path");
        CHECK(d->target_pid() == c.target_pid, "process target_pid");
        CHECK(d->syscall_name() == c.name_str, "process syscall_name");
    }
}

// ---- 执行事件 ----

struct ExecCase {
    enum syscall_event_name name;
    const char* invoked;  ///< 用户原始串，期望原样搬运
    const char* image;    ///< 内核解析出的绝对路径，期望先 normalize
    const char* argv0;
    const char* argv1;
    const char* argv2;
    const char* argv3;
    const char* ld_preload;
    const char* ld_library_path;
    __u32 flags;
    __u32 image_flags;
    const char* expect_image;  ///< normalize 之后的 image
    const char* expect_sem;    ///< 再语义化之后的 semantic_filename
    const char* name_str;
};

constexpr ExecCase kExecCases[] = {
    // 绝对路径原样保留，invoked 与 image 相同；argv 只到第二项
    {SYSCALL_EVENT_EXECVE, "/bin/bash", "/bin/bash", "bash", "deploy.sh", "", "",
     "", "", 0, 0, "/bin/bash", "/bin/bash", "execve"},
    // //、.、尾斜杠被 normalize；实例片段再被语义化；invoked 保留相对写法
    {SYSCALL_EVENT_EXECVE, "bash", "/tmp//./abc123def456/", "tmpbin", "", "", "",
     "", "", 0, 0, "/tmp/abc123def456", "/tmp/*", "execve"},
    // execveat：AT_* 标志、image_flags、argv2/argv3 与两个 LD_* 一并透传
    {SYSCALL_EVENT_EXECVEAT, "/proc/1234/cmdline", "/proc/1234/cmdline", "p",
     "-c", "--flag", "value", "/tmp/inject.so", "/opt/lib", 0x100, PATH_TRUNCATED,
     "/proc/1234/cmdline", "/proc/{pid}/**", "execveat"},
    // .. 归一化
    {SYSCALL_EVENT_EXECVE, "x", "/a//b/../c", "x", "", "", "", "", "", 0, 0,
     "/a/c", "/a/c", "execve"},
    // image 为空（无法解析）：image/semantic_filename 均留空，invoked 仍然搬运
    {SYSCALL_EVENT_EXECVE, "./run.sh", "", "run.sh", "", "", "", "", "", 0,
     PATH_UNRESOLVED, "", "", "execve"},
};

void run_exec()
{
    for (const ExecCase& c : kExecCases) {
        struct syscall_event raw = {};
        fill_head(raw, c.name, EXEC_EVENT);
        std::strncpy(raw.exec_event.invoked, c.invoked,
                     sizeof(raw.exec_event.invoked) - 1);
        std::strncpy(raw.exec_event.image, c.image,
                     sizeof(raw.exec_event.image) - 1);
        std::strncpy(raw.exec_event.argv0, c.argv0,
                     sizeof(raw.exec_event.argv0) - 1);
        std::strncpy(raw.exec_event.argv1, c.argv1,
                     sizeof(raw.exec_event.argv1) - 1);
        std::strncpy(raw.exec_event.argv2, c.argv2,
                     sizeof(raw.exec_event.argv2) - 1);
        std::strncpy(raw.exec_event.argv3, c.argv3,
                     sizeof(raw.exec_event.argv3) - 1);
        std::strncpy(raw.exec_event.ld_preload, c.ld_preload,
                     sizeof(raw.exec_event.ld_preload) - 1);
        std::strncpy(raw.exec_event.ld_library_path, c.ld_library_path,
                     sizeof(raw.exec_event.ld_library_path) - 1);
        raw.exec_event.flags       = c.flags;
        raw.exec_event.image_flags = c.image_flags;

        hng::syscall_semantic_data out;
        run_one(raw, out);
        check_head(raw, out);
        const auto* d = std::get_if<hng::exec_semantic_data>(&out.data);
        CHECK(d != nullptr, "exec variant type");
        if (!d) {
            continue;
        }
        CHECK(d->image() == c.expect_image, "exec image");
        CHECK(d->semantic_filename() == c.expect_sem, "exec semantic_filename");
        CHECK(d->invoked() == c.invoked, "exec invoked keeps raw input");
        CHECK(d->image_flags() == c.image_flags, "exec image_flags");
        CHECK(d->argv0() == c.argv0, "exec argv0");
        CHECK(d->argv1() == c.argv1, "exec argv1");
        CHECK(d->argv2() == c.argv2, "exec argv2");
        CHECK(d->argv3() == c.argv3, "exec argv3");
        CHECK(d->ld_preload() == c.ld_preload, "exec ld_preload");
        CHECK(d->ld_library_path() == c.ld_library_path, "exec ld_library_path");
        CHECK(d->flags() == c.flags, "exec flags");
        CHECK(d->syscall_name() == c.name_str, "exec syscall_name");
    }
}

// ---- 权限变更 ----

struct CredentialCase {
    enum syscall_event_name name;
    __u32 kind;
    __u32 count;
    __u32 requested[3];
    __u64 cap_eff, cap_perm, cap_inh;
    const char* name_str;
    __u32 prctl_option = 0;
    __u64 arg2         = 0;
    __u32 securebits   = 0;
};

constexpr CredentialCase kCredentialCases[] = {
    // 三类请求：UID 单值、GID 单值、Capability 集合
    {SYSCALL_EVENT_SETUID, CREDENTIAL_UID, 1, {1000, 0, 0}, 0, 0, 0, "setuid"},
    {SYSCALL_EVENT_SETGID, CREDENTIAL_GID, 1, {2000, 0, 0}, 0, 0, 0, "setgid"},
    {SYSCALL_EVENT_CAPSET, CREDENTIAL_CAPS, 0, {}, 0x1, 0x2, 0x4, "capset"},
    {SYSCALL_EVENT_SETREUID,
     CREDENTIAL_UID,
     2,
     {1000, 0, 0},
     0,
     0,
     0,
     "setreuid"},
    // prctl 只收安全相关 option：arg2 与 securebits 一并搬运
    {SYSCALL_EVENT_PRCTL,
     CREDENTIAL_PRCTL,
     0,
     {},
     0,
     0,
     0,
     "prctl",
     PR_SET_SECUREBITS,
     0x3f,
     0x3f},
};

void run_credential()
{
    for (const CredentialCase& c : kCredentialCases) {
        struct syscall_event raw = {};
        fill_head(raw, c.name, CREDENTIAL_EVENT);
        raw.credential_event.kind            = c.kind;
        raw.credential_event.requested_count = c.count;
        for (__u32 i = 0; i < 3; ++i) {
            raw.credential_event.requested[i] = c.requested[i];
        }
        raw.credential_event.cap_effective   = c.cap_eff;
        raw.credential_event.cap_permitted   = c.cap_perm;
        raw.credential_event.cap_inheritable = c.cap_inh;
        raw.credential_event.prctl_option    = c.prctl_option;
        raw.credential_event.arg2            = c.arg2;
        raw.credential_event.securebits      = c.securebits;

        hng::syscall_semantic_data out;
        run_one(raw, out);
        check_head(raw, out);
        const auto* d = std::get_if<hng::credential_semantic_data>(&out.data);
        CHECK(d != nullptr, "credential variant type");
        if (!d) {
            continue;
        }
        CHECK(d->syscall_name() == c.name_str, "credential syscall_name");
        CHECK(d->kind() == c.kind, "credential kind");
        CHECK(d->requested_size() == static_cast<int>(c.count),
              "credential requested count");
        for (__u32 i = 0; i < c.count; ++i) {
            CHECK(d->requested(i) == c.requested[i],
                  "credential requested value");
        }
        if (c.kind == CREDENTIAL_CAPS) {
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
        else {
            CHECK(!d->has_capset(), "credential non-capset has no capset");
        }
        if (c.kind == CREDENTIAL_PRCTL) {
            CHECK(d->prctl_option() == c.prctl_option, "credential prctl_option");
            CHECK(d->arg2() == c.arg2, "credential prctl arg2");
            CHECK(d->securebits() == c.securebits, "credential prctl securebits");
        }
    }
}

// ---- 命名空间 ----

struct NamespaceCase {
    enum syscall_event_name name;
    __u64 flags;
    __u32 ns_mask;
    __s32 fd;
    const char* name_str;
    const char* source     = "";
    const char* target     = "";
    __u32 source_flags     = 0;
    __u32 target_flags     = 0;
    const char* fstype     = "";
    __u64 mount_flags      = 0;
    const char* expect_src = "";
    const char* expect_dst = "";
};

constexpr NamespaceCase kNamespaceCases[] = {
    // unshare 一次新建多个命名空间：0x10000000 = CLONE_NEWUSER，
    // 0x40000000 = CLONE_NEWNET
    {SYSCALL_EVENT_UNSHARE, 0x50000000, 0x50000000, -1, "unshare"},
    // setns 只涉及单个命名空间类型，目标 fd 由 args[0] 给出
    {SYSCALL_EVENT_SETNS, 0, 0x40000000, 5, "setns"},
    // mount：两条路径都 normalize，fstype 与 MS_* 原样搬运
    {SYSCALL_EVENT_MOUNT, 0, 0, -1, "mount", "/dev//sda1", "/mnt/./data", 0, 0,
     "ext4", 0x1, "/dev/sda1", "/mnt/data"},
    // chroot：路径只装入 target；解析失败时保留原始串并透传状态位
    {SYSCALL_EVENT_CHROOT, 0, 0, -1, "chroot", "", "rel/newroot", 0,
     PATH_UNRESOLVED, "", 0, "", "rel/newroot"},
};

void run_namespace()
{
    for (const NamespaceCase& c : kNamespaceCases) {
        struct syscall_event raw = {};
        fill_head(raw, c.name, NAMESPACE_EVENT);
        raw.namespace_event.flags        = c.flags;
        raw.namespace_event.ns_mask      = c.ns_mask;
        raw.namespace_event.fd           = c.fd;
        raw.namespace_event.source_flags = c.source_flags;
        raw.namespace_event.target_flags = c.target_flags;
        raw.namespace_event.mount_flags  = c.mount_flags;
        std::strncpy(raw.namespace_event.source, c.source,
                     sizeof(raw.namespace_event.source) - 1);
        std::strncpy(raw.namespace_event.target, c.target,
                     sizeof(raw.namespace_event.target) - 1);
        std::strncpy(raw.namespace_event.fstype, c.fstype,
                     sizeof(raw.namespace_event.fstype) - 1);

        hng::syscall_semantic_data out;
        run_one(raw, out);
        check_head(raw, out);
        const auto* d = std::get_if<hng::namespace_semantic_data>(&out.data);
        CHECK(d != nullptr, "namespace variant type");
        if (!d) {
            continue;
        }
        CHECK(d->ns_mask() == c.ns_mask, "namespace ns_mask");
        CHECK(d->flags() == c.flags, "namespace flags");
        CHECK(d->fd() == c.fd, "namespace fd");
        CHECK(d->source() == c.expect_src, "namespace source");
        CHECK(d->target() == c.expect_dst, "namespace target");
        CHECK(d->source_flags() == c.source_flags, "namespace source_flags");
        CHECK(d->target_flags() == c.target_flags, "namespace target_flags");
        CHECK(d->fstype() == c.fstype, "namespace fstype");
        CHECK(d->mount_flags() == c.mount_flags, "namespace mount_flags");
        CHECK(d->syscall_name() == c.name_str, "namespace syscall_name");
    }
}

// ---- 文件系统调用 ----

struct FileCase {
    enum syscall_event_name name;
    const char* path1;
    const char* path2;
    __u32 flags;
    __u32 mode;
    __u32 path1_flags;
    __u32 path2_flags;
    __s32 dirfd;
    __s32 dirfd2;
    const char* expect_path1;
    const char* expect_path2;
    const char* name_str;
    __u32 at_flags = 0;
    __u64 resolve  = 0;
    __s64 length   = 0;
    __u32 dev      = 0;
    __s32 fd       = -1;
};

constexpr FileCase kFileCases[] = {
    // open：唯一路径在 path1，两个 dirfd 都是 AT_FDCWD
    {SYSCALL_EVENT_OPEN, "/tmp/../etc/./passwd", "", O_CREAT | O_WRONLY | O_TRUNC,
     0644, 0, 0, AT_FDCWD, AT_FDCWD, "/etc/passwd", "", "open"},
    // renameat2：源与目标各自带 dirfd，两条路径都 normalize
    {SYSCALL_EVENT_RENAMEAT2, "/a//b/../c", "/x/./y", 1 /* RENAME_NOREPLACE */, 0,
     0, 0, 5, 6, "/a/c", "/x/y", "renameat2"},
    // unlink：P4b 起带 path1
    {SYSCALL_EVENT_UNLINK, "/tmp/gone", "", 0, 0, 0, 0, AT_FDCWD, AT_FDCWD,
     "/tmp/gone", "", "unlink"},
    // 内核侧无法解析为绝对路径：path1 保留原始串，未解析位透传
    {SYSCALL_EVENT_OPENAT, "../etc/shadow", "", O_RDONLY, 0, PATH_UNRESOLVED, 0,
     3, AT_FDCWD, "../etc/shadow", "", "openat"},
    // 截断位与路径前缀一并透传
    {SYSCALL_EVENT_OPEN, "/tmp", "", O_RDONLY, 0, PATH_TRUNCATED, 0, AT_FDCWD,
     AT_FDCWD, "/tmp", "", "open"},
    // link：新名无法解析时只有 path2 带未解析位与原始串
    {SYSCALL_EVENT_LINK, "/tmp/src", "rel/new", 0, 0, 0, PATH_UNRESOLVED,
     AT_FDCWD, AT_FDCWD, "/tmp/src", "rel/new", "link"},
    // truncate：目标长度原样搬运
    {SYSCALL_EVENT_TRUNCATE, "/tmp/f", "", 0, 0, 0, 0, AT_FDCWD, AT_FDCWD,
     "/tmp/f", "", "truncate", 0, 0, 4096},
    // mknod：设备号原样搬运
    {SYSCALL_EVENT_MKNOD, "/tmp/dev", "", 0, 0600, 0, 0, AT_FDCWD, AT_FDCWD,
     "/tmp/dev", "", "mknod", 0, 0, 0, 0x1234},
    // fchmod 没有路径，只有 fd 与权限位
    {SYSCALL_EVENT_FCHMOD, "", "", 0, 0644, 0, 0, AT_FDCWD, AT_FDCWD, "", "",
     "fchmod", 0, 0, 0, 0, 3},
    // memfd_create：path1 带 memfd: 前缀且不置解析位（normalize 保持原样）
    {SYSCALL_EVENT_MEMFD_CREATE, "memfd:payload", "", 0, 0, 0, 0, AT_FDCWD,
     AT_FDCWD, "memfd:payload", "", "memfd_create"},
};

void run_file()
{
    for (const FileCase& c : kFileCases) {
        struct syscall_event raw = {};
        fill_head(raw, c.name, FILE_EVENT);
        std::strncpy(raw.file_event.path1, c.path1,
                     sizeof(raw.file_event.path1) - 1);
        std::strncpy(raw.file_event.path2, c.path2,
                     sizeof(raw.file_event.path2) - 1);
        raw.file_event.flags       = c.flags;
        raw.file_event.mode        = c.mode;
        raw.file_event.path1_flags = c.path1_flags;
        raw.file_event.path2_flags = c.path2_flags;
        raw.file_event.dirfd       = c.dirfd;
        raw.file_event.dirfd2      = c.dirfd2;
        raw.file_event.at_flags    = c.at_flags;
        raw.file_event.resolve     = c.resolve;
        raw.file_event.length      = c.length;
        raw.file_event.dev         = c.dev;
        raw.file_event.fd          = c.fd;

        hng::syscall_semantic_data out;
        run_one(raw, out);
        check_head(raw, out);
        const auto* d = std::get_if<hng::file_syscall_semantic_data>(&out.data);
        CHECK(d != nullptr, "file variant type");
        if (!d) {
            continue;
        }
        CHECK(d->path1() == c.expect_path1, "file path1");
        CHECK(d->path2() == c.expect_path2, "file path2");
        CHECK(d->flags() == c.flags, "file flags");
        CHECK(d->mode() == c.mode, "file mode");
        CHECK(d->path1_flags() == c.path1_flags, "file path1_flags");
        CHECK(d->path2_flags() == c.path2_flags, "file path2_flags");
        CHECK(d->dirfd() == c.dirfd, "file dirfd");
        CHECK(d->dirfd2() == c.dirfd2, "file dirfd2");
        CHECK(d->at_flags() == c.at_flags, "file at_flags");
        CHECK(d->resolve() == c.resolve, "file resolve");
        CHECK(d->length() == c.length, "file length");
        CHECK(d->dev() == c.dev, "file dev");
        CHECK(d->fd() == c.fd, "file fd");
        CHECK(hng::has_unresolved_path(raw) ==
                  (((c.path1_flags | c.path2_flags) & PATH_UNRESOLVED) != 0),
              "file unresolved predicate");
        CHECK(d->syscall_name() == c.name_str, "file syscall_name");
    }
}

/// @brief open_by_handle_at 的文件句柄按原始 16 字节搬运（不是字符串）
void run_file_handle()
{
    struct syscall_event raw = {};
    fill_head(raw, SYSCALL_EVENT_OPEN_BY_HANDLE_AT, FILE_EVENT);
    raw.file_event.dirfd    = 3;
    raw.file_event.fd       = 3;
    raw.file_event.at_flags = 0x100;
    for (int i = 0; i < static_cast<int>(sizeof(raw.file_event.handle)); ++i) {
        raw.file_event.handle[i] = static_cast<__u8>(i + 1);
    }

    hng::syscall_semantic_data out;
    run_one(raw, out);
    check_head(raw, out);
    const auto* d = std::get_if<hng::file_syscall_semantic_data>(&out.data);
    CHECK(d != nullptr, "file handle variant type");
    if (!d) {
        return;
    }
    CHECK(d->handle().size() == 16, "file handle length");
    for (int i = 0; i < 16 && i < d->handle().size(); ++i) {
        CHECK(static_cast<__u8>(d->handle()[i]) == static_cast<__u8>(i + 1),
              "file handle bytes");
    }
    CHECK(d->syscall_name() == "open_by_handle_at", "file handle syscall_name");
}

/// @brief path_unresolved 的计数判据：只认文件事件，且两条路径任一未解析即算
void run_unresolved_predicate()
{
    struct syscall_event raw = {};
    fill_head(raw, SYSCALL_EVENT_OPENAT, FILE_EVENT);
    std::strncpy(raw.file_event.path1, "rel/x", sizeof(raw.file_event.path1) - 1);
    std::strncpy(raw.file_event.path2, "rel/y", sizeof(raw.file_event.path2) - 1);

    raw.file_event.path1_flags = PATH_UNRESOLVED | PATH_TRUNCATED;
    CHECK(hng::has_unresolved_path(raw), "unresolved bit counts");
    raw.file_event.path1_flags = PATH_TRUNCATED;
    CHECK(!hng::has_unresolved_path(raw), "truncated bit does not count");
    raw.file_event.path1_flags = 0;
    CHECK(!hng::has_unresolved_path(raw), "resolved path does not count");
    raw.file_event.path2_flags = PATH_UNRESOLVED;
    CHECK(hng::has_unresolved_path(raw), "path2 unresolved counts");
    raw.file_event.path2_flags = 0;
    raw.file_event.path1_flags = PATH_UNRESOLVED;
    raw.hdr.subtype            = EXEC_EVENT;
    CHECK(!hng::has_unresolved_path(raw), "non-file subtype does not count");
}

// ---- 内存操作 ----

struct MemoryCase {
    enum syscall_event_name name;
    __u64 prot;
    __u64 flags;
    __u64 addr;
    __u64 length;
    __u64 offset;
    __s32 fd;
    bool anonymous;
    bool wx;
    const char* path;
    __u32 path_flags;
    const char* expect_path;  ///< path 经 normalize 之后
    const char* name_str;
};

constexpr MemoryCase kMemoryCases[] = {
    // 匿名 mmap：无源文件，path 为空、fd 为 -1
    {SYSCALL_EVENT_MMAP, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
     0x7f0000000000ULL, 4096, 0, -1, true, false, "", 0, "", "mmap"},
    // 文件 mmap：路径经 normalize，offset 记录区段起点
    {SYSCALL_EVENT_MMAP, PROT_READ, MAP_PRIVATE, 0, 8192, 4096, 3, false, false,
     "/usr//lib/./libc.so.6", 0, "/usr/lib/libc.so.6", "mmap"},
    // mprotect：没有源 fd 与 offset，W|X 同时置位
    {SYSCALL_EVENT_MPROTECT, PROT_READ | PROT_WRITE | PROT_EXEC, 0, 0x401000,
     2048, 0, -1, false, true, "", 0, "", "mprotect"},
    // 路径解析失败：path 为空串，未解析位透传
    {SYSCALL_EVENT_MMAP, PROT_WRITE, MAP_SHARED, 0, 4096, 0, 5, false, false, "",
     PATH_UNRESOLVED, "", "mmap"},
    // mremap：prot 为 0、fd 为 -1，记录 old_size 与 MREMAP_* 标志
    {SYSCALL_EVENT_MREMAP, 0, 1 /* MREMAP_MAYMOVE */, 0x7f0000000000ULL, 8192, 0,
     -1, false, false, "", 0, "", "mremap"},
    // munmap：只记录地址与长度
    {SYSCALL_EVENT_MUNMAP, 0, 0, 0x401000, 4096, 0, -1, false, false, "", 0, "",
     "munmap"},
};

void run_memory()
{
    for (const MemoryCase& c : kMemoryCases) {
        struct syscall_event raw = {};
        fill_head(raw, c.name, MEMORY_EVENT);
        raw.memory_event.prot       = c.prot;
        raw.memory_event.flags      = c.flags;
        raw.memory_event.addr       = c.addr;
        raw.memory_event.length     = c.length;
        raw.memory_event.offset     = c.offset;
        raw.memory_event.fd         = c.fd;
        raw.memory_event.anonymous  = c.anonymous ? 1 : 0;
        raw.memory_event.wx         = c.wx ? 1 : 0;
        raw.memory_event.path_flags = c.path_flags;
        std::strncpy(raw.memory_event.path, c.path,
                     sizeof(raw.memory_event.path) - 1);

        hng::syscall_semantic_data out;
        run_one(raw, out);
        check_head(raw, out);
        const auto* d = std::get_if<hng::memory_semantic_data>(&out.data);
        CHECK(d != nullptr, "memory variant type");
        if (!d) {
            continue;
        }
        CHECK(d->prot() == c.prot, "memory prot");
        CHECK(d->flags() == c.flags, "memory flags");
        CHECK(d->addr() == c.addr, "memory addr");
        CHECK(d->length() == c.length, "memory length");
        CHECK(d->offset() == c.offset, "memory offset");
        CHECK(d->fd() == c.fd, "memory fd");
        CHECK(d->anonymous() == c.anonymous, "memory anonymous");
        CHECK(d->wx() == c.wx, "memory wx");
        CHECK(d->path() == c.expect_path, "memory path");
        CHECK(d->path_flags() == c.path_flags, "memory path_flags");
        CHECK(d->syscall_name() == c.name_str, "memory syscall_name");
    }
}

// ---- 网络连接 ----

struct NetworkCase {
    enum syscall_event_name name;
    __u32 family;
    __u32 type;
    __u32 protocol;
    __u32 dst_ip[4];
    __u16 dst_port;
    __u16 src_port;
    __s32 sockfd;
    __u64 count;
    const char* unix_path;
    const char* name_str;
    __u32 src_ip[4] = {0, 0, 0, 0};
    __s32 backlog   = 0;
    __u32 flags     = 0;
};

// dst_ip 按内核记录的网络字节序存放（主机为小端）：
// 0x0a01a8c0 = 192.168.1.10，0xb80d0120/0x01000000 = 2001:db8::1
constexpr NetworkCase kNetworkCases[] = {
    // socket：新 fd 在返回值里，sockfd 为 -1
    {SYSCALL_EVENT_SOCKET,
     AF_INET,
     SOCK_STREAM,
     IPPROTO_TCP,
     {0, 0, 0, 0},
     0,
     0,
     -1,
     0,
     "",
     "socket"},
    {SYSCALL_EVENT_CONNECT,
     AF_INET,
     SOCK_STREAM,
     IPPROTO_TCP,
     {0x0a01a8c0, 0, 0, 0},
     443,
     50000,
     3,
     0,
     "",
     "connect"},
    // sendto 的 count 是本次发送的字节数
    {SYSCALL_EVENT_SENDTO,
     AF_INET6,
     SOCK_DGRAM,
     IPPROTO_UDP,
     {0xb80d0120, 0, 0, 0x01000000},
     53,
     40000,
     4,
     512,
     "",
     "sendto"},
    // AF_UNIX：目标不是 IP，dst_ip/端口为 0，sun_path 带上抽象命名空间前缀
    {SYSCALL_EVENT_CONNECT,
     AF_UNIX,
     SOCK_STREAM,
     0,
     {0, 0, 0, 0},
     0,
     0,
     5,
     0,
     "@/run/dbus",
     "connect"},
    // recvfrom：来源地址填入 src_ip/src_port，count 是本次接收的字节数
    {SYSCALL_EVENT_RECVFROM,
     AF_INET,
     SOCK_DGRAM,
     IPPROTO_UDP,
     {0, 0, 0, 0},
     0,
     443,
     3,
     512,
     "",
     "recvfrom",
     {0x0a01a8c0, 0, 0, 0}},
    // listen：backlog 原样搬运
    {SYSCALL_EVENT_LISTEN,
     AF_INET,
     SOCK_STREAM,
     IPPROTO_TCP,
     {0, 0, 0, 0},
     0,
     0,
     5,
     0,
     "",
     "listen",
     {0, 0, 0, 0},
     128},
    // accept4：args[3] 的 SOCK_* 标志落在专用字段，type 保持套接字类型语义
    {SYSCALL_EVENT_ACCEPT4,
     AF_INET,
     0,
     0,
     {0, 0, 0, 0},
     0,
     0,
     6,
     0,
     "",
     "accept4",
     {0, 0, 0, 0},
     0,
     0x800 /* SOCK_NONBLOCK */},
};

void run_network()
{
    for (const NetworkCase& c : kNetworkCases) {
        struct syscall_event raw = {};
        fill_head(raw, c.name, NETWORK_EVENT);
        raw.network_event.family   = c.family;
        raw.network_event.type     = c.type;
        raw.network_event.protocol = c.protocol;
        for (int i = 0; i < 4; ++i) {
            raw.network_event.dst_ip[i] = c.dst_ip[i];
            raw.network_event.src_ip[i] = c.src_ip[i];
        }
        raw.network_event.dst_port = c.dst_port;
        raw.network_event.src_port = c.src_port;
        raw.network_event.sockfd   = c.sockfd;
        raw.network_event.count    = c.count;
        raw.network_event.backlog  = c.backlog;
        raw.network_event.flags    = c.flags;
        std::strncpy(raw.network_event.unix_path, c.unix_path,
                     sizeof(raw.network_event.unix_path) - 1);

        hng::syscall_semantic_data out;
        run_one(raw, out);
        check_head(raw, out);
        const auto* d =
            std::get_if<hng::network_syscall_semantic_data>(&out.data);
        CHECK(d != nullptr, "network variant type");
        if (!d) {
            continue;
        }
        CHECK(d->family() == c.family, "network family");
        CHECK(d->type() == c.type, "network type");
        CHECK(d->protocol() == c.protocol, "network protocol");
        CHECK(d->dst_ip_size() == 4, "network dst_ip size");
        for (int i = 0; i < 4 && i < d->dst_ip_size(); ++i) {
            CHECK(d->dst_ip(i) == c.dst_ip[i], "network dst_ip");
        }
        CHECK(d->dst_port() == c.dst_port, "network dst_port");
        CHECK(d->src_port() == c.src_port, "network src_port");
        CHECK(d->sockfd() == c.sockfd, "network sockfd");
        CHECK(d->flags() == c.flags, "network flags");
        CHECK(d->count() == c.count, "network count");
        CHECK(d->src_ip_size() == 4, "network src_ip size");
        for (int i = 0; i < 4 && i < d->src_ip_size(); ++i) {
            CHECK(d->src_ip(i) == c.src_ip[i], "network src_ip");
        }
        CHECK(d->backlog() == c.backlog, "network backlog");
        CHECK(d->unix_path() == c.unix_path, "network unix_path");
        CHECK(d->syscall_name() == c.name_str, "network syscall_name");
    }
}

// ---- 信号发送 ----

struct SignalCase {
    enum syscall_event_name name;
    __u32 sig;
    __u32 target_pid;
    __u32 target_tid;
    __s32 si_code;
    const char* name_str;
};

constexpr SignalCase kSignalCases[] = {
    // kill / tkill 只有目标 pid，没有 tid 与 si_code
    {SYSCALL_EVENT_KILL, 9, 1234, 0, 0, "kill"},
    {SYSCALL_EVENT_TKILL, 15, 55, 0, 0, "tkill"},
    // tgkill 的 pid 是线程组、tid 是具体线程
    {SYSCALL_EVENT_TGKILL, 9, 1, 2, 0, "tgkill"},
    // rt_sigqueueinfo 携带用户给出的 si_code（可为负值）
    {SYSCALL_EVENT_RT_SIGQUEUEINFO, 10, 77, 0, -6, "rt_sigqueueinfo"},
};

void run_signal()
{
    for (const SignalCase& c : kSignalCases) {
        struct syscall_event raw = {};
        fill_head(raw, c.name, SIGNAL_EVENT);
        raw.signal_event.sig        = c.sig;
        raw.signal_event.target_pid = c.target_pid;
        raw.signal_event.target_tid = c.target_tid;
        raw.signal_event.si_code    = c.si_code;

        hng::syscall_semantic_data out;
        run_one(raw, out);
        check_head(raw, out);
        const auto* d = std::get_if<hng::signal_semantic_data>(&out.data);
        CHECK(d != nullptr, "signal variant type");
        if (!d) {
            continue;
        }
        CHECK(d->sig() == c.sig, "signal sig");
        CHECK(d->target_pid() == c.target_pid, "signal target_pid");
        CHECK(d->target_tid() == c.target_tid, "signal target_tid");
        CHECK(d->si_code() == c.si_code, "signal si_code");
        CHECK(d->syscall_name() == c.name_str, "signal syscall_name");
    }
}

// ---- 内核操作 ----

struct KernelCase {
    enum syscall_event_name name;
    __u32 command;
    __u32 target_pid;
    __u64 arg;
    __u32 attr[4];
    __u32 bpf_type;
    const char* name_str;
    const char* module_name = "";
    __u32 module_len        = 0;
    __u64 kexec_entry       = 0;
    __u32 kexec_segments    = 0;
    __u32 reboot_cmd        = 0;
    const char* hostname    = "";
};

constexpr KernelCase kKernelCases[] = {
    // ptrace：目标是 pid，arg 是 POKETEXT 的数据
    {SYSCALL_EVENT_PTRACE,
     PTRACE_POKETEXT,
     4242,
     0x4141414141414141ULL,
     {0, 0, 0, 0},
     0,
     "ptrace"},
    // bpf BPF_MAP_CREATE：attr 前 16 字节原样搬运，类型解出为 map_type=6
    {SYSCALL_EVENT_BPF, 0 /* BPF_MAP_CREATE */, 0, 0, {6, 4, 4, 0}, 6, "bpf"},
    // bpf BPF_PROG_ATTACH：attach_type 在 attr 的第 3 个字
    {SYSCALL_EVENT_BPF, 8 /* BPF_PROG_ATTACH */, 0, 0, {7, 9, 3, 0}, 3, "bpf"},
    // delete_module：模块名与 flags
    {SYSCALL_EVENT_DELETE_MODULE,
     0,
     0,
     1,
     {0, 0, 0, 0},
     0,
     "delete_module",
     "rootkit"},
    // init_module：只记录镜像长度
    {SYSCALL_EVENT_INIT_MODULE,
     0,
     0,
     0,
     {0, 0, 0, 0},
     0,
     "init_module",
     "",
     4096},
    // kexec_load：入口与段数
    {SYSCALL_EVENT_KEXEC_LOAD,
     0,
     0,
     0,
     {0, 0, 0, 0},
     0,
     "kexec_load",
     "",
     0,
     0x1000,
     3},
    // reboot：命令码
    {SYSCALL_EVENT_REBOOT,
     0,
     0,
     0,
     {0, 0, 0, 0},
     0,
     "reboot",
     "",
     0,
     0,
     0,
     0x01234567},
    // sethostname：主机名
    {SYSCALL_EVENT_SETHOSTNAME,
     0,
     0,
     0,
     {0, 0, 0, 0},
     0,
     "sethostname",
     "",
     0,
     0,
     0,
     0,
     "evil"},
};

void run_kernel()
{
    for (const KernelCase& c : kKernelCases) {
        struct syscall_event raw = {};
        fill_head(raw, c.name, KERNEL_EVENT);
        raw.kernel_event.command    = c.command;
        raw.kernel_event.target_pid = c.target_pid;
        raw.kernel_event.arg        = c.arg;
        for (int i = 0; i < 4; ++i) {
            raw.kernel_event.bpf_attr[i] = c.attr[i];
        }
        raw.kernel_event.bpf_type = c.bpf_type;
        std::strncpy(raw.kernel_event.module_name, c.module_name,
                     sizeof(raw.kernel_event.module_name) - 1);
        raw.kernel_event.module_len     = c.module_len;
        raw.kernel_event.kexec_entry    = c.kexec_entry;
        raw.kernel_event.kexec_segments = c.kexec_segments;
        raw.kernel_event.reboot_cmd     = c.reboot_cmd;
        std::strncpy(raw.kernel_event.hostname, c.hostname,
                     sizeof(raw.kernel_event.hostname) - 1);

        hng::syscall_semantic_data out;
        run_one(raw, out);
        check_head(raw, out);
        const auto* d = std::get_if<hng::kernel_semantic_data>(&out.data);
        CHECK(d != nullptr, "kernel variant type");
        if (!d) {
            continue;
        }
        CHECK(d->command() == c.command, "kernel command");
        CHECK(d->target_pid() == c.target_pid, "kernel target_pid");
        CHECK(d->arg() == c.arg, "kernel arg");
        CHECK(d->bpf_attr_size() == 4, "kernel bpf_attr size");
        for (int i = 0; i < 4 && i < d->bpf_attr_size(); ++i) {
            CHECK(d->bpf_attr(i) == c.attr[i], "kernel bpf_attr");
        }
        CHECK(d->bpf_type() == c.bpf_type, "kernel bpf_type");
        CHECK(d->module_name() == c.module_name, "kernel module_name");
        CHECK(d->module_len() == c.module_len, "kernel module_len");
        CHECK(d->kexec_entry() == c.kexec_entry, "kernel kexec_entry");
        CHECK(d->kexec_segments() == c.kexec_segments, "kernel kexec_segments");
        CHECK(d->reboot_cmd() == c.reboot_cmd, "kernel reboot_cmd");
        CHECK(d->hostname() == c.hostname, "kernel hostname");
        CHECK(d->syscall_name() == c.name_str, "kernel syscall_name");
    }
}

// ---- 通用事件头 ----

/// @brief 凭据/命名空间/进程名搬运，以及 comm 定长缓冲的截断规则
void run_head_fields()
{
    struct syscall_event raw = {};
    fill_head(raw, SYSCALL_EVENT_FORK, PROCESS_EVENT);
    raw.hdr.head.ret = -2;
    std::memset(raw.hdr.head.comm, 'z', sizeof(raw.hdr.head.comm));

    hng::syscall_semantic_data out;
    run_one(raw, out);
    CHECK(out.head.ret == -2, "head ret signed copy");
    CHECK(out.head.comm == std::string(sizeof(raw.hdr.head.comm), 'z'),
          "head comm keeps all 16 bytes without NUL");

    std::memset(raw.hdr.head.comm, 0, sizeof(raw.hdr.head.comm));
    out = hng::syscall_semantic_data{};
    run_one(raw, out);
    CHECK(out.head.comm.empty(), "head comm empty");

    // 合法 UTF-8（中文进程名）原样保留
    std::memset(raw.hdr.head.comm, 0, sizeof(raw.hdr.head.comm));
    std::memcpy(raw.hdr.head.comm, "\xe4\xb8\xad\xe6\x96\x87", 6);
    out = hng::syscall_semantic_data{};
    run_one(raw, out);
    CHECK(out.head.comm == "\xe4\xb8\xad\xe6\x96\x87",
          "head comm keeps valid UTF-8");

    // 非法字节逐个替换为 '?'：孤立续字节、非法首字节、被截断的多字节序列
    std::memset(raw.hdr.head.comm, 0, sizeof(raw.hdr.head.comm));
    raw.hdr.head.comm[0] = 'a';
    raw.hdr.head.comm[1] = static_cast<char>(0x80);
    raw.hdr.head.comm[2] = static_cast<char>(0xff);
    raw.hdr.head.comm[3] = static_cast<char>(0xe4);
    raw.hdr.head.comm[4] = static_cast<char>(0xb8);
    std::memset(raw.hdr.head.comm + 5, 0, sizeof(raw.hdr.head.comm) - 5);
    out = hng::syscall_semantic_data{};
    run_one(raw, out);
    CHECK(out.head.comm == "a????", "head comm replaces invalid UTF-8 bytes");
}

}  // namespace

int main()
{
    run_process();
    run_exec();
    run_credential();
    run_namespace();
    run_file();
    run_file_handle();
    run_unresolved_predicate();
    run_memory();
    run_network();
    run_signal();
    run_kernel();
    run_head_fields();

    if (g_fail) {
        std::fprintf(stderr, "TOTAL FAILURES: %d\n", g_fail);
        return 1;
    }
    std::printf(
        "ALL PASS (process=%zu exec=%zu credential=%zu namespace=%zu file=%zu "
        "memory=%zu network=%zu signal=%zu kernel=%zu)\n",
        sizeof(kProcessCases) / sizeof(ProcessCase),
        sizeof(kExecCases) / sizeof(ExecCase),
        sizeof(kCredentialCases) / sizeof(CredentialCase),
        sizeof(kNamespaceCases) / sizeof(NamespaceCase),
        sizeof(kFileCases) / sizeof(FileCase),
        sizeof(kMemoryCases) / sizeof(MemoryCase),
        sizeof(kNetworkCases) / sizeof(NetworkCase),
        sizeof(kSignalCases) / sizeof(SignalCase),
        sizeof(kKernelCases) / sizeof(KernelCase));
    return 0;
}
