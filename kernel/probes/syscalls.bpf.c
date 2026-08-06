/**
 * @file syscalls.bpf.c
 * @brief 监控关键系统调用
 * @details 收集带语义的系统调用信息。
 *  
 * 这个模块收集的数据将用于马尔科夫序列的基线学习，或
 * 结合序列基线进行异常分析。因此获取的信息应当具有语义、能反映行为特征。
 *
 * @author red_shinku
 * @date 2026.08.06
 */

#include "../include/vmlinux.h"
#include "../include/syscall_event_head.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// syscall参数最大长度
#define MAX_ARG_LEN 64
// 可执行程序文件名最大长度
#define MAX_EXEC_FILENAME_LEN 256

struct process_event {
    struct syscall_event_head hdr;

    u64 clone_flags; ///< clone 有效，新进程的创建方式
    s32 exit_code;   ///< exit_group 有效
};

struct exec_event {
    struct syscall_event_head hdr;

    char filename[MAX_EXEC_FILENAME_LEN]; ///< 可执行文件路径
    char argv0[MAX_ARG_LEN];              ///< argv[0]（程序名或启动命令）
    u32 flags;                            ///< execveat 有效，AT_* 标志
};

struct credential_event {
    struct syscall_event_head hdr;

    union {
        struct {
            u32 uid; ///< setuid() 设置的新 UID
        } setuid;

        struct {
            u32 gid; ///< setgid() 设置的新 GID
        } setgid;

        struct {
            u64 effective;    ///< Effective Capability
            u64 permitted;    ///< Permitted Capability
            u64 inheritable;  ///< Inheritable Capability
        } capset;
    };
};

struct namespace_event {
    struct syscall_event_head hdr;

    u32 ns_type; ///< setns() 目标 Namespace 类型（CLONE_NEW*）；或 unshare() 涉及的 Namespace
    u64 flags;   ///< unshare() 的 CLONE_* 标志；setns() 可扩展保存 flags
};

struct file_event {
    struct syscall_event_head hdr;

    // char path1[256]; ///< 主路径（open、unlink、creat、rename 源路径等）
    // char path2[256]; ///< 第二路径（link、rename 等目标路径，无则为空）
    u32 flags;       ///< open/openat/openat2 的 O_* 标志；renameat2 的 RENAME_* 标志
    u32 mode;        ///< creat()/open(O_CREAT) 创建权限；openat2 可扩展保存 mode
};

struct memory_event {
    struct syscall_event_head hdr;

    u64 prot;    ///< PROT_* 权限（mmap/mprotect）
    u64 flags;   ///< MAP_* 标志（mmap）或保留扩展
};

struct network_event {
    struct syscall_event_head hdr;

    u32 family;   ///< AF_INET / AF_INET6 / AF_UNIX 等地址族
    u32 type;     ///< SOCK_STREAM / SOCK_DGRAM 等
    u32 protocol; ///< IPPROTO_TCP 等协议号
};

struct kernel_event {
    struct syscall_event_head hdr;

    u32 command; ///< ptrace 请求类型（PTRACE_*）或 bpf 命令（BPF_*）
    u64 arg;     ///< 与 command 对应的重要参数（可根据事件类型解释）
};

/**
 * @brief RingBuf，存储syscall事件的数据
 *       用户态程序通过该结构获取事件数据
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} syscall_events SEC(".maps");

// ============================================================================
// 各事件类型的初始化函数，分配 ringbuf 空间并初始化事件头。
// ============================================================================

/**
 * @brief process_event 初始化
 * @param name syscall 事件名
 * @return NULL 失败
 * @return struct process_event* 成功
 */
static __always_inline struct process_event* init_process_event(enum syscall_event_name name)
{
    struct process_event *event = bpf_ringbuf_reserve(&syscall_events, sizeof(struct process_event), 0);
    if (!event) {
        return NULL;
    }
    init_syscall_event_head(&event->hdr, name);
    event->clone_flags = 0;
    event->exit_code = 0;
    return event;
}

/**
 * @brief exec_event 初始化
 */
static __always_inline struct exec_event* init_exec_event(enum syscall_event_name name)
{
    struct exec_event *event = bpf_ringbuf_reserve(&syscall_events, sizeof(struct exec_event), 0);
    if (!event) {
        return NULL;
    }
    init_syscall_event_head(&event->hdr, name);
    __builtin_memset(event->filename, 0, sizeof(event->filename));
    __builtin_memset(event->argv0, 0, sizeof(event->argv0));
    event->flags = 0;
    return event;
}

/**
 * @brief credential_event 初始化
 */
static __always_inline struct credential_event* init_credential_event(enum syscall_event_name name)
{
    struct credential_event *event = bpf_ringbuf_reserve(&syscall_events, sizeof(struct credential_event), 0);
    if (!event) {
        return NULL;
    }
    init_syscall_event_head(&event->hdr, name);
    // 联合体整体清零
    event->capset.effective = 0;
    event->capset.permitted = 0;
    event->capset.inheritable = 0;
    return event;
}

/**
 * @brief namespace_event 初始化
 */
static __always_inline struct namespace_event* init_namespace_event(enum syscall_event_name name)
{
    struct namespace_event *event = bpf_ringbuf_reserve(&syscall_events, sizeof(struct namespace_event), 0);
    if (!event) {
        return NULL;
    }
    init_syscall_event_head(&event->hdr, name);
    event->ns_type = 0;
    event->flags = 0;
    return event;
}

/**
 * @brief file_event 初始化
 */
static __always_inline struct file_event* init_file_event(enum syscall_event_name name)
{
    struct file_event *event = bpf_ringbuf_reserve(&syscall_events, sizeof(struct file_event), 0);
    if (!event) {
        return NULL;
    }
    init_syscall_event_head(&event->hdr, name);
    event->flags = 0;
    event->mode = 0;
    return event;
}

/**
 * @brief memory_event 初始化
 */
static __always_inline struct memory_event* init_memory_event(enum syscall_event_name name)
{
    struct memory_event *event = bpf_ringbuf_reserve(&syscall_events, sizeof(struct memory_event), 0);
    if (!event) {
        return NULL;
    }
    init_syscall_event_head(&event->hdr, name);
    event->prot = 0;
    event->flags = 0;
    return event;
}

/**
 * @brief network_event 初始化
 */
static __always_inline struct network_event* init_network_event(enum syscall_event_name name)
{
    struct network_event *event = bpf_ringbuf_reserve(&syscall_events, sizeof(struct network_event), 0);
    if (!event) {
        return NULL;
    }
    init_syscall_event_head(&event->hdr, name);
    event->family = 0;
    event->type = 0;
    event->protocol = 0;
    return event;
}

/**
 * @brief kernel_event 初始化
 */
static __always_inline struct kernel_event* init_kernel_event(enum syscall_event_name name)
{
    struct kernel_event *event = bpf_ringbuf_reserve(&syscall_events, sizeof(struct kernel_event), 0);
    if (!event) {
        return NULL;
    }
    init_syscall_event_head(&event->hdr, name);
    event->command = 0;
    event->arg = 0;
    return event;
}

// ============================================================================
// PROCESS_EVENT 类别的syscall 拦截
// ============================================================================

SEC("tracepoint/syscalls/sys_enter_fork")
int trace_fork(struct trace_event_raw_sys_enter *ctx)
{
    struct process_event *event = init_process_event(SYSCALL_EVENT_FORK);
    if (!event) return 0;

    // fork() 无参数，clone_flags 保持 0
    bpf_ringbuf_submit(event, BPF_RB_NO_WAKEUP);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_clone")
int trace_clone(struct trace_event_raw_sys_enter *ctx)
{
    struct process_event *event = init_process_event(SYSCALL_EVENT_CLONE);
    if (!event) return 0;

    // args[0]: clone_flags
    event->clone_flags = ctx->args[0];

    bpf_ringbuf_submit(event, BPF_RB_NO_WAKEUP);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_vfork")
int trace_vfork(struct trace_event_raw_sys_enter *ctx)
{
    struct process_event *event = init_process_event(SYSCALL_EVENT_VFORK);
    if (!event) return 0;

    // vfork() 无参数，clone_flags 保持 0
    bpf_ringbuf_submit(event, BPF_RB_NO_WAKEUP);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_exit_group")
int trace_exit_group(struct trace_event_raw_sys_enter *ctx)
{
    struct process_event *event = init_process_event(SYSCALL_EVENT_EXIT_GROUP);
    if (!event) return 0;

    // args[0]: int error_code
    event->exit_code = (s32)ctx->args[0];

    bpf_ringbuf_submit(event, BPF_RB_NO_WAKEUP);
    return 0;
}

// ============================================================================
// EXEC_EVENT 类别的 syscall 拦截
// ============================================================================

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct exec_event *event = init_exec_event(SYSCALL_EVENT_EXECVE);
    if (!event) return 0;

    // args[0]: const char *filename
    bpf_probe_read_user_str(&event->filename, sizeof(event->filename), (void *)ctx->args[0]);

    // args[1]: char *const argv[] — 读取 argv[0] 作为程序名
    const char *arg0_ptr = NULL;
    if (bpf_probe_read_user(&arg0_ptr, sizeof(arg0_ptr), (void *)ctx->args[1]) == 0 && arg0_ptr) {
        bpf_probe_read_user_str(&event->argv0, sizeof(event->argv0), arg0_ptr);
    }

    bpf_ringbuf_submit(event, BPF_RB_NO_WAKEUP);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int trace_execveat(struct trace_event_raw_sys_enter *ctx)
{
    struct exec_event *event = init_exec_event(SYSCALL_EVENT_EXECVEAT);
    if (!event) return 0;

    // args[1]: const char *filename
    bpf_probe_read_user_str(&event->filename, sizeof(event->filename), (void *)ctx->args[1]);

    // args[2]: char *const argv[]
    const char *arg0_ptr = NULL;
    if (bpf_probe_read_user(&arg0_ptr, sizeof(arg0_ptr), (void *)ctx->args[2]) == 0 && arg0_ptr) {
        bpf_probe_read_user_str(&event->argv0, sizeof(event->argv0), arg0_ptr);
    }

    // args[4]: int flags
    event->flags = (u32)ctx->args[4];

    bpf_ringbuf_submit(event, BPF_RB_NO_WAKEUP);
    return 0;
}

// ============================================================================
// CREDENTIAL_EVENT 类别的 syscall 拦截
// ============================================================================

SEC("tracepoint/syscalls/sys_enter_setuid")
int trace_setuid(struct trace_event_raw_sys_enter *ctx)
{
    struct credential_event *event = init_credential_event(SYSCALL_EVENT_SETUID);
    if (!event) return 0;

    // args[0]: uid_t uid
    event->setuid.uid = (u32)ctx->args[0];

    bpf_ringbuf_submit(event, BPF_RB_NO_WAKEUP);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setgid")
int trace_setgid(struct trace_event_raw_sys_enter *ctx)
{
    struct credential_event *event = init_credential_event(SYSCALL_EVENT_SETGID);
    if (!event) return 0;

    // args[0]: gid_t gid
    event->setgid.gid = (u32)ctx->args[0];

    bpf_ringbuf_submit(event, BPF_RB_NO_WAKEUP);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_capset")
int trace_capset(struct trace_event_raw_sys_enter *ctx)
{
    struct credential_event *event = init_credential_event(SYSCALL_EVENT_CAPSET);
    if (!event) return 0;

    // args[1]: const cap_user_data_t datap — 指向 struct __user_cap_data_struct[2]
    //   data[0] 为 capabilities 0-31，data[1] 为 capabilities 32-63
    //   合并为 64 位值以兼容 v2/v3 能力集
    struct __user_cap_data_struct cap_data[2];
    if (bpf_probe_read_user(cap_data, sizeof(cap_data), (void *)ctx->args[1]) == 0) {
        event->capset.effective   = ((u64)cap_data[1].effective   << 32) | cap_data[0].effective;
        event->capset.permitted   = ((u64)cap_data[1].permitted   << 32) | cap_data[0].permitted;
        event->capset.inheritable = ((u64)cap_data[1].inheritable << 32) | cap_data[0].inheritable;
    }

    bpf_ringbuf_submit(event, BPF_RB_NO_WAKEUP);
    return 0;
}

// ============================================================================
// NAMESPACE_EVENT 类别的 syscall 拦截
// ============================================================================

SEC("tracepoint/syscalls/sys_enter_unshare")
int trace_unshare(struct trace_event_raw_sys_enter *ctx)
{
    struct namespace_event *event = init_namespace_event(SYSCALL_EVENT_UNSHARE);
    if (!event) return 0;

    // args[0]: int unshare_flags (CLONE_NEW*)
    u64 flags = ctx->args[0];
    event->flags = flags;

    // 提取涉及的 namespace 类型
    if (flags & CLONE_NEWNS)
        event->ns_type = CLONE_NEWNS;
    else if (flags & CLONE_NEWUTS)
        event->ns_type = CLONE_NEWUTS;
    else if (flags & CLONE_NEWIPC)
        event->ns_type = CLONE_NEWIPC;
    else if (flags & CLONE_NEWNET)
        event->ns_type = CLONE_NEWNET;
    else if (flags & CLONE_NEWUSER)
        event->ns_type = CLONE_NEWUSER;
    else if (flags & CLONE_NEWPID)
        event->ns_type = CLONE_NEWPID;
    else if (flags & CLONE_NEWCGROUP)
        event->ns_type = CLONE_NEWCGROUP;

    bpf_ringbuf_submit(event, BPF_RB_NO_WAKEUP);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setns")
int trace_setns(struct trace_event_raw_sys_enter *ctx)
{
    struct namespace_event *event = init_namespace_event(SYSCALL_EVENT_SETNS);
    if (!event) return 0;

    event->ns_type = (u32)ctx->args[1];
    event->flags = 0;

    bpf_ringbuf_submit(event, BPF_RB_NO_WAKEUP);
    return 0;
}

// ============================================================================
// FILE_EVENT 类别的 syscall 拦截
// ============================================================================

SEC("tracepoint/syscalls/sys_enter_open")
int trace_syscall_open(struct trace_event_raw_sys_enter *ctx)
{
    struct file_event *event = init_file_event(SYSCALL_EVENT_OPEN);
    if (!event) return 0;

    event->flags = (u32)ctx->args[1];
    event->mode  = (u32)ctx->args[2];

    bpf_ringbuf_submit(event, BPF_RB_NO_WAKEUP);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_syscall_openat(struct trace_event_raw_sys_enter *ctx)
{
    struct file_event *event = init_file_event(SYSCALL_EVENT_OPENAT);
    if (!event) return 0;

    event->flags = (u32)ctx->args[2];
    event->mode  = (u32)ctx->args[3];

    bpf_ringbuf_submit(event, BPF_RB_NO_WAKEUP);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat2")
int trace_syscall_openat2(struct trace_event_raw_sys_enter *ctx)
{
    struct file_event *event = init_file_event(SYSCALL_EVENT_OPENAT2);
    if (!event) return 0;

    struct open_how how;
    if (bpf_probe_read_user(&how, sizeof(how), (void *)ctx->args[2]) == 0) {
        event->flags = (u32)how.flags;
        event->mode  = (u32)how.mode;
    }

    bpf_ringbuf_submit(event, BPF_RB_NO_WAKEUP);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_creat")
int trace_syscall_creat(struct trace_event_raw_sys_enter *ctx)
{
    struct file_event *event = init_file_event(SYSCALL_EVENT_CREAT);
    if (!event) return 0;

    // creat() 隐含了 O_CREAT | O_WRONLY | O_TRUNC
    event->flags = O_CREAT | O_WRONLY | O_TRUNC;
    // args[1]: umode_t mode
    event->mode  = (u32)ctx->args[1];

    bpf_ringbuf_submit(event, BPF_RB_NO_WAKEUP);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlink")
int trace_syscall_unlink(struct trace_event_raw_sys_enter *ctx)
{
    struct file_event *event = init_file_event(SYSCALL_EVENT_UNLINK);
    if (!event) return 0;

    bpf_ringbuf_submit(event, BPF_RB_NO_WAKEUP);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_link")
int trace_syscall_link(struct trace_event_raw_sys_enter *ctx)
{
    struct file_event *event = init_file_event(SYSCALL_EVENT_LINK);
    if (!event) return 0;

    bpf_ringbuf_submit(event, BPF_RB_NO_WAKEUP);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_rename")
int trace_syscall_rename(struct trace_event_raw_sys_enter *ctx)
{
    struct file_event *event = init_file_event(SYSCALL_EVENT_RENAME);
    if (!event) return 0;

    bpf_ringbuf_submit(event, BPF_RB_NO_WAKEUP);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_renameat")
int trace_syscall_renameat(struct trace_event_raw_sys_enter *ctx)
{
    struct file_event *event = init_file_event(SYSCALL_EVENT_RENAMEAT);
    if (!event) return 0;

    bpf_ringbuf_submit(event, BPF_RB_NO_WAKEUP);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_renameat2")
int trace_syscall_renameat2(struct trace_event_raw_sys_enter *ctx)
{
    struct file_event *event = init_file_event(SYSCALL_EVENT_RENAMEAT2);
    if (!event) return 0;

    event->flags = (u32)ctx->args[4];

    bpf_ringbuf_submit(event, BPF_RB_NO_WAKEUP);
    return 0;
}

// ============================================================================
// MEMORY_EVENT 类别的 syscall 拦截
// ============================================================================

SEC("tracepoint/syscalls/sys_enter_mmap")
int trace_mmap(struct trace_event_raw_sys_enter *ctx)
{
    struct memory_event *event = init_memory_event(SYSCALL_EVENT_MMAP);
    if (!event) return 0;

    // args[2]: int prot (PROT_*)
    event->prot  = ctx->args[2];
    // args[3]: int flags (MAP_*)
    event->flags = ctx->args[3];

    bpf_ringbuf_submit(event, BPF_RB_NO_WAKEUP);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mprotect")
int trace_mprotect(struct trace_event_raw_sys_enter *ctx)
{
    struct memory_event *event = init_memory_event(SYSCALL_EVENT_MPROTECT);
    if (!event) return 0;

    // args[2]: int prot (PROT_*)
    event->prot  = ctx->args[2];

    bpf_ringbuf_submit(event, BPF_RB_NO_WAKEUP);
    return 0;
}

// ============================================================================
// NETWORK_EVENT 类别的 syscall 拦截
// ============================================================================

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx)
{
    struct network_event *event = init_network_event(SYSCALL_EVENT_CONNECT);
    if (!event) return 0;

    struct sockaddr sa;
    if (bpf_probe_read_user(&sa, sizeof(sa), (void *)ctx->args[1]) == 0) {
        event->family = sa.sa_family;
    }

    bpf_ringbuf_submit(event, BPF_RB_NO_WAKEUP);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_socket")
int trace_socket(struct trace_event_raw_sys_enter *ctx)
{
    struct network_event *event = init_network_event(SYSCALL_EVENT_SOCKET);
    if (!event) return 0;

    event->family   = (u32)ctx->args[0];
    event->type     = (u32)ctx->args[1];
    event->protocol = (u32)ctx->args[2];

    bpf_ringbuf_submit(event, BPF_RB_NO_WAKEUP);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_bind")
int trace_bind(struct trace_event_raw_sys_enter *ctx)
{
    struct network_event *event = init_network_event(SYSCALL_EVENT_BIND);
    if (!event) return 0;

    // args[1]: const struct sockaddr *addr
    struct sockaddr sa;
    if (bpf_probe_read_user(&sa, sizeof(sa), (void *)ctx->args[1]) == 0) {
        event->family = sa.sa_family;
    }

    bpf_ringbuf_submit(event, BPF_RB_NO_WAKEUP);
    return 0;
}

// ============================================================================
// KERNEL_EVENT 类别的 syscall 拦截
// ============================================================================

SEC("tracepoint/syscalls/sys_enter_ptrace")
int trace_ptrace(struct trace_event_raw_sys_enter *ctx)
{
    struct kernel_event *event = init_kernel_event(SYSCALL_EVENT_PTRACE);
    if (!event) return 0;

    // args[0]: int request (PTRACE_*)
    event->command = (u32)ctx->args[0];
    // args[1]: pid_t pid — 目标进程
    event->arg     = ctx->args[1];

    bpf_ringbuf_submit(event, BPF_RB_NO_WAKEUP);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_bpf")
int trace_bpf(struct trace_event_raw_sys_enter *ctx)
{
    struct kernel_event *event = init_kernel_event(SYSCALL_EVENT_BPF);
    if (!event) return 0;

    // args[0]: int cmd (BPF_*)
    event->command = (u32)ctx->args[0];
    // args[2]: unsigned int size — attr 大小（可用于推断 BPF 命令版本）
    event->arg     = ctx->args[2];

    bpf_ringbuf_submit(event, BPF_RB_NO_WAKEUP);
    return 0;
}

