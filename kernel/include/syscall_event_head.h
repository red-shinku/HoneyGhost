/**
 * @file syscall_event_head.h
 * @brief 定义syscalls事件专有的头结构
 * @details
 * syscalls事件头包含通用事件头，并新增了syscall名称和自定义的syscall类别归属。
 * @author red_shinku
 * @date 2026.08.06
 */

#ifndef _BPF_SYSCALLS_EVENT_HEAD_H_
#define _BPF_SYSCALLS_EVENT_HEAD_H_

#include "kernel/include/event_head.h"

enum syscall_event_name {
    SYSCALL_EVENT_FORK,
    SYSCALL_EVENT_CLONE,
    SYSCALL_EVENT_EXECVE,
    SYSCALL_EVENT_EXECVEAT,
    SYSCALL_EVENT_VFORK,

    SYSCALL_EVENT_SETUID,
    SYSCALL_EVENT_SETGID,
    SYSCALL_EVENT_CAPSET,
    SYSCALL_EVENT_SETREUID,
    SYSCALL_EVENT_SETRESUID,
    SYSCALL_EVENT_SETFSUID,
    SYSCALL_EVENT_SETRESGID,
    SYSCALL_EVENT_SETGROUPS,
    SYSCALL_EVENT_PRCTL,

    SYSCALL_EVENT_UNSHARE,
    SYSCALL_EVENT_SETNS,
    SYSCALL_EVENT_MOUNT,
    SYSCALL_EVENT_UMOUNT2,
    SYSCALL_EVENT_PIVOT_ROOT,
    SYSCALL_EVENT_CHROOT,

    SYSCALL_EVENT_PTRACE,

    SYSCALL_EVENT_BPF,
    SYSCALL_EVENT_INIT_MODULE,
    SYSCALL_EVENT_FINIT_MODULE,
    SYSCALL_EVENT_DELETE_MODULE,
    SYSCALL_EVENT_KEXEC_LOAD,
    SYSCALL_EVENT_REBOOT,
    SYSCALL_EVENT_SETHOSTNAME,

    SYSCALL_EVENT_OPEN,
    SYSCALL_EVENT_OPENAT,
    SYSCALL_EVENT_OPENAT2,
    SYSCALL_EVENT_CREAT,
    SYSCALL_EVENT_UNLINK,
    SYSCALL_EVENT_LINK,
    SYSCALL_EVENT_RENAME,
    SYSCALL_EVENT_RENAMEAT,
    SYSCALL_EVENT_RENAMEAT2,
    SYSCALL_EVENT_UNLINKAT,
    SYSCALL_EVENT_LINKAT,
    SYSCALL_EVENT_SYMLINK,
    SYSCALL_EVENT_SYMLINKAT,
    SYSCALL_EVENT_CHMOD,
    SYSCALL_EVENT_FCHMOD,
    SYSCALL_EVENT_FCHMODAT,
    SYSCALL_EVENT_TRUNCATE,
    SYSCALL_EVENT_FTRUNCATE,
    SYSCALL_EVENT_MKNOD,
    SYSCALL_EVENT_MKNODAT,
    SYSCALL_EVENT_MEMFD_CREATE,
    SYSCALL_EVENT_OPEN_BY_HANDLE_AT,
    SYSCALL_EVENT_NAME_TO_HANDLE_AT,
    SYSCALL_EVENT_CHDIR,
    SYSCALL_EVENT_FCHDIR,

    SYSCALL_EVENT_MMAP,
    SYSCALL_EVENT_MPROTECT,
    SYSCALL_EVENT_MREMAP,
    SYSCALL_EVENT_MUNMAP,

    SYSCALL_EVENT_CONNECT,
    SYSCALL_EVENT_SOCKET,
    SYSCALL_EVENT_BIND,
    SYSCALL_EVENT_SENDTO,
    SYSCALL_EVENT_SENDMSG,
    SYSCALL_EVENT_RECVFROM,
    SYSCALL_EVENT_ACCEPT4,
    SYSCALL_EVENT_LISTEN,

    SYSCALL_EVENT_KILL,
    SYSCALL_EVENT_TKILL,
    SYSCALL_EVENT_TGKILL,
    SYSCALL_EVENT_RT_SIGQUEUEINFO,

    SYSCALL_EVENT_EXIT_GROUP,

    // 非系统调用来源的事件名（tracepoint）
    SYSCALL_EVENT_TASK_RENAME,
    SYSCALL_EVENT_CGROUP_ATTACH_TASK,
    SYSCALL_EVENT_MODULE_LOAD,
    SYSCALL_EVENT_MODULE_FREE
};

/**
 * @brief 自定义syscall类别.
 * @details 根据语义划分。每个类型也对应一种数据结构，用户态以此从 ringbuf
 * 解析数据。取值与 proto 的 Subtype 同数值；PROCESS_EVENT..KERNEL_EVENT 的
 * 顺序与 syscall_semantic_data 载荷 variant 的顺序一一对应，故 variant 第 i
 * 个备选对应取值 i + 1。0 保留给未归类的事件。
 */
enum syscall_event_type {
    UNKNOWN_EVENT    = 0,  ///< 未归类
    PROCESS_EVENT    = 1,  ///< 进程生命周期
    EXEC_EVENT       = 2,  ///< 执行语义
    CREDENTIAL_EVENT = 3,  ///< 权限变化
    NAMESPACE_EVENT  = 4,  ///< 命名空间事件
    FILE_EVENT       = 5,  ///< 文件操作
    MEMORY_EVENT     = 6,  ///< 内存操作
    NETWORK_EVENT    = 7,  ///< 网络连接
    KERNEL_EVENT     = 8,  ///< 内核操作
    SIGNAL_EVENT     = 9   ///< 信号发送
};

struct syscall_event_head {
    struct event_head head;
    enum syscall_event_name name;
    /// 系统调用类别；与用户态 event_head.subtype 同义
    enum syscall_event_type subtype;
};

// 初始化函数依赖 init_event_head，仅内核态探针程序使用
#ifdef __bpf__
static __always_inline void init_syscall_event_head(
    struct syscall_event_head *s_head, enum syscall_event_name name)
{
    if (!s_head) {
        return;
    }
    init_event_head(&s_head->head);
    s_head->name = name;
    switch (name) {
        case SYSCALL_EVENT_FORK:
        case SYSCALL_EVENT_CLONE:
        case SYSCALL_EVENT_VFORK:
        case SYSCALL_EVENT_EXIT_GROUP:
        case SYSCALL_EVENT_TASK_RENAME:
        case SYSCALL_EVENT_CGROUP_ATTACH_TASK:
            s_head->subtype = PROCESS_EVENT;
            break;
        case SYSCALL_EVENT_EXECVE:
        case SYSCALL_EVENT_EXECVEAT:
            s_head->subtype = EXEC_EVENT;
            break;
        case SYSCALL_EVENT_SETUID:
        case SYSCALL_EVENT_SETGID:
        case SYSCALL_EVENT_CAPSET:
        case SYSCALL_EVENT_SETREUID:
        case SYSCALL_EVENT_SETRESUID:
        case SYSCALL_EVENT_SETFSUID:
        case SYSCALL_EVENT_SETRESGID:
        case SYSCALL_EVENT_SETGROUPS:
        case SYSCALL_EVENT_PRCTL:
            s_head->subtype = CREDENTIAL_EVENT;
            break;
        case SYSCALL_EVENT_UNSHARE:
        case SYSCALL_EVENT_SETNS:
        case SYSCALL_EVENT_MOUNT:
        case SYSCALL_EVENT_UMOUNT2:
        case SYSCALL_EVENT_PIVOT_ROOT:
        case SYSCALL_EVENT_CHROOT:
            s_head->subtype = NAMESPACE_EVENT;
            break;
        case SYSCALL_EVENT_OPEN:
        case SYSCALL_EVENT_OPENAT:
        case SYSCALL_EVENT_OPENAT2:
        case SYSCALL_EVENT_CREAT:
        case SYSCALL_EVENT_UNLINK:
        case SYSCALL_EVENT_LINK:
        case SYSCALL_EVENT_RENAME:
        case SYSCALL_EVENT_RENAMEAT:
        case SYSCALL_EVENT_RENAMEAT2:
        case SYSCALL_EVENT_UNLINKAT:
        case SYSCALL_EVENT_LINKAT:
        case SYSCALL_EVENT_SYMLINK:
        case SYSCALL_EVENT_SYMLINKAT:
        case SYSCALL_EVENT_CHMOD:
        case SYSCALL_EVENT_FCHMOD:
        case SYSCALL_EVENT_FCHMODAT:
        case SYSCALL_EVENT_TRUNCATE:
        case SYSCALL_EVENT_FTRUNCATE:
        case SYSCALL_EVENT_MKNOD:
        case SYSCALL_EVENT_MKNODAT:
        case SYSCALL_EVENT_MEMFD_CREATE:
        case SYSCALL_EVENT_OPEN_BY_HANDLE_AT:
        case SYSCALL_EVENT_NAME_TO_HANDLE_AT:
        case SYSCALL_EVENT_CHDIR:
        case SYSCALL_EVENT_FCHDIR:
            s_head->subtype = FILE_EVENT;
            break;
        case SYSCALL_EVENT_MMAP:
        case SYSCALL_EVENT_MPROTECT:
        case SYSCALL_EVENT_MREMAP:
        case SYSCALL_EVENT_MUNMAP:
            s_head->subtype = MEMORY_EVENT;
            break;
        case SYSCALL_EVENT_CONNECT:
        case SYSCALL_EVENT_SOCKET:
        case SYSCALL_EVENT_BIND:
        case SYSCALL_EVENT_SENDTO:
        case SYSCALL_EVENT_SENDMSG:
        case SYSCALL_EVENT_RECVFROM:
        case SYSCALL_EVENT_ACCEPT4:
        case SYSCALL_EVENT_LISTEN:
            s_head->subtype = NETWORK_EVENT;
            break;
        case SYSCALL_EVENT_PTRACE:
        case SYSCALL_EVENT_BPF:
        case SYSCALL_EVENT_INIT_MODULE:
        case SYSCALL_EVENT_FINIT_MODULE:
        case SYSCALL_EVENT_DELETE_MODULE:
        case SYSCALL_EVENT_KEXEC_LOAD:
        case SYSCALL_EVENT_REBOOT:
        case SYSCALL_EVENT_SETHOSTNAME:
        case SYSCALL_EVENT_MODULE_LOAD:
        case SYSCALL_EVENT_MODULE_FREE:
            s_head->subtype = KERNEL_EVENT;
            break;
        case SYSCALL_EVENT_KILL:
        case SYSCALL_EVENT_TKILL:
        case SYSCALL_EVENT_TGKILL:
        case SYSCALL_EVENT_RT_SIGQUEUEINFO:
            s_head->subtype = SIGNAL_EVENT;
            break;
        default:
            // 新增 name 尚未归类时落到 0，避免沿用上一条事件的取值
            s_head->subtype = UNKNOWN_EVENT;
            break;
    }
}
#endif  // __bpf__

#endif  // _BPF_SYSCALLS_EVENT_HEAD_H_