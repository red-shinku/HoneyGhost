/**
 * @file syscall_event_head.h
 * @brief 定义syscalls事件专有的头结构
 * @details syscalls事件头包含通用事件头，并新增了syscall名称和自定义的syscall类别归属。
 * @author red_shinku
 * @date 2026.08.06
 */

#ifndef _SYSCALLS_EVENT_HEAD_H
#define _SYSCALLS_EVENT_HEAD_H

#include "event_head.h"

enum syscall_event_name {
    SYSCALL_EVENT_FORK,
    SYSCALL_EVENT_CLONE,
    SYSCALL_EVENT_EXECVE,
    SYSCALL_EVENT_EXECVEAT,
    SYSCALL_EVENT_VFORK,

    SYSCALL_EVENT_SETUID,
    SYSCALL_EVENT_SETGID,
    SYSCALL_EVENT_CAPSET,

    SYSCALL_EVENT_UNSHARE,
    SYSCALL_EVENT_SETNS,

    SYSCALL_EVENT_PTRACE,

    SYSCALL_EVENT_BPF,

    SYSCALL_EVENT_OPEN,
    SYSCALL_EVENT_OPENAT,
    SYSCALL_EVENT_OPENAT2,
    SYSCALL_EVENT_CREAT,
    SYSCALL_EVENT_UNLINK,
    SYSCALL_EVENT_LINK,
    SYSCALL_EVENT_RENAME,
    SYSCALL_EVENT_RENAMEAT,
    SYSCALL_EVENT_RENAMEAT2,

    SYSCALL_EVENT_MMAP,
    SYSCALL_EVENT_MPROTECT,

    SYSCALL_EVENT_CONNECT,
    SYSCALL_EVENT_SOCKET,
    SYSCALL_EVENT_BIND,

    SYSCALL_EVENT_EXIT_GROUP
};

/**
 * @brief 自定义syscall类别.
 * @details 根据语义划分。每个类型也对应一种数据结构，用户态以此从 ringbuf 解析数据。
 */
enum syscall_event_type {
    PROCESS_EVENT,     ///< 进程生命周期
    EXEC_EVENT,        ///< 执行语义
    CREDENTIAL_EVENT,  ///< 权限变化
    NAMESPACE_EVENT,   ///< 命名空间事件
    FILE_EVENT,        ///< 文件操作
    MEMORY_EVENT,      ///< 内存操作
    NETWORK_EVENT,     ///< 网络连接
    KERNEL_EVENT       ///< 内核操作
};

struct syscall_event_head {
    struct event_head head;
    enum syscall_event_name name;
    enum syscall_event_type type;
};

static __always_inline void init_syscall_event_head(struct syscall_event_head *s_head, enum syscall_event_name name)
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
            s_head->type = PROCESS_EVENT;
            break;
        case SYSCALL_EVENT_EXECVE:
        case SYSCALL_EVENT_EXECVEAT:
            s_head->type = EXEC_EVENT;
            break;
        case SYSCALL_EVENT_SETUID:
        case SYSCALL_EVENT_SETGID:
        case SYSCALL_EVENT_CAPSET:
            s_head->type = CREDENTIAL_EVENT;
            break;
        case SYSCALL_EVENT_UNSHARE:
        case SYSCALL_EVENT_SETNS:
            s_head->type = NAMESPACE_EVENT;
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
            s_head->type = FILE_EVENT;
            break;
        case SYSCALL_EVENT_MMAP:
        case SYSCALL_EVENT_MPROTECT:
            s_head->type = MEMORY_EVENT;
            break;
        case SYSCALL_EVENT_CONNECT:
        case SYSCALL_EVENT_SOCKET:
        case SYSCALL_EVENT_BIND:
            s_head->type = NETWORK_EVENT;
            break;
        case SYSCALL_EVENT_PTRACE:
        case SYSCALL_EVENT_BPF:
            s_head->type = KERNEL_EVENT;
            break;
    }
}

#endif  // _SYSCALLS_EVENT_HEAD_H