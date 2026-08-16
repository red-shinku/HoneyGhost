/**
 * @file syscalls_type.h
 * @brief 此文件定义系统调用事件收集模块的数据结构
 * @details
 *
 * 将八种事件用union联合到 syscall_event 中
 * 事件收集均放回该结构
 * 用户态直接引用该头文件以使用相关结构
 *
 * @author red_shinku
 * @date 2026.08.12
 */

#ifndef _BPF_SYSCALL_TYPE_H_
#define _BPF_SYSCALL_TYPE_H_

#include "../include/syscall_event_head.h"

// syscall参数最大长度
#define MAX_ARG_LEN 64
// 可执行程序文件名最大长度
#define MAX_EXEC_FILENAME_LEN 256

struct process_event {
    __u64 clone_flags;  ///< clone 有效，新进程的创建方式
    __s32 exit_code;    ///< exit_group 有效
};

struct exec_event {
    char filename[MAX_EXEC_FILENAME_LEN];  ///< 可执行文件路径
    char argv0[MAX_ARG_LEN];               ///< argv[0]（程序名或启动命令）
    __u32 flags;                           ///< execveat 有效，AT_* 标志
};

struct credential_event {
    union {
        struct {
            __u32 uid;  ///< setuid() 设置的新 UID
        } setuid;

        struct {
            __u32 gid;  ///< setgid() 设置的新 GID
        } setgid;

        struct {
            __u64 effective;    ///< Effective Capability
            __u64 permitted;    ///< Permitted Capability
            __u64 inheritable;  ///< Inheritable Capability
        } capset;
    };
};

struct namespace_event {
    __u32 ns_type;  ///< setns() 目标 Namespace 类型（CLONE_NEW*）；或 unshare() 涉及的 Namespace
    __u64 flags;    ///< unshare() 的 CLONE_* 标志；setns() 可扩展保存 flags
};

struct file_event {
    // char path1[256]; ///< 主路径（open、unlink、creat、rename 源路径等）
    // char path2[256]; ///< 第二路径（link、rename 等目标路径，无则为空）
    __u32 flags;  ///< open/openat/openat2 的 O_* 标志；renameat2 的 RENAME_* 标志
    __u32 mode;   ///< creat()/open(O_CREAT) 创建权限；openat2 可扩展保存 mode
};

struct memory_event {
    __u64 prot;   ///< PROT_* 权限（mmap/mprotect）
    __u64 flags;  ///< MAP_* 标志（mmap）或保留扩展
};

struct network_event {
    __u32 family;    ///< AF_INET / AF_INET6 / AF_UNIX 等地址族
    __u32 type;      ///< SOCK_STREAM / SOCK_DGRAM 等
    __u32 protocol;  ///< IPPROTO_TCP 等协议号
};

struct kernel_event {
    __u32 command;  ///< ptrace 请求类型（PTRACE_*）或 bpf 命令（BPF_*）
    __u64 arg;      ///< 与 command 对应的重要参数（可根据事件类型解释）
};

/**
 * @brief 通用 syscall 事件结构
 * @details 通过 union 统一八种事件类型，hdr 位于结构体开头。
 * 内核态以该结构提交至 ringbuf，用户态依据 hdr.type 解析 union。
 */
struct syscall_event {
    struct syscall_event_head hdr;
    union {
        struct process_event process_event;
        struct exec_event exec_event;
        struct credential_event credential_event;
        struct namespace_event namespace_event;
        struct file_event file_event;
        struct memory_event memory_event;
        struct network_event network_event;
        struct kernel_event kernel_event;
    };
};

#endif  //_BPF_SYSCALL_TYPE_H_