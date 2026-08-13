/**
 * @file event_head.h
 * @brief 定义通用事件头结构
 * @details
 * 事件头用于记录某事件的身份、上下文等信息，用于对事件进行归类（归类至某个
 * Context 中）。
 *
 * 该头文件同时被内核态（BPF 程序）与用户态 C++ 引用：
 *  - 类型统一使用 Linux UAPI 类型（__u32 / __u64）：
 *      * BPF 程序由 vmlinux.h 提供；
 *      * 用户态 C++ 在 #ifdef __cplusplus 下自动包含 <linux/types.h>；
 *  - 依赖 BPF helper 的初始化函数仅在内核态（__bpf__）编译，用户态不可见。
 *
 * @author red_shinku
 * @date 2026.08.05
 */

#ifndef __EVENT_HEAD_H
#define __EVENT_HEAD_H

// 用户态 C++ 提供 __u32 等类型；BPF 程序由 vmlinux.h 提供
#ifdef __cplusplus
#include <linux/types.h>
#endif

struct event_head {
    __u32 pid;
    __u64 pid_start_time;
    __u32 ppid;
    __u64 ppid_start_time;
};

// 初始化函数依赖 BPF helper，仅内核态探针程序使用
#ifdef __bpf__
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

static __always_inline void init_event_head(struct event_head *head)
{
    if (!head) {
        return;
    }
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    // 以进程为最小单元
    head->pid                = BPF_CORE_READ(task, tgid);
    head->pid_start_time     = BPF_CORE_READ(task, start_time);
    head->ppid               = BPF_CORE_READ(task, real_parent, tgid);
    head->ppid_start_time    = BPF_CORE_READ(task, real_parent, start_time);
}
#endif  // __bpf__

#endif  // __EVENT_HEAD_H
