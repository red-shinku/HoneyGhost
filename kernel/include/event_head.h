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

#ifndef _BPF_EVENT_HEAD_H_
#define _BPF_EVENT_HEAD_H_

// 用户态 C++ 提供 __u32 等类型；BPF 程序由 vmlinux.h 提供
#ifdef __cplusplus
#include <linux/types.h>
#endif

/**
 * @brief 启动时间由内核纳秒值换算为 tick 的除数：NSEC_PER_SEC / USER_HZ
 * @details
 * /proc/<pid>/stat 字段 22 取自 start_boottime （分辨率
 * 10ms），eBPF 侧须换算到同一精度。
 *
 * USER_HZ 是 ABI 固定值 100（include/asm-generic/param.h），不是运行时可变量。
 */
#define NSEC_PER_USER_HZ 10000000ULL

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

/**
 * @brief 填写事件头的父进程字段：父进程的 TGID 与组长启动时间。
 * @param[out] head 待填写的事件头。
 * @param[in] parent 事件主体所属进程的 real_parent；为空时字段保持原值。
 * @note 父进程身份由父进程的 TGID 与组长启动时间构成。real_parent 指向父进程
 *       中发起 fork 的那个任务，可能是普通线程，其自身启动时间不是进程身份。
 */
static __always_inline void init_event_head_parent(struct event_head *head,
                                                   struct task_struct *parent)
{
    if (!head || !parent) {
        return;
    }
    struct task_struct *leader = BPF_CORE_READ(parent, group_leader);
    if (!leader) {
        return;
    }
    head->ppid = BPF_CORE_READ(leader, tgid);
    head->ppid_start_time =
        BPF_CORE_READ(leader, start_boottime) / NSEC_PER_USER_HZ;
}

/**
 * @brief 按当前任务填写事件头。
 * @param[out] head 待填写的事件头。
 * @note 父进程取当前任务的 real_parent，即线程组的父进程；同组线程共享该值，
 *       故给出相同的父进程（见 @ref init_event_head_parent）。
 */
static __always_inline void init_event_head(struct event_head *head)
{
    if (!head) {
        return;
    }
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    // 以进程为最小单元
    head->pid                = BPF_CORE_READ(task, tgid);
    head->pid_start_time = BPF_CORE_READ(task, start_boottime) / NSEC_PER_USER_HZ;
    init_event_head_parent(head, BPF_CORE_READ(task, real_parent));
}
#endif  // __bpf__

#endif  // _BPF_EVENT_HEAD_H_
