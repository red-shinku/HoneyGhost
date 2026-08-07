/**
 * @file event_head.h
 * @brief 定义通用事件头结构
 * @details
 * 事件头用于记录某事件的身份、上下文等信息，用于对事件进行归类（归类至某个
 * Context 中）
 * @author red_shinku
 * @date 2026.08.05
 */

#ifndef __EVENT_HEAD_H
#define __EVENT_HEAD_H

#include <bpf/bpf_helpers.h>
#include <linux/types.h>

struct event_head {
    __u32 pid;
    __u64 pid_start_time;
    __u32 ppid;
    __u64 ppid_start_time;
};

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

#endif  // __EVENT_HEAD_H