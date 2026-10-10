#ifndef HNG_ROLE_FILTER_BPF_H_
#define HNG_ROLE_FILTER_BPF_H_

#include "kernel/include/event_head.h"
#include "kernel/include/role_filter_types.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

/* 每个探针对象各有一份。用户态向三份 map 同步同一有效白名单。
 * 普通 HASH 不做 LRU 淘汰：满表报错由用户态观测、重试，不能静默丢允许项。
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, HNG_ROLE_FILTER_MAX_ENTRIES);
    __type(key, struct hng_role_filter_key);
    __type(value, __u32);
} hng_role_filter SEC(".maps");

static __always_inline int hng_should_collect(void)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) return 0;
    struct task_struct *leader = BPF_CORE_READ(task, group_leader);
    if (!leader) return 0;

    /* TGID 搭配组长 start_time：工作线程自己的启动时间不能匹配进程身份。 */
    struct hng_role_filter_key key = {};
    key.tgid = BPF_CORE_READ(leader, tgid);
    key.start_time = BPF_CORE_READ(leader, start_boottime) / NSEC_PER_USER_HZ;
    const __u32 *allowed = (const __u32 *)bpf_map_lookup_elem(&hng_role_filter, &key);
    return allowed && *allowed == 1;
}

#endif
