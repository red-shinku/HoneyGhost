#ifndef HNG_SYSCALL_MAPS_BPF_H_
#define HNG_SYSCALL_MAPS_BPF_H_

#include "kernel/include/syscall_event_type.h"

#include <bpf/bpf_helpers.h>

/**
 * @brief RingBuf，存储syscall事件的数据
 *       用户态程序通过该结构获取事件数据
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} syscall_events SEC(".maps");

/**
 * @brief ringbuf 预留失败计数；每 CPU 一个 u64，用户态按 CPU 求和
 * @note 失败包括 ringbuf 满与 NMI 上下文拿不到锁，故名为 reserve_failures
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} reserve_failures SEC(".maps");

/// @brief 记录一次 ringbuf 预留失败；只在失败分支调用
static __always_inline void count_reserve_failure(void)
{
    __u32 key   = 0;
    __u64 *lost = bpf_map_lookup_elem(&reserve_failures, &key);
    if (lost) {
        __sync_fetch_and_add(lost, 1);
    }
}

/**
 * @brief enter 侧暂存表：key 为 pid_tgid，value 为已组装的完整事件
 * @details enter 探针末尾写入，对应系统调用的 exit 探针取回后补上返回值再提交。
 * @note 用普通 LRU hash 而非 LRU_PERCPU_HASH：后者的 key 也是全局的，value 按 CPU
 *       分槽，enter 写入的值只有同一 CPU 上的 exit 才读得到，而任务在系统调用中
 *       可被迁移到其它 CPU；配对必须跨 CPU 成立。
 * @note 2048 条只为容纳「enter 后任务未走到 exit」的滞留条目，写满由 LRU 淘汰。
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 2048);
    __type(key, __u64);
    __type(value, struct syscall_event);
} hng_pending SEC(".maps");

/**
 * @brief enter 侧组装事件用的 per-CPU 槽
 * @note 只在一次探针内使用：同一探针内组装完成即写入 hng_pending，不跨探针持有。
 *       事件尺寸超过 eBPF 的 512B 栈上限，故不放栈上。
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct syscall_event);
} hng_scratch SEC(".maps");

/**
 * @brief exit 时暂存条目缺失的计数；每 CPU 一个 u64，用户态按 CPU 求和
 * @note 只计入「enter 本应暂存却查不到」，即 LRU 淘汰或异常；角色过滤造成的
 *       不暂存、sendto/sendmsg 目标不可解析造成的主动不暂存都不计入。
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} pending_lost SEC(".maps");

/// @brief 记录一次暂存条目丢失；只在 exit 侧判定为丢失时调用
static __always_inline void count_pending_lost(void)
{
    __u32 key   = 0;
    __u64 *lost = bpf_map_lookup_elem(&pending_lost, &key);
    if (lost) {
        __sync_fetch_and_add(lost, 1);
    }
}

/// @brief 取本 CPU 的事件暂存槽；取不到返回 NULL
static __always_inline struct syscall_event *hng_scratch_event(void)
{
    __u32 key = 0;
    return bpf_map_lookup_elem(&hng_scratch, &key);
}
#endif
