#ifndef HNG_SYSCALL_EVENT_COMMIT_BPF_H_
#define HNG_SYSCALL_EVENT_COMMIT_BPF_H_

#include "kernel/include/path_resolver.bpf.h"
#include "kernel/include/role_filter.bpf.h"
#include "kernel/include/syscall_event_type.h"
#include "kernel/src/syscall_maps.bpf.h"

#include <bpf/bpf_helpers.h>

/**
 * @name enter/exit 配对
 * @details
 * 每个被采集的系统调用都有 enter 与 exit 两个探针：enter 把事件组装进本 CPU 槽后
 * 写入 hng_pending；exit 取回同一线程的条目，按完成时刻重填事件头、补上返回值，
 * 再提交 ringbuf。由此：
 * - 事件按**完成序**下发，hdr.head.ret 是系统调用的真实返回值；
 * - 同一线程的系统调用不会重叠，故 pid_tgid 足以标识一次未完成的事件；
 * - 被信号打断后重启的系统调用各有一次 enter/exit，即产生两条事件；
 * - exec 成功的 exit 已换镜像，头里的 uid/euid/comm 即新镜像的值；
 * - enter 后任务被 kill（没有 exit）的条目滞留，由 hng_pending 的 LRU 淘汰兜底。
 * @{
 */

/**
 * @brief 把 enter 组装好的事件写入当前线程的暂存条目。
 * @param[in] event 本 CPU 暂存槽内的事件；为空时不做任何事。
 * @note 覆盖同键旧条目：同一线程不会有两个未完成的被采集系统调用。
 */
static __always_inline void hng_stash_pending(struct syscall_event *event)
{
    if (!event) return;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&hng_pending, &pid_tgid, event, BPF_ANY);
}

/**
 * @brief 复制 exec_event 载荷。
 * @note 大结构按字段复制：整体 __builtin_memcpy 可能退化成对 memcpy 的调用。
 */
static __always_inline void hng_copy_exec_event(struct exec_event *dst,
                                                const struct exec_event *src)
{
    __builtin_memcpy(dst->invoked, src->invoked, sizeof(dst->invoked));
    __builtin_memcpy(dst->image, src->image, sizeof(dst->image));
    __builtin_memcpy(dst->argv0, src->argv0, sizeof(dst->argv0));
    __builtin_memcpy(dst->argv1, src->argv1, sizeof(dst->argv1));
    __builtin_memcpy(dst->argv2, src->argv2, sizeof(dst->argv2));
    __builtin_memcpy(dst->argv3, src->argv3, sizeof(dst->argv3));
    __builtin_memcpy(dst->ld_preload, src->ld_preload, sizeof(dst->ld_preload));
    __builtin_memcpy(dst->ld_library_path, src->ld_library_path,
                     sizeof(dst->ld_library_path));
    dst->flags       = src->flags;
    dst->image_flags = src->image_flags;
}

/**
 * @brief 提交前的空操作钩子：除 EXEC 外的子类型无需补填字段。
 * @param pending 即将提交的暂存事件；本函数不读也不写
 */
static __always_inline void hng_prepare_none(struct syscall_event *pending)
{
    (void)pending;
}

/**
 * @brief FILE 事件提交前的补填钩子。
 * @param pending 即将提交的暂存事件。
 * @note name_to_handle_at 的句柄缓冲是输出参数：enter 只把用户指针暂存在
 *       length 字段，exit 时再读句柄内容并把该字段清回 0。
 */
static __always_inline void hng_prepare_file(struct syscall_event *pending)
{
    if (!pending || pending->hdr.name != SYSCALL_EVENT_NAME_TO_HANDLE_AT) {
        return;
    }
    const void *handle = (const void *)(unsigned long)pending->file_event.length;
    if (handle) {
        bpf_probe_read_user(pending->file_event.handle,
                            sizeof(pending->file_event.handle), handle);
    }
    pending->file_event.length = 0;
}

/// @brief 复制 credential_event 载荷。
static __always_inline void hng_copy_credential_event(
    struct credential_event *dst, const struct credential_event *src)
{
    __builtin_memcpy(dst, src, sizeof(*dst));
}

/// @brief 复制 namespace_event 载荷。
static __always_inline void hng_copy_namespace_event(
    struct namespace_event *dst, const struct namespace_event *src)
{
    dst->flags   = src->flags;
    dst->ns_mask = src->ns_mask;
    dst->fd      = src->fd;
    __builtin_memcpy(dst->source, src->source, sizeof(dst->source));
    __builtin_memcpy(dst->target, src->target, sizeof(dst->target));
    __builtin_memcpy(dst->fstype, src->fstype, sizeof(dst->fstype));
    dst->source_flags = src->source_flags;
    dst->target_flags = src->target_flags;
    dst->mount_flags  = src->mount_flags;
}

/// @brief 复制 file_event 载荷。
static __always_inline void hng_copy_file_event(struct file_event *dst,
                                                const struct file_event *src)
{
    __builtin_memcpy(dst->path1, src->path1, sizeof(dst->path1));
    __builtin_memcpy(dst->path2, src->path2, sizeof(dst->path2));
    dst->path1_flags = src->path1_flags;
    dst->path2_flags = src->path2_flags;
    dst->dirfd       = src->dirfd;
    dst->dirfd2      = src->dirfd2;
    dst->flags       = src->flags;
    dst->mode        = src->mode;
    dst->at_flags    = src->at_flags;
    dst->resolve     = src->resolve;
    dst->length      = src->length;
    dst->dev         = src->dev;
    __builtin_memcpy(dst->handle, src->handle, sizeof(dst->handle));
    dst->fd = src->fd;
}

/// @brief 复制 memory_event 载荷。
static __always_inline void hng_copy_memory_event(struct memory_event *dst,
                                                  const struct memory_event *src)
{
    __builtin_memcpy(dst->path, src->path, sizeof(dst->path));
    dst->prot       = src->prot;
    dst->flags      = src->flags;
    dst->addr       = src->addr;
    dst->length     = src->length;
    dst->offset     = src->offset;
    dst->fd         = src->fd;
    dst->anonymous  = src->anonymous;
    dst->wx         = src->wx;
    dst->path_flags = src->path_flags;
}

/// @brief 复制 network_event 载荷。
static __always_inline void hng_copy_network_event(
    struct network_event *dst, const struct network_event *src)
{
    dst->family   = src->family;
    dst->type     = src->type;
    dst->protocol = src->protocol;
    __builtin_memcpy(dst->dst_ip, src->dst_ip, sizeof(dst->dst_ip));
    __builtin_memcpy(dst->src_ip, src->src_ip, sizeof(dst->src_ip));
    __builtin_memcpy(dst->unix_path, src->unix_path, sizeof(dst->unix_path));
    dst->dst_port = src->dst_port;
    dst->src_port = src->src_port;
    dst->sockfd   = src->sockfd;
    dst->count    = src->count;
    dst->backlog  = src->backlog;
    dst->flags    = src->flags;
}

/// @brief 复制 kernel_event 载荷。
static __always_inline void hng_copy_kernel_event(struct kernel_event *dst,
                                                  const struct kernel_event *src)
{
    dst->command    = src->command;
    dst->target_pid = src->target_pid;
    dst->arg        = src->arg;
    __builtin_memcpy(dst->bpf_attr, src->bpf_attr, sizeof(dst->bpf_attr));
    dst->bpf_type = src->bpf_type;
    __builtin_memcpy(dst->module_name, src->module_name,
                     sizeof(dst->module_name));
    dst->module_len     = src->module_len;
    dst->kexec_entry    = src->kexec_entry;
    dst->kexec_segments = src->kexec_segments;
    dst->reboot_cmd     = src->reboot_cmd;
    __builtin_memcpy(dst->hostname, src->hostname, sizeof(dst->hostname));
}

/// @brief 复制 signal_event 载荷。
static __always_inline void hng_copy_signal_event(struct signal_event *dst,
                                                  const struct signal_event *src)
{
    dst->sig        = src->sig;
    dst->target_pid = src->target_pid;
    dst->target_tid = src->target_tid;
    dst->si_code    = src->si_code;
}

/**
 * @brief 生成一个按 subtype 定长提交的 exit 侧函数。
 * @param[in] subtype_id 该分支处理的子类型，同时构成函数名后缀。
 * @param[in] payload 该子类型的载荷结构体名；记录长度 = 头 + 该结构体。
 * @param[in] prepare 提交前的补填钩子，写暂存条目的 map value；
 *                    无需补填的子类型传 hng_prepare_none。
 * @details 预留长度是编译期常量，分支内只访问自己的载荷类型。不能用运行期
 *          变量当预留长度跨分支写：verifier 对变长 PTR_TO_MEM 的越界判定会
 *          变保守，且分支与长度不匹配时是运行期越界。记录头里的 subtype 取
 *          本分支的参数，保证长度前缀与载荷布局一致。
 * @note 暂存条目的名字与 name 不符时按残留条目丢弃，不提交；ringbuf 预留
 *       失败时删除条目并计入 reserve_failures，避免污染下一次 exit。
 * @note prepare 在名字校验通过之后、ringbuf 预留之前调用，此时条目确定属于
 *       本次 exit；它直接写 map value，避免 exit 探针为路径结果再开栈缓冲。
 */
#define HNG_DEFINE_COMMIT(subtype_id, payload, prepare)                       \
    static __always_inline int hng_commit_##subtype_id(                       \
        __s64 ret, enum syscall_event_name name, int count_lost)              \
    {                                                                         \
        __u64 pid_tgid = bpf_get_current_pid_tgid();                          \
        struct syscall_event *pending =                                       \
            bpf_map_lookup_elem(&hng_pending, &pid_tgid);                     \
        if (!pending) {                                                       \
            if (count_lost && hng_should_collect()) {                         \
                count_pending_lost();                                         \
            }                                                                 \
            return 0;                                                         \
        }                                                                     \
        if (pending->hdr.name != name) {                                      \
            bpf_map_delete_elem(&hng_pending, &pid_tgid);                     \
            if (count_lost && hng_should_collect()) {                         \
                count_pending_lost();                                         \
            }                                                                 \
            return 0;                                                         \
        }                                                                     \
        prepare(pending);                                                     \
        char *record = bpf_ringbuf_reserve(                                   \
            &syscall_events,                                                  \
            sizeof(struct syscall_event_head) + sizeof(struct payload), 0);   \
        if (!record) {                                                        \
            bpf_map_delete_elem(&hng_pending, &pid_tgid);                     \
            count_reserve_failure();                                          \
            return 0;                                                         \
        }                                                                     \
        struct syscall_event_head *hdr = (struct syscall_event_head *)record; \
        struct payload *dst =                                                 \
            (struct payload *)(record + sizeof(struct syscall_event_head));   \
        hng_copy_##payload(dst, &pending->payload);                           \
        init_syscall_event_head(hdr, name);                                   \
        hdr->subtype  = subtype_id;                                           \
        hdr->head.ret = ret;                                                  \
        bpf_map_delete_elem(&hng_pending, &pid_tgid);                         \
        bpf_ringbuf_submit(record, 0);                                        \
        return 0;                                                             \
    }

HNG_DEFINE_COMMIT(EXEC_EVENT, exec_event, hng_fill_exec_image)
HNG_DEFINE_COMMIT(CREDENTIAL_EVENT, credential_event, hng_prepare_none)
HNG_DEFINE_COMMIT(NAMESPACE_EVENT, namespace_event, hng_prepare_none)
HNG_DEFINE_COMMIT(FILE_EVENT, file_event, hng_prepare_file)
HNG_DEFINE_COMMIT(MEMORY_EVENT, memory_event, hng_fill_mmap_path)
HNG_DEFINE_COMMIT(NETWORK_EVENT, network_event, hng_prepare_none)
HNG_DEFINE_COMMIT(KERNEL_EVENT, kernel_event, hng_prepare_none)
HNG_DEFINE_COMMIT(SIGNAL_EVENT, signal_event, hng_prepare_none)

/** @} */
#endif
