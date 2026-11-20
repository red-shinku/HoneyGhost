#ifndef HNG_SYSCALL_EVENT_BUILDERS_BPF_H_
#define HNG_SYSCALL_EVENT_BUILDERS_BPF_H_

#include "kernel/include/role_filter.bpf.h"
#include "kernel/include/syscall_event_type.h"
#include "kernel/include/uapi_const.h"
#include "kernel/src/syscall_maps.bpf.h"

#include <bpf/bpf_helpers.h>

/**
 * @name 各事件类型的初始化函数，取本 CPU 的暂存槽并初始化事件头。
 * 事件在本 CPU 槽内组装，enter 探针末尾写入暂存表，由对应 exit 探针提交。
 * 生命周期事件不经配对，仍预留 ringbuf 后直接提交（见 init_process_event）。
 * @{
 */

/**
 * @brief 初始化进程生命周期事件，并预留 ringbuf 事件空间。
 * @param[in] name 系统调用事件名。
 * @return 成功时返回事件指针；空间不足时返回 NULL。
 * @note 生命周期事件不经 enter/exit 配对，调用者直接提交或丢弃。
 * @note 生命周期事件绕过角色过滤，以维护完整进程树。
 * @note 只预留头与 process_event 的定长记录；返回指针便于调用者填头与
 *       process_event，记录中不含 union 的其余载荷。
 */
static __always_inline struct syscall_event *init_process_event(
    enum syscall_event_name name)
{
    struct syscall_event *event = bpf_ringbuf_reserve(
        &syscall_events,
        sizeof(struct syscall_event_head) + sizeof(struct process_event), 0);
    if (!event) {
        count_reserve_failure();
        return NULL;
    }
    init_syscall_event_head(&event->hdr, name);
    //! @note 载荷整体清零：生命周期与 tracepoint 事件只填自己的字段
    __builtin_memset(&event->process_event, 0, sizeof(event->process_event));
    return event;
}

/**
 * @brief 初始化 exec_event，并取本 CPU 的事件暂存槽。
 * @param[in] name 系统调用事件名。
 * @return 成功时返回暂存槽内的事件指针；槽不可用时返回 NULL。
 * @note 事件在本 CPU 槽内组装，enter 探针末尾写入暂存表，由对应 exit 探针提交。
 */
static __always_inline struct syscall_event *init_exec_event(
    enum syscall_event_name name)
{
    struct syscall_event *event = hng_scratch_event();
    if (!event) return NULL;
    init_syscall_event_head(&event->hdr, name);
    __builtin_memset(event->exec_event.invoked, 0,
                     sizeof(event->exec_event.invoked));
    __builtin_memset(event->exec_event.image, 0, sizeof(event->exec_event.image));
    __builtin_memset(event->exec_event.argv0, 0, sizeof(event->exec_event.argv0));
    __builtin_memset(event->exec_event.argv1, 0, sizeof(event->exec_event.argv1));
    __builtin_memset(event->exec_event.argv2, 0, sizeof(event->exec_event.argv2));
    __builtin_memset(event->exec_event.argv3, 0, sizeof(event->exec_event.argv3));
    __builtin_memset(event->exec_event.ld_preload, 0,
                     sizeof(event->exec_event.ld_preload));
    __builtin_memset(event->exec_event.ld_library_path, 0,
                     sizeof(event->exec_event.ld_library_path));
    event->exec_event.flags       = 0;
    event->exec_event.image_flags = 0;
    return event;
}

/**
 * @brief 初始化 credential_event，并取本 CPU 的事件暂存槽。
 * @param[in] name 系统调用事件名。
 * @return 角色被过滤或槽不可用时返回 NULL，否则返回暂存槽内的事件指针。
 * @note 事件在本 CPU 槽内组装，enter 探针末尾写入暂存表，由对应 exit 探针提交。
 * @note 先检查角色白名单，通过后才占用事件槽。
 */
static __always_inline struct syscall_event *init_credential_event(
    enum syscall_event_name name)
{
    if (!hng_should_collect()) return NULL;
    struct syscall_event *event = hng_scratch_event();
    if (!event) return NULL;
    init_syscall_event_head(&event->hdr, name);
    //! @note 载荷整体清零：各系统调用只填自己的字段，其余保持初值
    __builtin_memset(&event->credential_event, 0,
                     sizeof(event->credential_event));
    return event;
}

/**
 * @brief 初始化 namespace_event，并取本 CPU 的事件暂存槽。
 * @param[in] name 系统调用事件名。
 * @return 角色被过滤或槽不可用时返回 NULL，否则返回暂存槽内的事件指针。
 * @note 事件在本 CPU 槽内组装，enter 探针末尾写入暂存表，由对应 exit 探针提交。
 * @note 先检查角色白名单，通过后才占用事件槽。
 */
static __always_inline struct syscall_event *init_namespace_event(
    enum syscall_event_name name)
{
    if (!hng_should_collect()) return NULL;
    struct syscall_event *event = hng_scratch_event();
    if (!event) return NULL;
    init_syscall_event_head(&event->hdr, name);
    //! @note 载荷整体清零：各系统调用只填自己的字段，其余保持初值
    __builtin_memset(&event->namespace_event, 0, sizeof(event->namespace_event));
    //! @note 无目标 fd 时保持哨兵值，避免与合法的 fd 0 混淆
    event->namespace_event.fd = -1;
    return event;
}

/**
 * @brief 初始化 file_event，并取本 CPU 的事件暂存槽。
 * @param[in] name 系统调用事件名。
 * @return 角色被过滤或槽不可用时返回 NULL，否则返回暂存槽内的事件指针。
 * @note 事件在本 CPU 槽内组装，enter 探针末尾写入暂存表，由对应 exit 探针提交。
 * @note 先检查角色白名单，通过后才占用事件槽。
 */
static __always_inline struct syscall_event *init_file_event(
    enum syscall_event_name name)
{
    if (!hng_should_collect()) return NULL;
    struct syscall_event *event = hng_scratch_event();
    if (!event) return NULL;
    init_syscall_event_head(&event->hdr, name);
    //! @note 载荷整体清零：各系统调用只填自己的字段，其余保持初值
    __builtin_memset(&event->file_event, 0, sizeof(event->file_event));
    event->file_event.dirfd  = AT_FDCWD;
    event->file_event.dirfd2 = AT_FDCWD;
    //! @note 无 fd 参数时保持哨兵值，与合法的 fd 0 区分
    event->file_event.fd     = -1;
    return event;
}

/**
 * @brief 初始化 memory_event，并取本 CPU 的事件暂存槽。
 * @param[in] name 系统调用事件名。
 * @return 角色被过滤或槽不可用时返回 NULL，否则返回暂存槽内的事件指针。
 * @note 事件在本 CPU 槽内组装，enter 探针末尾写入暂存表，由对应 exit 探针提交。
 * @note 先检查角色白名单，通过后才占用事件槽。
 */
static __always_inline struct syscall_event *init_memory_event(
    enum syscall_event_name name)
{
    if (!hng_should_collect()) return NULL;
    struct syscall_event *event = hng_scratch_event();
    if (!event) return NULL;
    init_syscall_event_head(&event->hdr, name);
    __builtin_memset(event->memory_event.path, 0,
                     sizeof(event->memory_event.path));
    event->memory_event.prot       = 0;
    event->memory_event.flags      = 0;
    event->memory_event.addr       = 0;
    event->memory_event.length     = 0;
    event->memory_event.offset     = 0;
    //! @note 无源 fd（匿名映射、mprotect）保持哨兵 -1，与合法的 fd 0 区分
    event->memory_event.fd         = -1;
    event->memory_event.anonymous  = 0;
    event->memory_event.wx         = 0;
    event->memory_event.path_flags = 0;
    return event;
}

/**
 * @brief 初始化 network_event，并取本 CPU 的事件暂存槽。
 * @param[in] name 系统调用事件名。
 * @return 角色被过滤或槽不可用时返回 NULL，否则返回暂存槽内的事件指针。
 * @note 事件在本 CPU 槽内组装，enter 探针末尾写入暂存表，由对应 exit 探针提交。
 * @note 先检查角色白名单，通过后才占用事件槽。
 */
static __always_inline struct syscall_event *init_network_event(
    enum syscall_event_name name)
{
    if (!hng_should_collect()) return NULL;
    struct syscall_event *event = hng_scratch_event();
    if (!event) return NULL;
    init_syscall_event_head(&event->hdr, name);
    //! @note 载荷整体清零：各系统调用只填自己的字段，其余保持初值
    __builtin_memset(&event->network_event, 0, sizeof(event->network_event));
    //! @note socket 的新 fd 在返回值里，enter 阶段的 sockfd 保持哨兵 -1
    event->network_event.sockfd = -1;
    return event;
}

/**
 * @brief 初始化 kernel_event，并取本 CPU 的事件暂存槽。
 * @param[in] name 系统调用事件名。
 * @return 角色被过滤或槽不可用时返回 NULL，否则返回暂存槽内的事件指针。
 * @note 事件在本 CPU 槽内组装，enter 探针末尾写入暂存表，由对应 exit 探针提交。
 * @note 先检查角色白名单，通过后才占用事件槽。
 */
static __always_inline struct syscall_event *init_kernel_event(
    enum syscall_event_name name)
{
    if (!hng_should_collect()) return NULL;
    struct syscall_event *event = hng_scratch_event();
    if (!event) return NULL;
    init_syscall_event_head(&event->hdr, name);
    //! @note 载荷整体清零：各系统调用只填自己的字段，其余保持初值
    __builtin_memset(&event->kernel_event, 0, sizeof(event->kernel_event));
    return event;
}

/**
 * @brief 初始化 signal_event，并取本 CPU 的事件暂存槽。
 * @param[in] name 系统调用事件名。
 * @return 角色被过滤或槽不可用时返回 NULL，否则返回暂存槽内的事件指针。
 * @note 事件在本 CPU 槽内组装，enter 探针末尾写入暂存表，由对应 exit 探针提交。
 * @note 先检查角色白名单，通过后才占用事件槽。
 */
static __always_inline struct syscall_event *init_signal_event(
    enum syscall_event_name name)
{
    if (!hng_should_collect()) return NULL;
    struct syscall_event *event = hng_scratch_event();
    if (!event) return NULL;
    init_syscall_event_head(&event->hdr, name);
    __builtin_memset(&event->signal_event, 0, sizeof(event->signal_event));
    return event;
}

/**
 * @brief 初始化 kernel 类 tracepoint 事件，并直接预留 ringbuf 空间。
 * @param[in] name 事件名。
 * @return 成功时返回可直接填写的记录指针；空间不足时返回 NULL。
 * @note 这类事件不经 enter/exit 配对，调用者填完即提交。
 */
static __always_inline struct syscall_event *init_kernel_trace_event(
    enum syscall_event_name name)
{
    struct syscall_event *event = bpf_ringbuf_reserve(
        &syscall_events,
        sizeof(struct syscall_event_head) + sizeof(struct kernel_event), 0);
    if (!event) {
        count_reserve_failure();
        return NULL;
    }
    init_syscall_event_head(&event->hdr, name);
    __builtin_memset(&event->kernel_event, 0, sizeof(event->kernel_event));
    return event;
}

/** @} */
#endif
