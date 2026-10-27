/**
 * @file syscalls.bpf.c
 * @brief 监控关键系统调用
 * @details 收集带语义的系统调用信息。
 *
 * 这个模块收集的数据将用于马尔科夫序列的基线学习，或
 * 结合序列基线进行异常分析。因此获取的信息应当具有语义、能反映行为特征。
 *
 * @author red_shinku
 * @date 2026.08.06
 */

#include "kernel/include/vmlinux.h"
#include "kernel/include/role_filter.bpf.h"
#include "kernel/include/syscalls_type.h"
#include "kernel/include/uapi_const.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

//! @note PF_KTHREAD（内核线程标志，include/linux/sched.h），非 UAPI，此处显式取值
#define PF_KTHREAD 0x00200000

/**
 * @brief RingBuf，存储syscall事件的数据
 *       用户态程序通过该结构获取事件数据
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} syscall_events SEC(".maps");

/**
 * @name 各事件类型的初始化函数，分配 ringbuf 空间并初始化事件头。
 * 统一分配 sizeof(struct syscall_event)，通过 union 成员访问各事件字段。
 * @{
 */

/**
 * @brief 初始化 process_event，并预留 ringbuf 事件空间。
 * @param[in] name 系统调用事件名。
 * @return 成功时返回事件指针；空间不足时返回 NULL。
 * @note 调用者须对返回的事件执行提交或丢弃，完成 ringbuf 资源处理。
 * @note 生命周期事件绕过角色过滤，以维护完整进程树。
 */
static __always_inline struct syscall_event *init_process_event(
    enum syscall_event_name name)
{
    struct syscall_event *event =
        bpf_ringbuf_reserve(&syscall_events, sizeof(struct syscall_event), 0);
    if (!event) {
        return NULL;
    }
    init_syscall_event_head(&event->hdr, name);
    event->process_event.exit_code = 0;
    return event;
}

/**
 * @brief 初始化 exec_event，并预留 ringbuf 事件空间。
 * @param[in] name 系统调用事件名。
 * @return 成功时返回事件指针；空间不足时返回 NULL。
 * @note 调用者须对返回的事件执行提交或丢弃，完成 ringbuf 资源处理。
 * @note 生命周期事件绕过角色过滤，以维护完整进程树。
 */
static __always_inline struct syscall_event *init_exec_event(
    enum syscall_event_name name)
{
    struct syscall_event *event =
        bpf_ringbuf_reserve(&syscall_events, sizeof(struct syscall_event), 0);
    if (!event) {
        return NULL;
    }
    init_syscall_event_head(&event->hdr, name);
    __builtin_memset(event->exec_event.filename, 0,
                     sizeof(event->exec_event.filename));
    __builtin_memset(event->exec_event.argv0, 0, sizeof(event->exec_event.argv0));
    __builtin_memset(event->exec_event.argv1, 0, sizeof(event->exec_event.argv1));
    event->exec_event.flags = 0;
    return event;
}

/**
 * @brief 初始化 credential_event，并预留 ringbuf 事件空间。
 * @param[in] name 系统调用事件名。
 * @return 成功时返回事件指针；角色被过滤或空间不足时返回 NULL。
 * @note 调用者须对返回的事件执行提交或丢弃，完成 ringbuf 资源处理。
 * @note 先检查角色白名单，通过后才分配 ringbuf 空间。
 */
static __always_inline struct syscall_event *init_credential_event(
    enum syscall_event_name name)
{
    if (!hng_should_collect()) return NULL;
    struct syscall_event *event =
        bpf_ringbuf_reserve(&syscall_events, sizeof(struct syscall_event), 0);
    if (!event) {
        return NULL;
    }
    init_syscall_event_head(&event->hdr, name);
    //! @note 联合体整体清零（capset 为最大成员，覆盖整个 union）
    event->credential_event.capset.effective   = 0;
    event->credential_event.capset.permitted   = 0;
    event->credential_event.capset.inheritable = 0;
    return event;
}

/**
 * @brief 初始化 namespace_event，并预留 ringbuf 事件空间。
 * @param[in] name 系统调用事件名。
 * @return 成功时返回事件指针；角色被过滤或空间不足时返回 NULL。
 * @note 调用者须对返回的事件执行提交或丢弃，完成 ringbuf 资源处理。
 * @note 先检查角色白名单，通过后才分配 ringbuf 空间。
 */
static __always_inline struct syscall_event *init_namespace_event(
    enum syscall_event_name name)
{
    if (!hng_should_collect()) return NULL;
    struct syscall_event *event =
        bpf_ringbuf_reserve(&syscall_events, sizeof(struct syscall_event), 0);
    if (!event) {
        return NULL;
    }
    init_syscall_event_head(&event->hdr, name);
    event->namespace_event.ns_type = 0;
    event->namespace_event.flags   = 0;
    return event;
}

/**
 * @brief 初始化 file_event，并预留 ringbuf 事件空间。
 * @param[in] name 系统调用事件名。
 * @return 成功时返回事件指针；角色被过滤或空间不足时返回 NULL。
 * @note 调用者须对返回的事件执行提交或丢弃，完成 ringbuf 资源处理。
 * @note 先检查角色白名单，通过后才分配 ringbuf 空间。
 */
static __always_inline struct syscall_event *init_file_event(
    enum syscall_event_name name)
{
    if (!hng_should_collect()) return NULL;
    struct syscall_event *event =
        bpf_ringbuf_reserve(&syscall_events, sizeof(struct syscall_event), 0);
    if (!event) {
        return NULL;
    }
    init_syscall_event_head(&event->hdr, name);
    event->file_event.flags = 0;
    event->file_event.mode  = 0;
    return event;
}

/**
 * @brief 初始化 memory_event，并预留 ringbuf 事件空间。
 * @param[in] name 系统调用事件名。
 * @return 成功时返回事件指针；角色被过滤或空间不足时返回 NULL。
 * @note 调用者须对返回的事件执行提交或丢弃，完成 ringbuf 资源处理。
 * @note 先检查角色白名单，通过后才分配 ringbuf 空间。
 */
static __always_inline struct syscall_event *init_memory_event(
    enum syscall_event_name name)
{
    if (!hng_should_collect()) return NULL;
    struct syscall_event *event =
        bpf_ringbuf_reserve(&syscall_events, sizeof(struct syscall_event), 0);
    if (!event) {
        return NULL;
    }
    init_syscall_event_head(&event->hdr, name);
    event->memory_event.prot  = 0;
    event->memory_event.flags = 0;
    return event;
}

/**
 * @brief 初始化 network_event，并预留 ringbuf 事件空间。
 * @param[in] name 系统调用事件名。
 * @return 成功时返回事件指针；角色被过滤或空间不足时返回 NULL。
 * @note 调用者须对返回的事件执行提交或丢弃，完成 ringbuf 资源处理。
 * @note 先检查角色白名单，通过后才分配 ringbuf 空间。
 */
static __always_inline struct syscall_event *init_network_event(
    enum syscall_event_name name)
{
    if (!hng_should_collect()) return NULL;
    struct syscall_event *event =
        bpf_ringbuf_reserve(&syscall_events, sizeof(struct syscall_event), 0);
    if (!event) {
        return NULL;
    }
    init_syscall_event_head(&event->hdr, name);
    event->network_event.family   = 0;
    event->network_event.type     = 0;
    event->network_event.protocol = 0;
    return event;
}

/**
 * @brief 初始化 kernel_event，并预留 ringbuf 事件空间。
 * @param[in] name 系统调用事件名。
 * @return 成功时返回事件指针；角色被过滤或空间不足时返回 NULL。
 * @note 调用者须对返回的事件执行提交或丢弃，完成 ringbuf 资源处理。
 * @note 先检查角色白名单，通过后才分配 ringbuf 空间。
 */
static __always_inline struct syscall_event *init_kernel_event(
    enum syscall_event_name name)
{
    if (!hng_should_collect()) return NULL;
    struct syscall_event *event =
        bpf_ringbuf_reserve(&syscall_events, sizeof(struct syscall_event), 0);
    if (!event) {
        return NULL;
    }
    init_syscall_event_head(&event->hdr, name);
    event->kernel_event.command = 0;
    event->kernel_event.arg     = 0;
    return event;
}

/** @} */

/**
 * @name PROCESS_EVENT 类别的进程生命周期拦截
 * @{
 */

/**
 * @brief 进程诞生事件（fork / clone / vfork / clone3 创建新线程组）
 * @details
 * fork 类 sys_enter tracepoint 触发于子进程存在之前，只能拿到父进程身份，
 * 无法提供新进程。故使用 kprobe wake_up_new_task：入参即新任务的 task_struct，
 * 事件头手动填为 新进程为主体——pid=子 tgid+start_time、ppid=父进程，满足
 * "fork 事件给出子进程身份"。原 fork/clone/vfork 的区分及 clone_flags 不再采集；
 * 线程/内核线程在此直接过滤。
 * @param[in] ctx kprobe 寄存器上下文，PARM1 = struct task_struct *child。
 * @return 始终返回 0；线程、内核线程及事件空间不足时跳过提交。
 */
SEC("kprobe/wake_up_new_task")
int trace_process_birth(struct pt_regs *ctx)
{
    struct task_struct *child = (struct task_struct *)PT_REGS_PARM1(ctx);
    if (!child) {
        return 0;
    }

    //! @note 仅"新线程组"构成新进程：线程（clone 共享 tgid）与内核线程不产生进程上下文
    __u32 child_pid  = BPF_CORE_READ(child, pid);
    __u32 child_tgid = BPF_CORE_READ(child, tgid);
    if (child_pid != child_tgid) {
        return 0;  /** @note 线程创建。 */
    }
    if (BPF_CORE_READ(child, flags) & PF_KTHREAD) {
        return 0;  /** @note 内核线程。 */
    }

    struct task_struct *parent = BPF_CORE_READ(child, real_parent);
    if (!parent) {
        return 0;
    }

    struct syscall_event *event = init_process_event(SYSCALL_EVENT_FORK);
    if (!event) {
        return 0;
    }
    /**
     * @note 事件头 = 新进程自身：与子进程后续事件经 init_event_head 产出的头部一致，
     * (pid/pid_start_time, ppid/ppid_start_time) 可精确作为 Process 键与父进程键
     */
    event->hdr.head.pid             = child_tgid;
    event->hdr.head.pid_start_time =
        BPF_CORE_READ(child, start_boottime) / NSEC_PER_USER_HZ;
    event->hdr.head.ppid            = BPF_CORE_READ(parent, tgid);
    event->hdr.head.ppid_start_time =
        BPF_CORE_READ(parent, start_boottime) / NSEC_PER_USER_HZ;

    bpf_ringbuf_submit(event, 0);
    return 0;
}

/**
 * @brief 处理 sys_enter_exit_group 事件并提交采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过提交。
 */
SEC("tracepoint/syscalls/sys_enter_exit_group")
int trace_exit_group(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_process_event(SYSCALL_EVENT_EXIT_GROUP);
    if (!event) return 0;

    //! @note args[0]: int error_code
    event->process_event.exit_code = (s32)ctx->args[0];

    bpf_ringbuf_submit(event, 0);
    return 0;
}

/** @} */

/**
 * @name EXEC_EVENT 类别的 syscall 拦截
 * @{
 */

/**
 * @brief 处理 sys_enter_execve 事件并提交采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过提交。
 */
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_exec_event(SYSCALL_EVENT_EXECVE);
    if (!event) return 0;

    //! @note args[0]: const char *filename
    bpf_probe_read_user_str(&event->exec_event.filename,
                            sizeof(event->exec_event.filename),
                            (void *)ctx->args[0]);

    //! @note args[1]: char *const argv[] — 读取 argv[0]/argv[1]
    const char *arg0_ptr = NULL;
    const char *arg1_ptr = NULL;
    if (bpf_probe_read_user(&arg0_ptr, sizeof(arg0_ptr), (void *)ctx->args[1]) ==
            0 &&
        arg0_ptr) {
        bpf_probe_read_user_str(&event->exec_event.argv0,
                                sizeof(event->exec_event.argv0), arg0_ptr);
    }
    //! @note argv[1] = argv 数组第二个元素（用户可空终止，读取失败留空）
    if (bpf_probe_read_user(&arg1_ptr, sizeof(arg1_ptr),
                            (void *)(ctx->args[1] + sizeof(char *))) == 0 &&
        arg1_ptr) {
        bpf_probe_read_user_str(&event->exec_event.argv1,
                                sizeof(event->exec_event.argv1), arg1_ptr);
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

/**
 * @brief 处理 sys_enter_execveat 事件并提交采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过提交。
 */
SEC("tracepoint/syscalls/sys_enter_execveat")
int trace_execveat(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_exec_event(SYSCALL_EVENT_EXECVEAT);
    if (!event) return 0;

    //! @note args[1]: const char *filename
    bpf_probe_read_user_str(&event->exec_event.filename,
                            sizeof(event->exec_event.filename),
                            (void *)ctx->args[1]);

    //! @note args[2]: char *const argv[] — 读取 argv[0]/argv[1]
    const char *arg0_ptr = NULL;
    const char *arg1_ptr = NULL;
    if (bpf_probe_read_user(&arg0_ptr, sizeof(arg0_ptr), (void *)ctx->args[2]) ==
            0 &&
        arg0_ptr) {
        bpf_probe_read_user_str(&event->exec_event.argv0,
                                sizeof(event->exec_event.argv0), arg0_ptr);
    }
    //! @note argv[1] = argv 数组第二个元素
    if (bpf_probe_read_user(&arg1_ptr, sizeof(arg1_ptr),
                            (void *)(ctx->args[2] + sizeof(char *))) == 0 &&
        arg1_ptr) {
        bpf_probe_read_user_str(&event->exec_event.argv1,
                                sizeof(event->exec_event.argv1), arg1_ptr);
    }

    //! @note args[4]: int flags
    event->exec_event.flags = (u32)ctx->args[4];

    bpf_ringbuf_submit(event, 0);
    return 0;
}

/** @} */

/**
 * @name CREDENTIAL_EVENT 类别的 syscall 拦截
 * @{
 */

/**
 * @brief 处理 sys_enter_setuid 事件并提交采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过提交。
 */
SEC("tracepoint/syscalls/sys_enter_setuid")
int trace_setuid(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_credential_event(SYSCALL_EVENT_SETUID);
    if (!event) return 0;

    //! @note args[0]: uid_t uid
    event->credential_event.setuid.uid = (u32)ctx->args[0];

    bpf_ringbuf_submit(event, 0);
    return 0;
}

/**
 * @brief 处理 sys_enter_setgid 事件并提交采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过提交。
 */
SEC("tracepoint/syscalls/sys_enter_setgid")
int trace_setgid(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_credential_event(SYSCALL_EVENT_SETGID);
    if (!event) return 0;

    //! @note args[0]: gid_t gid
    event->credential_event.setgid.gid = (u32)ctx->args[0];

    bpf_ringbuf_submit(event, 0);
    return 0;
}

/**
 * @brief 处理 sys_enter_capset 事件并提交采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过提交。
 */
SEC("tracepoint/syscalls/sys_enter_capset")
int trace_capset(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_credential_event(SYSCALL_EVENT_CAPSET);
    if (!event) return 0;

    /**
     * @note args[1]: const cap_user_data_t datap — 指向 struct
     * __user_cap_data_struct[2]
     *   data[0] 为 capabilities 0-31，data[1] 为 capabilities 32-63
     *   合并为 64 位值以兼容 v2/v3 能力集
     */
    struct __user_cap_data_struct cap_data[2];
    if (bpf_probe_read_user(cap_data, sizeof(cap_data), (void *)ctx->args[1]) ==
        0) {
        event->credential_event.capset.effective =
            ((u64)cap_data[1].effective << 32) | cap_data[0].effective;
        event->credential_event.capset.permitted =
            ((u64)cap_data[1].permitted << 32) | cap_data[0].permitted;
        event->credential_event.capset.inheritable =
            ((u64)cap_data[1].inheritable << 32) | cap_data[0].inheritable;
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

/** @} */

/**
 * @name NAMESPACE_EVENT 类别的 syscall 拦截
 * @{
 */

/**
 * @brief 处理 sys_enter_unshare 事件并提交采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过提交。
 */
SEC("tracepoint/syscalls/sys_enter_unshare")
int trace_unshare(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_namespace_event(SYSCALL_EVENT_UNSHARE);
    if (!event) return 0;

    //! @note args[0]: int unshare_flags (CLONE_NEW*)
    u64 flags                    = ctx->args[0];
    event->namespace_event.flags = flags;

    //! @note 提取涉及的 namespace 类型
    if (flags & CLONE_NEWNS)
        event->namespace_event.ns_type = CLONE_NEWNS;
    else if (flags & CLONE_NEWUTS)
        event->namespace_event.ns_type = CLONE_NEWUTS;
    else if (flags & CLONE_NEWIPC)
        event->namespace_event.ns_type = CLONE_NEWIPC;
    else if (flags & CLONE_NEWNET)
        event->namespace_event.ns_type = CLONE_NEWNET;
    else if (flags & CLONE_NEWUSER)
        event->namespace_event.ns_type = CLONE_NEWUSER;
    else if (flags & CLONE_NEWPID)
        event->namespace_event.ns_type = CLONE_NEWPID;
    else if (flags & CLONE_NEWCGROUP)
        event->namespace_event.ns_type = CLONE_NEWCGROUP;

    bpf_ringbuf_submit(event, 0);
    return 0;
}

/**
 * @brief 处理 sys_enter_setns 事件并提交采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过提交。
 */
SEC("tracepoint/syscalls/sys_enter_setns")
int trace_setns(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_namespace_event(SYSCALL_EVENT_SETNS);
    if (!event) return 0;

    event->namespace_event.ns_type = (u32)ctx->args[1];
    event->namespace_event.flags   = 0;

    bpf_ringbuf_submit(event, 0);
    return 0;
}

/** @} */

/**
 * @name FILE_EVENT 类别的 syscall 拦截
 * @{
 */

/**
 * @brief 处理 sys_enter_open 事件并提交采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过提交。
 */
SEC("tracepoint/syscalls/sys_enter_open")
int trace_syscall_open(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_file_event(SYSCALL_EVENT_OPEN);
    if (!event) return 0;

    event->file_event.flags = (u32)ctx->args[1];
    event->file_event.mode  = (u32)ctx->args[2];

    bpf_ringbuf_submit(event, 0);
    return 0;
}

/**
 * @brief 处理 sys_enter_openat 事件并提交采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过提交。
 */
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_syscall_openat(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_file_event(SYSCALL_EVENT_OPENAT);
    if (!event) return 0;

    event->file_event.flags = (u32)ctx->args[2];
    event->file_event.mode  = (u32)ctx->args[3];

    bpf_ringbuf_submit(event, 0);
    return 0;
}

/**
 * @brief 处理 sys_enter_openat2 事件并提交采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过提交。
 */
SEC("tracepoint/syscalls/sys_enter_openat2")
int trace_syscall_openat2(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_file_event(SYSCALL_EVENT_OPENAT2);
    if (!event) return 0;

    struct open_how how;
    if (bpf_probe_read_user(&how, sizeof(how), (void *)ctx->args[2]) == 0) {
        event->file_event.flags = (u32)how.flags;
        event->file_event.mode  = (u32)how.mode;
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

/**
 * @brief 处理 sys_enter_creat 事件并提交采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过提交。
 */
SEC("tracepoint/syscalls/sys_enter_creat")
int trace_syscall_creat(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_file_event(SYSCALL_EVENT_CREAT);
    if (!event) return 0;

    //! @note creat() 隐含了 O_CREAT | O_WRONLY | O_TRUNC
    event->file_event.flags = O_CREAT | O_WRONLY | O_TRUNC;
    //! @note args[1]: umode_t mode
    event->file_event.mode  = (u32)ctx->args[1];

    bpf_ringbuf_submit(event, 0);
    return 0;
}

/**
 * @brief 处理 sys_enter_unlink 事件并提交采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过提交。
 */
SEC("tracepoint/syscalls/sys_enter_unlink")
int trace_syscall_unlink(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_file_event(SYSCALL_EVENT_UNLINK);
    if (!event) return 0;

    bpf_ringbuf_submit(event, 0);
    return 0;
}

/**
 * @brief 处理 sys_enter_link 事件并提交采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过提交。
 */
SEC("tracepoint/syscalls/sys_enter_link")
int trace_syscall_link(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_file_event(SYSCALL_EVENT_LINK);
    if (!event) return 0;

    bpf_ringbuf_submit(event, 0);
    return 0;
}

/**
 * @brief 处理 sys_enter_rename 事件并提交采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过提交。
 */
SEC("tracepoint/syscalls/sys_enter_rename")
int trace_syscall_rename(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_file_event(SYSCALL_EVENT_RENAME);
    if (!event) return 0;

    bpf_ringbuf_submit(event, 0);
    return 0;
}

/**
 * @brief 处理 sys_enter_renameat 事件并提交采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过提交。
 */
SEC("tracepoint/syscalls/sys_enter_renameat")
int trace_syscall_renameat(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_file_event(SYSCALL_EVENT_RENAMEAT);
    if (!event) return 0;

    bpf_ringbuf_submit(event, 0);
    return 0;
}

/**
 * @brief 处理 sys_enter_renameat2 事件并提交采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过提交。
 */
SEC("tracepoint/syscalls/sys_enter_renameat2")
int trace_syscall_renameat2(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_file_event(SYSCALL_EVENT_RENAMEAT2);
    if (!event) return 0;

    event->file_event.flags = (u32)ctx->args[4];

    bpf_ringbuf_submit(event, 0);
    return 0;
}

/** @} */

/**
 * @name MEMORY_EVENT 类别的 syscall 拦截
 * @{
 */

/**
 * @brief 处理 sys_enter_mmap 事件并提交采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过提交。
 */
SEC("tracepoint/syscalls/sys_enter_mmap")
int trace_mmap(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_memory_event(SYSCALL_EVENT_MMAP);
    if (!event) return 0;

    //! @note args[2]: int prot (PROT_*)
    event->memory_event.prot  = ctx->args[2];
    //! @note args[3]: int flags (MAP_*)
    event->memory_event.flags = ctx->args[3];

    bpf_ringbuf_submit(event, 0);
    return 0;
}

/**
 * @brief 处理 sys_enter_mprotect 事件并提交采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过提交。
 */
SEC("tracepoint/syscalls/sys_enter_mprotect")
int trace_mprotect(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_memory_event(SYSCALL_EVENT_MPROTECT);
    if (!event) return 0;

    //! @note args[2]: int prot (PROT_*)
    event->memory_event.prot = ctx->args[2];

    bpf_ringbuf_submit(event, 0);
    return 0;
}

/** @} */

/**
 * @name NETWORK_EVENT 类别的 syscall 拦截
 * @{
 */

/**
 * @brief 处理 sys_enter_connect 事件并提交采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过提交。
 */
SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_network_event(SYSCALL_EVENT_CONNECT);
    if (!event) return 0;

    struct sockaddr sa;
    if (bpf_probe_read_user(&sa, sizeof(sa), (void *)ctx->args[1]) == 0) {
        event->network_event.family = sa.sa_family;
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

/**
 * @brief 处理 sys_enter_socket 事件并提交采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过提交。
 */
SEC("tracepoint/syscalls/sys_enter_socket")
int trace_socket(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_network_event(SYSCALL_EVENT_SOCKET);
    if (!event) return 0;

    event->network_event.family   = (u32)ctx->args[0];
    event->network_event.type     = (u32)ctx->args[1];
    event->network_event.protocol = (u32)ctx->args[2];

    bpf_ringbuf_submit(event, 0);
    return 0;
}

/**
 * @brief 处理 sys_enter_bind 事件并提交采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过提交。
 */
SEC("tracepoint/syscalls/sys_enter_bind")
int trace_bind(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_network_event(SYSCALL_EVENT_BIND);
    if (!event) return 0;

    //! @note args[1]: const struct sockaddr *addr
    struct sockaddr sa;
    if (bpf_probe_read_user(&sa, sizeof(sa), (void *)ctx->args[1]) == 0) {
        event->network_event.family = sa.sa_family;
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

/** @} */

/**
 * @name KERNEL_EVENT 类别的 syscall 拦截
 * @{
 */

/**
 * @brief 处理 sys_enter_ptrace 事件并提交采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过提交。
 */
SEC("tracepoint/syscalls/sys_enter_ptrace")
int trace_ptrace(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_kernel_event(SYSCALL_EVENT_PTRACE);
    if (!event) return 0;

    //! @note args[0]: int request (PTRACE_*)
    event->kernel_event.command = (u32)ctx->args[0];
    //! @note args[1]: pid_t pid — 目标进程
    event->kernel_event.arg     = ctx->args[1];

    bpf_ringbuf_submit(event, 0);
    return 0;
}

/**
 * @brief 处理 sys_enter_bpf 事件并提交采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过提交。
 */
SEC("tracepoint/syscalls/sys_enter_bpf")
int trace_bpf(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_kernel_event(SYSCALL_EVENT_BPF);
    if (!event) return 0;

    //! @note args[0]: int cmd (BPF_*)
    event->kernel_event.command = (u32)ctx->args[0];
    //! @note args[2]: unsigned int size — attr 大小（可用于推断 BPF 命令版本）
    event->kernel_event.arg     = ctx->args[2];

    bpf_ringbuf_submit(event, 0);
    return 0;
}

/** @} */

char LICENSE[] SEC("license") = "GPL";
