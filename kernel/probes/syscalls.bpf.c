/**
 * @file syscalls.bpf.c
 * @brief 监控关键系统调用
 * @details 收集带语义的系统调用信息。
 *
 * 被采集的系统调用采用 enter 暂存、exit 提交：enter 探针把组装好的事件写入
 * hng_pending，对应 exit 探针取回、补上返回值后提交 ringbuf。事件因此按完成序
 * 下发，头里的 ret 是真实返回值。
 *
 * @author red_shinku
 * @date 2026.08.06
 */

#include "kernel/include/vmlinux.h"
#include "kernel/include/syscall_event_type.h"
#include "kernel/include/uapi_const.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "kernel/src/syscall_event_builders.bpf.h"
#include "kernel/src/syscall_event_commit.bpf.h"
#include "kernel/src/socket_helpers.bpf.h"
#include "kernel/src/exec_helpers.bpf.h"
#include "kernel/src/syscall_path_helpers.bpf.h"
#include "kernel/src/kernel_helpers.bpf.h"

//! @note PF_KTHREAD（内核线程标志，include/linux/sched.h），非 UAPI，此处显式取值
#define PF_KTHREAD 0x00200000

/// @brief memfd_create 的路径前缀：匿名文件没有可解析的路径
#define HNG_MEMFD_PREFIX "memfd:"

/// @brief 七个 CLONE_NEW* 命名空间标志之并（include/uapi/linux/sched.h）
#define HNG_CLONE_NEW_ALL                                                       \
    (CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWUSER | CLONE_NEWPID | \
     CLONE_NEWNET | CLONE_NEWCGROUP)

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

    //! @note 仅"新线程组"构成新进程：线程（clone 共享
    //! tgid）与内核线程不产生进程上下文
    __u32 child_pid  = BPF_CORE_READ(child, pid);
    __u32 child_tgid = BPF_CORE_READ(child, tgid);
    if (child_pid != child_tgid) {
        return 0; /** @note 线程创建。 */
    }
    if (BPF_CORE_READ(child, flags) & PF_KTHREAD) {
        return 0; /** @note 内核线程。 */
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
     * @note 事件头 = 新进程自身：与子进程后续事件经 init_event_head
     * 产出的头部一致， (pid/pid_start_time, ppid/ppid_start_time) 可精确作为
     * Process 键与父进程键。fork 可能发生在父进程的普通线程上，父进程键按该
     * 线程的组长取，见 @ref init_event_head_parent
     */
    init_event_head_self(&event->hdr.head, child);
    init_event_head_parent(&event->hdr.head, parent);

    /**
     * @note 派生位：与发起创建的 current 比较。CLONE_PARENT 时子进程的
     *       real_parent 不是 current，据此置位；线程已被上方过滤。
     */
    __u8 derived                = 0;
    struct task_struct *creator = (struct task_struct *)bpf_get_current_task();
    if (creator) {
        struct mm_struct *child_mm = BPF_CORE_READ(child, mm);
        if (child_mm && child_mm == BPF_CORE_READ(creator, mm)) {
            derived |= HNG_PROCESS_DERIVED_SHARED_MM;
        }
        if (BPF_CORE_READ(child, real_parent) != creator) {
            derived |= HNG_PROCESS_DERIVED_PARENT;
        }
        if (BPF_CORE_READ(child, nsproxy) != BPF_CORE_READ(creator, nsproxy)) {
            derived |= HNG_PROCESS_DERIVED_NEW_NS;
        }
        const struct cred *child_cred   = BPF_CORE_READ(child, cred);
        const struct cred *creator_cred = BPF_CORE_READ(creator, cred);
        if (child_cred && creator_cred &&
            BPF_CORE_READ(child_cred, user_ns) !=
                BPF_CORE_READ(creator_cred, user_ns)) {
            derived |= HNG_PROCESS_DERIVED_NEW_USER_NS;
        }
    }
    event->process_event.derived_flags = derived;

    bpf_ringbuf_submit(event, 0);
    return 0;
}

/**
 * @brief 处理 sched_process_exit 事件并提交采集结果。
 * @return 始终返回 0；非线程组末线程、内核线程或无法构造事件时跳过提交。
 * @note 以线程组末线程的退出代表进程退出：exit_group 与信号终止两条路径都会
 *       经过该 tracepoint，故覆盖面与退出原因无关。
 * @note 6.14 起该 tracepoint 只带退出任务一个参数，线程组是否终结改由
 *       signal_struct::live 判定：do_exit 在触发 tracepoint 前已把它减到 0。
 * @note 事件头取线程组首领身份，而不是触发退出的线程：多线程进程最后退出的
 *       往往不是首领，按当前线程填会与 fork 事件记录的进程身份不一致。
 * @note 事件名沿用 SYSCALL_EVENT_EXIT_GROUP；exit_code 正常退出时为退出状态码，
 *       被信号终止时为终止信号的负数。
 */
SEC("tracepoint/sched/sched_process_exit")
int trace_process_exit(void *ctx)
{
    (void)ctx;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (BPF_CORE_READ(task, flags) & PF_KTHREAD) return 0;

    struct signal_struct *sig = BPF_CORE_READ(task, signal);
    if (!sig || BPF_CORE_READ(sig, live.counter) != 0) return 0;

    struct syscall_event *event = init_process_event(SYSCALL_EVENT_EXIT_GROUP);
    if (!event) return 0;

    init_event_head_self(&event->hdr.head, task);
    init_event_head_parent(&event->hdr.head, BPF_CORE_READ(task, real_parent));

    //! @note 低 7 位非零表示被信号终止，否则高位是退出状态码
    s32 code                         = BPF_CORE_READ(task, exit_code);
    //! @note 终止信号号独立保存，避免下游从 exit_code 的负数反推
    event->process_event.exit_signal = code & 0x7f;
    if (code & 0x7f) {
        event->process_event.exit_code = -(code & 0x7f);
    }
    else {
        event->process_event.exit_code = code >> 8;
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

/**
 * @brief 处理 task_rename tracepoint：记录改名前后进程名。
 * @param[in] ctx raw entry 上下文。
 * @return 始终返回 0；事件空间不足时跳过提交。
 * @note entry 布局：trace_entry(8) + pid(4) + oldcomm(16) + newcomm(16)；
 *       comm 在 vmlinux BTF 里是定长数组，读取函数同时兼容 __data_loc。
 * @note 事件头的主体取 current（发起改名的任务），tracepoint 的 pid 是被改名的
 *       任务，落在 target_pid：两者多数时候相同，但主体与身份必须自洽，不能把
 *       别的任务的 pid 填进当前任务的启动时间旁边。
 */
SEC("tracepoint/task/task_rename")
int trace_task_rename(void *ctx)
{
    struct syscall_event *event = init_process_event(SYSCALL_EVENT_TASK_RENAME);
    if (!event) return 0;

    bpf_probe_read_kernel(&event->process_event.target_pid,
                          sizeof(event->process_event.target_pid),
                          (const char *)ctx + 8);
    hng_read_trace_string(event->process_event.old_comm,
                          sizeof(event->process_event.old_comm), ctx, 12);
    hng_read_trace_string(event->process_event.new_comm,
                          sizeof(event->process_event.new_comm), ctx, 28);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

/**
 * @brief 处理 cgroup_attach_task tracepoint：记录目标 cgroup 路径。
 * @param[in] ctx raw entry 上下文。
 * @return 始终返回 0；事件空间不足时跳过提交。
 * @note entry 布局：trace_entry(8) + dst_root(4) + dst_id(4) +
 *       __data_loc path(4) + pid(4)，字符串数据在 entry 尾部。
 * @note 事件主体按约定取 current（发起迁移的进程），被迁移的任务落在
 *       target_pid（entry 偏移 20 的 pid）。
 */
SEC("tracepoint/cgroup/cgroup_attach_task")
int trace_cgroup_attach_task(void *ctx)
{
    struct syscall_event *event =
        init_process_event(SYSCALL_EVENT_CGROUP_ATTACH_TASK);
    if (!event) return 0;

    bpf_probe_read_kernel(&event->process_event.target_pid,
                          sizeof(event->process_event.target_pid),
                          (const char *)ctx + 20);
    hng_read_trace_string(event->process_event.cgroup_path,
                          sizeof(event->process_event.cgroup_path), ctx, 16);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

/** @} */

/**
 * @name EXEC_EVENT 类别的 syscall 拦截
 * @{
 */

/**
 * @brief 处理 sys_enter_execve 事件并暂存采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过暂存。
 */
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_exec_event(SYSCALL_EVENT_EXECVE);
    if (!event) return 0;

    //! @note args[0]: const char *filename — 用户原始输入，原样存入 invoked
    bpf_probe_read_user_str(&event->exec_event.invoked,
                            sizeof(event->exec_event.invoked),
                            (void *)ctx->args[0]);

    //! @note args[1]: char *const argv[], args[2]: char *const envp[] —
    //!       argv 取前四项，envp 只取两个 LD_* 变量的值
    fill_exec_argv(&event->exec_event, ctx->args[1]);
    fill_exec_env(&event->exec_event, ctx->args[2]);

    hng_stash_pending(event);
    return 0;
}

/**
 * @brief 处理 sys_enter_execveat 事件并暂存采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过暂存。
 */
SEC("tracepoint/syscalls/sys_enter_execveat")
int trace_execveat(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_exec_event(SYSCALL_EVENT_EXECVEAT);
    if (!event) return 0;

    //! @note args[1]: const char *filename — 用户原始输入，原样存入 invoked
    bpf_probe_read_user_str(&event->exec_event.invoked,
                            sizeof(event->exec_event.invoked),
                            (void *)ctx->args[1]);

    //! @note args[2]: char *const argv[], args[3]: char *const envp[] —
    //!       argv 取前四项，envp 只取两个 LD_* 变量的值
    fill_exec_argv(&event->exec_event, ctx->args[2]);
    fill_exec_env(&event->exec_event, ctx->args[3]);

    //! @note args[4]: int flags
    event->exec_event.flags = (u32)ctx->args[4];

    hng_stash_pending(event);
    return 0;
}

/** @} */

/**
 * @name CREDENTIAL_EVENT 类别的 syscall 拦截
 * @{
 */

/**
 * @brief 处理 sys_enter_setuid 事件并暂存采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过暂存。
 */
SEC("tracepoint/syscalls/sys_enter_setuid")
int trace_setuid(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_credential_event(SYSCALL_EVENT_SETUID);
    if (!event) return 0;

    //! @note args[0]: uid_t uid
    event->credential_event.kind            = CREDENTIAL_UID;
    event->credential_event.requested_count = 1;
    event->credential_event.requested[0]    = (u32)ctx->args[0];

    hng_stash_pending(event);
    return 0;
}

/**
 * @brief 处理 sys_enter_setgid 事件并暂存采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过暂存。
 */
SEC("tracepoint/syscalls/sys_enter_setgid")
int trace_setgid(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_credential_event(SYSCALL_EVENT_SETGID);
    if (!event) return 0;

    //! @note args[0]: gid_t gid
    event->credential_event.kind            = CREDENTIAL_GID;
    event->credential_event.requested_count = 1;
    event->credential_event.requested[0]    = (u32)ctx->args[0];

    hng_stash_pending(event);
    return 0;
}

/**
 * @brief 处理 sys_enter_capset 事件并暂存采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过暂存。
 */
SEC("tracepoint/syscalls/sys_enter_capset")
int trace_capset(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_credential_event(SYSCALL_EVENT_CAPSET);
    if (!event) return 0;

    //! @note requested_count 与 requested[] 保持 init 的 0，capset 无目标 ID
    event->credential_event.kind = CREDENTIAL_CAPS;

    /**
     * @note args[1]: const cap_user_data_t datap — 指向 struct
     * __user_cap_data_struct[2]
     *   data[0] 为 capabilities 0-31，data[1] 为 capabilities 32-63
     *   合并为 64 位值以兼容 v2/v3 能力集
     */
    struct __user_cap_data_struct cap_data[2];
    if (bpf_probe_read_user(cap_data, sizeof(cap_data), (void *)ctx->args[1]) ==
        0) {
        event->credential_event.cap_effective =
            ((u64)cap_data[1].effective << 32) | cap_data[0].effective;
        event->credential_event.cap_permitted =
            ((u64)cap_data[1].permitted << 32) | cap_data[0].permitted;
        event->credential_event.cap_inheritable =
            ((u64)cap_data[1].inheritable << 32) | cap_data[0].inheritable;
    }

    hng_stash_pending(event);
    return 0;
}

/** @} */

/**
 * @brief 处理 sys_enter_setreuid 事件并暂存采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过暂存。
 */
SEC("tracepoint/syscalls/sys_enter_setreuid")
int trace_setreuid(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_credential_event(SYSCALL_EVENT_SETREUID);
    if (!event) return 0;

    //! @note args[0]: uid_t ruid, args[1]: uid_t euid
    event->credential_event.kind            = CREDENTIAL_UID;
    event->credential_event.requested_count = 2;
    event->credential_event.requested[0]    = (u32)ctx->args[0];
    event->credential_event.requested[1]    = (u32)ctx->args[1];

    hng_stash_pending(event);
    return 0;
}

/**
 * @brief 处理 sys_enter_setresuid 事件并暂存采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过暂存。
 */
SEC("tracepoint/syscalls/sys_enter_setresuid")
int trace_setresuid(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_credential_event(SYSCALL_EVENT_SETRESUID);
    if (!event) return 0;

    //! @note args[0..2]: uid_t ruid, euid, suid
    event->credential_event.kind            = CREDENTIAL_UID;
    event->credential_event.requested_count = 3;
    event->credential_event.requested[0]    = (u32)ctx->args[0];
    event->credential_event.requested[1]    = (u32)ctx->args[1];
    event->credential_event.requested[2]    = (u32)ctx->args[2];

    hng_stash_pending(event);
    return 0;
}

/**
 * @brief 处理 sys_enter_setfsuid 事件并暂存采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过暂存。
 */
SEC("tracepoint/syscalls/sys_enter_setfsuid")
int trace_setfsuid(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_credential_event(SYSCALL_EVENT_SETFSUID);
    if (!event) return 0;

    //! @note args[0]: uid_t fsuid
    event->credential_event.kind            = CREDENTIAL_UID;
    event->credential_event.requested_count = 1;
    event->credential_event.requested[0]    = (u32)ctx->args[0];

    hng_stash_pending(event);
    return 0;
}

/**
 * @brief 处理 sys_enter_setresgid 事件并暂存采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过暂存。
 */
SEC("tracepoint/syscalls/sys_enter_setresgid")
int trace_setresgid(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_credential_event(SYSCALL_EVENT_SETRESGID);
    if (!event) return 0;

    //! @note args[0..2]: gid_t rgid, egid, sgid
    event->credential_event.kind            = CREDENTIAL_GID;
    event->credential_event.requested_count = 3;
    event->credential_event.requested[0]    = (u32)ctx->args[0];
    event->credential_event.requested[1]    = (u32)ctx->args[1];
    event->credential_event.requested[2]    = (u32)ctx->args[2];

    hng_stash_pending(event);
    return 0;
}

/**
 * @brief 处理 sys_enter_setgroups 事件并暂存采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过暂存。
 * @note 最多记录前三个补充组；size 超过 3 时只截取前三项，不表示完整集合。
 */
SEC("tracepoint/syscalls/sys_enter_setgroups")
int trace_setgroups(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_credential_event(SYSCALL_EVENT_SETGROUPS);
    if (!event) return 0;

    //! @note args[0]: int gidsetsize, args[1]: const gid_t *grouplist
    __u32 count = (__u32)ctx->args[0];
    if (count > 3) {
        count = 3;
    }
    event->credential_event.kind            = CREDENTIAL_GID;
    event->credential_event.requested_count = count;
    const __u32 *list                       = (const __u32 *)ctx->args[1];
    if (count >= 1) {
        bpf_probe_read_user(&event->credential_event.requested[0], sizeof(__u32),
                            &list[0]);
    }
    if (count >= 2) {
        bpf_probe_read_user(&event->credential_event.requested[1], sizeof(__u32),
                            &list[1]);
    }
    if (count >= 3) {
        bpf_probe_read_user(&event->credential_event.requested[2], sizeof(__u32),
                            &list[2]);
    }

    hng_stash_pending(event);
    return 0;
}

/**
 * @brief 处理 sys_enter_prctl 事件并暂存采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；option 与安全无关或无法构造事件时跳过暂存。
 * @note 只收安全相关的 option，其余不暂存以避免噪声；对应的 exit 探针
 *       因此按「可能合法跳过」处理，不计 pending_lost。
 */
SEC("tracepoint/syscalls/sys_enter_prctl")
int trace_prctl(struct trace_event_raw_sys_enter *ctx)
{
    //! @note args[0]: int option, args[1]: unsigned long arg2
    __u32 option = (u32)ctx->args[0];
    switch (option) {
        case PR_SET_NO_NEW_PRIVS:
        case PR_SET_SECUREBITS:
        case PR_SET_KEEPCAPS:
        case PR_CAPBSET_DROP:
        case PR_SET_DUMPABLE:
            break;
        default:
            return 0;
    }

    struct syscall_event *event = init_credential_event(SYSCALL_EVENT_PRCTL);
    if (!event) return 0;

    event->credential_event.kind         = CREDENTIAL_PRCTL;
    event->credential_event.prctl_option = option;
    event->credential_event.arg2         = ctx->args[1];
    //! @note securebits 只在 PR_SET_SECUREBITS 时由 arg2 给出
    if (option == PR_SET_SECUREBITS) {
        event->credential_event.securebits = (u32)ctx->args[1];
    }

    hng_stash_pending(event);
    return 0;
}

/**
 * @name NAMESPACE_EVENT 类别的 syscall 拦截
 * @{
 */

/**
 * @brief 处理 sys_enter_unshare 事件并暂存采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过暂存。
 */
SEC("tracepoint/syscalls/sys_enter_unshare")
int trace_unshare(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_namespace_event(SYSCALL_EVENT_UNSHARE);
    if (!event) return 0;

    //! @note args[0]: int unshare_flags (CLONE_*)
    //! @note 全量标志与命名空间掩码分开保存：一次 unshare 可新建多个命名空间
    event->namespace_event.flags   = ctx->args[0];
    event->namespace_event.ns_mask = (u32)(ctx->args[0] & HNG_CLONE_NEW_ALL);
    event->namespace_event.fd      = -1;

    hng_stash_pending(event);
    return 0;
}

/**
 * @brief 处理 sys_enter_setns 事件并暂存采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过暂存。
 */
SEC("tracepoint/syscalls/sys_enter_setns")
int trace_setns(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_namespace_event(SYSCALL_EVENT_SETNS);
    if (!event) return 0;

    //! @note args[0]: int fd；args[1]: int nstype (CLONE_NEW*)
    event->namespace_event.flags   = 0;
    event->namespace_event.ns_mask = (u32)ctx->args[1];
    event->namespace_event.fd      = (s32)ctx->args[0];

    hng_stash_pending(event);
    return 0;
}

/**
 * @brief 处理 sys_enter_mount 事件并暂存采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过暂存。
 * @note target 经路径解析器绝对化；fstype 原样读取用户串。
 * @note source 原样保存、不解析：它要么是设备路径（通常已是绝对路径），要么是
 *       "proc"/"tmpfs"/"none" 这类伪文件系统名——把后者按 CWD 拼成绝对路径会
 *       造出一个并不存在的路径。
 */
SEC("tracepoint/syscalls/sys_enter_mount")
int trace_mount(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_namespace_event(SYSCALL_EVENT_MOUNT);
    if (!event) return 0;

    //! @note args[0]: const char *source, args[1]: const char *target,
    //!       args[2]: const char *filesystemtype, args[3]: MS_* flags
    if (ctx->args[0]) {
        bpf_probe_read_user_str(event->namespace_event.source,
                                sizeof(event->namespace_event.source),
                                (void *)ctx->args[0]);
    }
    hng_fill_file_path(event->namespace_event.target,
                       sizeof(event->namespace_event.target),
                       &event->namespace_event.target_flags,
                       (const void *)ctx->args[1], AT_FDCWD);
    if (ctx->args[2]) {
        bpf_probe_read_user_str(event->namespace_event.fstype,
                                sizeof(event->namespace_event.fstype),
                                (void *)ctx->args[2]);
    }
    event->namespace_event.mount_flags = ctx->args[3];

    hng_stash_pending(event);
    return 0;
}

/**
 * @brief 处理 sys_enter_umount2 事件并暂存采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过暂存。
 */
SEC("tracepoint/syscalls/sys_enter_umount2")
int trace_umount2(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_namespace_event(SYSCALL_EVENT_UMOUNT2);
    if (!event) return 0;

    //! @note args[0]: const char *target, args[1]: int flags (MNT_*)
    hng_fill_file_path(event->namespace_event.target,
                       sizeof(event->namespace_event.target),
                       &event->namespace_event.target_flags,
                       (const void *)ctx->args[0], AT_FDCWD);
    event->namespace_event.mount_flags = ctx->args[1];

    hng_stash_pending(event);
    return 0;
}

/**
 * @brief 处理 sys_enter_pivot_root 事件并暂存采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过暂存。
 */
SEC("tracepoint/syscalls/sys_enter_pivot_root")
int trace_pivot_root(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_namespace_event(SYSCALL_EVENT_PIVOT_ROOT);
    if (!event) return 0;

    //! @note args[0]: const char *new_root, args[1]: const char *put_old
    hng_fill_file_path(event->namespace_event.source,
                       sizeof(event->namespace_event.source),
                       &event->namespace_event.source_flags,
                       (const void *)ctx->args[0], AT_FDCWD);
    hng_fill_file_path(event->namespace_event.target,
                       sizeof(event->namespace_event.target),
                       &event->namespace_event.target_flags,
                       (const void *)ctx->args[1], AT_FDCWD);

    hng_stash_pending(event);
    return 0;
}

/**
 * @brief 处理 sys_enter_chroot 事件并暂存采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过暂存。
 */
SEC("tracepoint/syscalls/sys_enter_chroot")
int trace_chroot(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_namespace_event(SYSCALL_EVENT_CHROOT);
    if (!event) return 0;

    //! @note args[0]: const char *filename — 新根，装入 target
    hng_fill_file_path(event->namespace_event.target,
                       sizeof(event->namespace_event.target),
                       &event->namespace_event.target_flags,
                       (const void *)ctx->args[0], AT_FDCWD);

    hng_stash_pending(event);
    return 0;
}

/** @} */

/**
 * @name FILE_EVENT 类别的 syscall 拦截
 * @{
 */

/**
 * @brief 处理 sys_enter_open 事件并暂存采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过暂存。
 */
SEC("tracepoint/syscalls/sys_enter_open")
int trace_syscall_open(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_file_event(SYSCALL_EVENT_OPEN);
    if (!event) return 0;

    //! @note args[0]: const char *filename；open 没有 dirfd 参数，基准为当前
    //!       工作目录，dirfd 保持 init 的 AT_FDCWD
    hng_fill_file_paths(&event->file_event, (const void *)ctx->args[0], AT_FDCWD,
                        NULL, AT_FDCWD);
    //! @note args[1]: int flags, args[2]: umode_t mode
    event->file_event.flags = (u32)ctx->args[1];
    event->file_event.mode  = (u32)ctx->args[2];

    hng_stash_pending(event);
    return 0;
}

/**
 * @brief 处理 sys_enter_openat 事件并暂存采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过暂存。
 */
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_syscall_openat(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_file_event(SYSCALL_EVENT_OPENAT);
    if (!event) return 0;

    //! @note args[0]: int dirfd, args[1]: const char *filename
    event->file_event.dirfd = (s32)ctx->args[0];
    hng_fill_file_paths(&event->file_event, (const void *)ctx->args[1],
                        (int)ctx->args[0], NULL, AT_FDCWD);
    //! @note args[2]: int flags, args[3]: umode_t mode
    event->file_event.flags = (u32)ctx->args[2];
    event->file_event.mode  = (u32)ctx->args[3];

    hng_stash_pending(event);
    return 0;
}

/**
 * @brief 处理 sys_enter_openat2 事件并暂存采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过暂存。
 */
SEC("tracepoint/syscalls/sys_enter_openat2")
int trace_syscall_openat2(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_file_event(SYSCALL_EVENT_OPENAT2);
    if (!event) return 0;

    //! @note args[0]: int dirfd, args[1]: const char *filename
    event->file_event.dirfd = (s32)ctx->args[0];
    hng_fill_file_paths(&event->file_event, (const void *)ctx->args[1],
                        (int)ctx->args[0], NULL, AT_FDCWD);
    //! @note args[2]: struct open_how *
    struct open_how how;
    if (bpf_probe_read_user(&how, sizeof(how), (void *)ctx->args[2]) == 0) {
        event->file_event.flags   = (u32)how.flags;
        event->file_event.mode    = (u32)how.mode;
        event->file_event.resolve = how.resolve;
    }

    hng_stash_pending(event);
    return 0;
}

/**
 * @brief 处理 sys_enter_creat 事件并暂存采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过暂存。
 */
SEC("tracepoint/syscalls/sys_enter_creat")
int trace_syscall_creat(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_file_event(SYSCALL_EVENT_CREAT);
    if (!event) return 0;

    //! @note args[0]: const char *filename；creat 没有 dirfd 参数，基准为当前
    //!       工作目录，dirfd 保持 init 的 AT_FDCWD
    hng_fill_file_paths(&event->file_event, (const void *)ctx->args[0], AT_FDCWD,
                        NULL, AT_FDCWD);
    //! @note creat() 隐含了 O_CREAT | O_WRONLY | O_TRUNC
    event->file_event.flags = O_CREAT | O_WRONLY | O_TRUNC;
    //! @note args[1]: umode_t mode
    event->file_event.mode  = (u32)ctx->args[1];

    hng_stash_pending(event);
    return 0;
}

/**
 * @brief 处理 sys_enter_unlink 事件并暂存采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过暂存。
 */
SEC("tracepoint/syscalls/sys_enter_unlink")
int trace_syscall_unlink(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_file_event(SYSCALL_EVENT_UNLINK);
    if (!event) return 0;

    //! @note args[0]: const char *pathname；unlink 没有 dirfd 参数，基准为当前
    //!       工作目录，dirfd 保持 init 的 AT_FDCWD
    hng_fill_file_paths(&event->file_event, (const void *)ctx->args[0], AT_FDCWD,
                        NULL, AT_FDCWD);

    hng_stash_pending(event);
    return 0;
}

/**
 * @brief 处理 sys_enter_link 事件并暂存采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过暂存。
 */
SEC("tracepoint/syscalls/sys_enter_link")
int trace_syscall_link(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_file_event(SYSCALL_EVENT_LINK);
    if (!event) return 0;

    //! @note args[0]: const char *oldname（源）, args[1]: const char *newname
    //!       （新名）；link 没有 dirfd 参数，两个基准都保持 AT_FDCWD
    hng_fill_file_paths(&event->file_event, (const void *)ctx->args[0], AT_FDCWD,
                        (const void *)ctx->args[1], AT_FDCWD);

    hng_stash_pending(event);
    return 0;
}

/**
 * @brief 处理 sys_enter_rename 事件并暂存采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过暂存。
 */
SEC("tracepoint/syscalls/sys_enter_rename")
int trace_syscall_rename(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_file_event(SYSCALL_EVENT_RENAME);
    if (!event) return 0;

    //! @note args[0]: const char *oldname（源）, args[1]: const char *newname
    //!       （目标）；rename 没有 dirfd 参数，两个基准都保持 AT_FDCWD
    hng_fill_file_paths(&event->file_event, (const void *)ctx->args[0], AT_FDCWD,
                        (const void *)ctx->args[1], AT_FDCWD);

    hng_stash_pending(event);
    return 0;
}

/**
 * @brief 处理 sys_enter_renameat 事件并暂存采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过暂存。
 */
SEC("tracepoint/syscalls/sys_enter_renameat")
int trace_syscall_renameat(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_file_event(SYSCALL_EVENT_RENAMEAT);
    if (!event) return 0;

    //! @note args[0]: int olddirfd, args[1]: const char *oldname,
    //!       args[2]: int newdirfd, args[3]: const char *newname
    event->file_event.dirfd  = (s32)ctx->args[0];
    event->file_event.dirfd2 = (s32)ctx->args[2];
    hng_fill_file_paths(&event->file_event, (const void *)ctx->args[1],
                        (int)ctx->args[0], (const void *)ctx->args[3],
                        (int)ctx->args[2]);

    hng_stash_pending(event);
    return 0;
}

/**
 * @brief 处理 sys_enter_renameat2 事件并暂存采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过暂存。
 */
SEC("tracepoint/syscalls/sys_enter_renameat2")
int trace_syscall_renameat2(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_file_event(SYSCALL_EVENT_RENAMEAT2);
    if (!event) return 0;

    //! @note args[0]: int olddirfd, args[1]: const char *oldname,
    //!       args[2]: int newdirfd, args[3]: const char *newname,
    //!       args[4]: unsigned int flags (RENAME_*)
    event->file_event.dirfd  = (s32)ctx->args[0];
    event->file_event.dirfd2 = (s32)ctx->args[2];
    hng_fill_file_paths(&event->file_event, (const void *)ctx->args[1],
                        (int)ctx->args[0], (const void *)ctx->args[3],
                        (int)ctx->args[2]);
    event->file_event.flags = (u32)ctx->args[4];

    hng_stash_pending(event);
    return 0;
}

/**
 * @brief 处理 sys_enter_unlinkat 事件并暂存采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过暂存。
 */
SEC("tracepoint/syscalls/sys_enter_unlinkat")
int trace_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_file_event(SYSCALL_EVENT_UNLINKAT);
    if (!event) return 0;

    //! @note args[0]: int dirfd, args[1]: const char *pathname,
    //!       args[2]: int flags (AT_REMOVEDIR)
    event->file_event.dirfd = (s32)ctx->args[0];
    hng_fill_file_paths(&event->file_event, (const void *)ctx->args[1],
                        (int)ctx->args[0], NULL, AT_FDCWD);
    event->file_event.at_flags = (u32)ctx->args[2];

    hng_stash_pending(event);
    return 0;
}

/**
 * @brief 处理 sys_enter_linkat 事件并暂存采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过暂存。
 */
SEC("tracepoint/syscalls/sys_enter_linkat")
int trace_linkat(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_file_event(SYSCALL_EVENT_LINKAT);
    if (!event) return 0;

    //! @note args[0]: int olddirfd, args[1]: const char *oldpath,
    //!       args[2]: int newdirfd, args[3]: const char *newpath,
    //!       args[4]: int flags (AT_SYMLINK_FOLLOW / AT_EMPTY_PATH)
    event->file_event.dirfd  = (s32)ctx->args[0];
    event->file_event.dirfd2 = (s32)ctx->args[2];
    hng_fill_file_paths(&event->file_event, (const void *)ctx->args[1],
                        (int)ctx->args[0], (const void *)ctx->args[3],
                        (int)ctx->args[2]);
    event->file_event.at_flags = (u32)ctx->args[4];

    hng_stash_pending(event);
    return 0;
}

/**
 * @brief 处理 sys_enter_symlink 事件并暂存采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过暂存。
 * @note path1 是被链接的目标串，path2 是新建的链接名（第二个路径）。
 */
SEC("tracepoint/syscalls/sys_enter_symlink")
int trace_symlink(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_file_event(SYSCALL_EVENT_SYMLINK);
    if (!event) return 0;

    //! @note args[0]: const char *target, args[1]: const char *linkpath
    hng_fill_file_paths(&event->file_event, (const void *)ctx->args[0], AT_FDCWD,
                        (const void *)ctx->args[1], AT_FDCWD);

    hng_stash_pending(event);
    return 0;
}

/**
 * @brief 处理 sys_enter_symlinkat 事件并暂存采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过暂存。
 * @note args[1] 的 dirfd 只作用于 linkpath，故 path2 的基准是它，path1 为 CWD。
 */
SEC("tracepoint/syscalls/sys_enter_symlinkat")
int trace_symlinkat(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_file_event(SYSCALL_EVENT_SYMLINKAT);
    if (!event) return 0;

    //! @note args[0]: const char *target, args[1]: int newdirfd,
    //!       args[2]: const char *linkpath
    event->file_event.dirfd2 = (s32)ctx->args[1];
    hng_fill_file_paths(&event->file_event, (const void *)ctx->args[0], AT_FDCWD,
                        (const void *)ctx->args[2], (int)ctx->args[1]);

    hng_stash_pending(event);
    return 0;
}

/**
 * @brief 处理 sys_enter_chmod 事件并暂存采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过暂存。
 */
SEC("tracepoint/syscalls/sys_enter_chmod")
int trace_chmod(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_file_event(SYSCALL_EVENT_CHMOD);
    if (!event) return 0;

    //! @note args[0]: const char *filename, args[1]: umode_t mode
    hng_fill_file_paths(&event->file_event, (const void *)ctx->args[0], AT_FDCWD,
                        NULL, AT_FDCWD);
    event->file_event.mode = (u32)ctx->args[1];

    hng_stash_pending(event);
    return 0;
}

/**
 * @brief 处理 sys_enter_fchmod 事件并暂存采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过暂存。
 */
SEC("tracepoint/syscalls/sys_enter_fchmod")
int trace_fchmod(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_file_event(SYSCALL_EVENT_FCHMOD);
    if (!event) return 0;

    //! @note args[0]: unsigned int fd, args[1]: umode_t mode — 没有路径
    event->file_event.fd   = (s32)ctx->args[0];
    event->file_event.mode = (u32)ctx->args[1];

    hng_stash_pending(event);
    return 0;
}

/**
 * @brief 处理 sys_enter_fchmodat 事件并暂存采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过暂存。
 */
SEC("tracepoint/syscalls/sys_enter_fchmodat")
int trace_fchmodat(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_file_event(SYSCALL_EVENT_FCHMODAT);
    if (!event) return 0;

    //! @note args[0]: int dirfd, args[1]: const char *filename,
    //!       args[2]: umode_t mode, args[3]: int flags (AT_SYMLINK_NOFOLLOW)
    event->file_event.dirfd = (s32)ctx->args[0];
    hng_fill_file_paths(&event->file_event, (const void *)ctx->args[1],
                        (int)ctx->args[0], NULL, AT_FDCWD);
    event->file_event.mode     = (u32)ctx->args[2];
    event->file_event.at_flags = (u32)ctx->args[3];

    hng_stash_pending(event);
    return 0;
}

/**
 * @brief 处理 sys_enter_truncate 事件并暂存采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过暂存。
 */
SEC("tracepoint/syscalls/sys_enter_truncate")
int trace_truncate(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_file_event(SYSCALL_EVENT_TRUNCATE);
    if (!event) return 0;

    //! @note args[0]: const char *path, args[1]: off_t length
    hng_fill_file_paths(&event->file_event, (const void *)ctx->args[0], AT_FDCWD,
                        NULL, AT_FDCWD);
    event->file_event.length = (s64)ctx->args[1];

    hng_stash_pending(event);
    return 0;
}

/**
 * @brief 处理 sys_enter_ftruncate 事件并暂存采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过暂存。
 */
SEC("tracepoint/syscalls/sys_enter_ftruncate")
int trace_ftruncate(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_file_event(SYSCALL_EVENT_FTRUNCATE);
    if (!event) return 0;

    //! @note args[0]: unsigned int fd, args[1]: off_t length — 没有路径
    event->file_event.fd     = (s32)ctx->args[0];
    event->file_event.length = (s64)ctx->args[1];

    hng_stash_pending(event);
    return 0;
}

/**
 * @brief 处理 sys_enter_mknod 事件并暂存采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过暂存。
 */
SEC("tracepoint/syscalls/sys_enter_mknod")
int trace_mknod(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_file_event(SYSCALL_EVENT_MKNOD);
    if (!event) return 0;

    //! @note args[0]: const char *filename, args[1]: umode_t mode,
    //!       args[2]: unsigned dev
    hng_fill_file_paths(&event->file_event, (const void *)ctx->args[0], AT_FDCWD,
                        NULL, AT_FDCWD);
    event->file_event.mode = (u32)ctx->args[1];
    event->file_event.dev  = (u32)ctx->args[2];

    hng_stash_pending(event);
    return 0;
}

/**
 * @brief 处理 sys_enter_mknodat 事件并暂存采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过暂存。
 */
SEC("tracepoint/syscalls/sys_enter_mknodat")
int trace_mknodat(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_file_event(SYSCALL_EVENT_MKNODAT);
    if (!event) return 0;

    //! @note args[0]: int dirfd, args[1]: const char *filename,
    //!       args[2]: umode_t mode, args[3]: unsigned dev
    event->file_event.dirfd = (s32)ctx->args[0];
    hng_fill_file_paths(&event->file_event, (const void *)ctx->args[1],
                        (int)ctx->args[0], NULL, AT_FDCWD);
    event->file_event.mode = (u32)ctx->args[2];
    event->file_event.dev  = (u32)ctx->args[3];

    hng_stash_pending(event);
    return 0;
}

/**
 * @brief 处理 sys_enter_memfd_create 事件并暂存采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过暂存。
 * @note 匿名文件没有可解析路径：path1 写成 "memfd:NAME" 且不置解析位。
 */
SEC("tracepoint/syscalls/sys_enter_memfd_create")
int trace_memfd_create(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_file_event(SYSCALL_EVENT_MEMFD_CREATE);
    if (!event) return 0;

    //! @note args[0]: const char *name, args[1]: unsigned int flags (MFD_*)
    __builtin_memcpy(event->file_event.path1, HNG_MEMFD_PREFIX,
                     sizeof(HNG_MEMFD_PREFIX) - 1);
    if (ctx->args[0]) {
        bpf_probe_read_user_str(
            event->file_event.path1 + sizeof(HNG_MEMFD_PREFIX) - 1,
            sizeof(event->file_event.path1) - (sizeof(HNG_MEMFD_PREFIX) - 1),
            (void *)ctx->args[0]);
    }
    event->file_event.flags = (u32)ctx->args[1];

    hng_stash_pending(event);
    return 0;
}

/**
 * @brief 处理 sys_enter_open_by_handle_at 事件并暂存采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过暂存。
 * @note args[0] 在系统调用里是 mount fd，没有路径；句柄只记录前 16 字节。
 */
SEC("tracepoint/syscalls/sys_enter_open_by_handle_at")
int trace_open_by_handle_at(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event =
        init_file_event(SYSCALL_EVENT_OPEN_BY_HANDLE_AT);
    if (!event) return 0;

    //! @note args[0]: int mount_fd, args[1]: struct file_handle *handle,
    //!       args[2]: int flags
    event->file_event.dirfd = (s32)ctx->args[0];
    event->file_event.fd    = (s32)ctx->args[0];
    if (ctx->args[1]) {
        bpf_probe_read_user(event->file_event.handle,
                            sizeof(event->file_event.handle),
                            (void *)ctx->args[1]);
    }
    event->file_event.at_flags = (u32)ctx->args[2];

    hng_stash_pending(event);
    return 0;
}

/**
 * @brief 处理 sys_enter_name_to_handle_at 事件并暂存采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过暂存。
 * @note 句柄缓冲是输出参数：enter 只暂存用户指针，exit 提交前再读实际内容。
 */
SEC("tracepoint/syscalls/sys_enter_name_to_handle_at")
int trace_name_to_handle_at(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event =
        init_file_event(SYSCALL_EVENT_NAME_TO_HANDLE_AT);
    if (!event) return 0;

    //! @note args[0]: int dirfd, args[1]: const char *pathname,
    //!       args[2]: struct file_handle *handle, args[3]: int *mount_id,
    //!       args[4]: int flags
    event->file_event.dirfd = (s32)ctx->args[0];
    event->file_event.fd    = (s32)ctx->args[0];
    hng_fill_file_paths(&event->file_event, (const void *)ctx->args[1],
                        (int)ctx->args[0], NULL, AT_FDCWD);
    //! @note 指针暂存到 length，由 FILE 的 exit 钩子读取句柄内容
    event->file_event.length   = (s64)ctx->args[2];
    event->file_event.at_flags = (u32)ctx->args[4];

    hng_stash_pending(event);
    return 0;
}

/**
 * @brief 处理 sys_enter_chdir 事件并暂存采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过暂存。
 */
SEC("tracepoint/syscalls/sys_enter_chdir")
int trace_chdir(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_file_event(SYSCALL_EVENT_CHDIR);
    if (!event) return 0;

    //! @note args[0]: const char *filename；chdir 没有 dirfd 参数
    hng_fill_file_paths(&event->file_event, (const void *)ctx->args[0], AT_FDCWD,
                        NULL, AT_FDCWD);

    hng_stash_pending(event);
    return 0;
}

/**
 * @brief 处理 sys_enter_fchdir 事件并暂存采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过暂存。
 */
SEC("tracepoint/syscalls/sys_enter_fchdir")
int trace_fchdir(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_file_event(SYSCALL_EVENT_FCHDIR);
    if (!event) return 0;

    //! @note args[0]: unsigned int fd — 没有路径
    event->file_event.fd = (s32)ctx->args[0];

    hng_stash_pending(event);
    return 0;
}

/** @} */

/**
 * @name MEMORY_EVENT 类别的 syscall 拦截
 * @{
 */

/**
 * @brief 处理 sys_enter_mmap 事件并暂存采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过暂存。
 */
SEC("tracepoint/syscalls/sys_enter_mmap")
int trace_mmap(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_memory_event(SYSCALL_EVENT_MMAP);
    if (!event) return 0;

    //! @note args[0]: void *addr, args[1]: size_t length, args[2]: int prot
    //!       (PROT_*), args[3]: int flags (MAP_*), args[4]: int fd,
    //!       args[5]: off_t offset
    event->memory_event.addr   = ctx->args[0];
    event->memory_event.length = ctx->args[1];
    event->memory_event.prot   = ctx->args[2];
    event->memory_event.flags  = ctx->args[3];
    event->memory_event.fd     = (s32)ctx->args[4];
    event->memory_event.offset = ctx->args[5];
    //! @note MAP_ANONYMOUS 时 fd 被忽略，匿名标志独立记录
    event->memory_event.anonymous =
        (event->memory_event.flags & MAP_ANONYMOUS) ? 1 : 0;
    //! @note 同时可写可执行：自修改代码与代码注入的典型特征
    event->memory_event.wx =
        (event->memory_event.prot & (PROT_WRITE | PROT_EXEC)) ==
                (PROT_WRITE | PROT_EXEC)
            ? 1
            : 0;

    hng_stash_pending(event);
    return 0;
}

/**
 * @brief 处理 sys_enter_mprotect 事件并暂存采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过暂存。
 */
SEC("tracepoint/syscalls/sys_enter_mprotect")
int trace_mprotect(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_memory_event(SYSCALL_EVENT_MPROTECT);
    if (!event) return 0;

    //! @note args[0]: void *addr, args[1]: size_t len, args[2]: int prot
    event->memory_event.addr   = ctx->args[0];
    event->memory_event.length = ctx->args[1];
    event->memory_event.prot   = ctx->args[2];
    //! @note W|X 同时出现即自修改代码特征；fd 与 offset 保持 init 的空值
    event->memory_event.wx =
        (event->memory_event.prot & (PROT_WRITE | PROT_EXEC)) ==
                (PROT_WRITE | PROT_EXEC)
            ? 1
            : 0;

    hng_stash_pending(event);
    return 0;
}

/**
 * @brief 处理 sys_enter_mremap 事件并暂存采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过暂存。
 * @note 现有载荷只有一个长度字段，记录 old_size；new_size 暂不表达。
 */
SEC("tracepoint/syscalls/sys_enter_mremap")
int trace_mremap(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_memory_event(SYSCALL_EVENT_MREMAP);
    if (!event) return 0;

    //! @note args[0]: void *old_address, args[1]: size_t old_size,
    //!       args[2]: size_t new_size, args[3]: int flags (MREMAP_*)
    event->memory_event.addr   = ctx->args[0];
    event->memory_event.length = ctx->args[1];
    event->memory_event.flags  = ctx->args[3];

    hng_stash_pending(event);
    return 0;
}

/**
 * @brief 处理 sys_enter_munmap 事件并暂存采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过暂存。
 */
SEC("tracepoint/syscalls/sys_enter_munmap")
int trace_munmap(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_memory_event(SYSCALL_EVENT_MUNMAP);
    if (!event) return 0;

    //! @note args[0]: void *addr, args[1]: size_t length
    event->memory_event.addr   = ctx->args[0];
    event->memory_event.length = ctx->args[1];

    hng_stash_pending(event);
    return 0;
}

/** @} */

/**
 * @name NETWORK_EVENT 类别的 syscall 拦截
 * @{
 */

/**
 * @brief 处理 sys_enter_connect 事件并暂存采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过暂存。
 * @note 无论目标地址能否解析都暂存事件：连接意图本身是语义的一部分，
 *       AF_UNIX 等非 IP 连接同样可见。
 * @note 源端口为本地临时端口，sys_enter 阶段可能尚未分配，为 0。
 */
SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_network_event(SYSCALL_EVENT_CONNECT);
    if (!event) return 0;

    //! @note args[0]: sockfd, args[1]: 目标 sockaddr, args[2]: addrlen
    event->network_event.sockfd = (s32)ctx->args[0];
    if (parse_sockaddr(
            (const void *)ctx->args[1], (u32)ctx->args[2],
            event->network_event.dst_ip, &event->network_event.dst_port,
            &event->network_event.family, event->network_event.unix_path,
            sizeof(event->network_event.unix_path))) {
        fill_local_info(get_socket_sk((u32)ctx->args[0]), &event->network_event);
    }
    else {
        /**
         * @note 解析不出 IPv4/IPv6 时只填 sockaddr 中读到的地址族，
         * 目标地址与端口保持 0；AF_UNIX 的 sun_path 已由 parse_sockaddr 写出
         */
        struct sockaddr sa;
        if (bpf_probe_read_user(&sa, sizeof(sa), (void *)ctx->args[1]) == 0) {
            event->network_event.family = sa.sa_family;
        }
    }

    hng_stash_pending(event);
    return 0;
}

/**
 * @brief 处理 sys_enter_sendto 事件并暂存采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件、目标地址不可解析或无法构造事件时跳过暂存。
 * @note 目标 sockaddr 解析为 IPv4/IPv6 或 AF_UNIX 时暂存；已 connect 的套接字
 *       通常不再携带目标地址，其连接信息由 connect 事件记录。
 */
SEC("tracepoint/syscalls/sys_enter_sendto")
int trace_sendto(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_network_event(SYSCALL_EVENT_SENDTO);
    if (!event) return 0;

    //! @note args[0]: sockfd, args[2]: size_t len（本次发送的字节数）,
    //!       args[4]: 目标 sockaddr, args[5]: addrlen
    event->network_event.sockfd = (s32)ctx->args[0];
    event->network_event.count  = ctx->args[2];
    if (!parse_sockaddr(
            (const void *)ctx->args[4], (u32)ctx->args[5],
            event->network_event.dst_ip, &event->network_event.dst_port,
            &event->network_event.family, event->network_event.unix_path,
            sizeof(event->network_event.unix_path)) &&
        event->network_event.family != AF_UNIX) {
        /**
         * @note 只有 IP 目标与 AF_UNIX 目标算「目标已知」：前者已填 ip/port，
         *       后者已由 parse_sockaddr 写出 sun_path。已 connect 的套接字通常
         *       不再携带目标地址，其连接信息由 connect 事件记录，本次不暂存；
         *       未预留任何资源，exit 侧据此不计 pending_lost。
         */
        return 0;
    }

    fill_local_info(get_socket_sk((u32)ctx->args[0]), &event->network_event);

    hng_stash_pending(event);
    return 0;
}

/**
 * @brief 处理 sys_enter_sendmsg 事件并暂存采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件、目标地址不可解析或无法构造事件时跳过暂存。
 * @note msg_name 解析为 IPv4/IPv6 或 AF_UNIX 时暂存；已 connect 的套接字可传空的
 *       msg_name，此时连接信息已由 connect 事件记录，跳过本次暂存。
 */
SEC("tracepoint/syscalls/sys_enter_sendmsg")
int trace_sendmsg(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_network_event(SYSCALL_EVENT_SENDMSG);
    if (!event) return 0;

    //! @note args[0]: sockfd, args[1]: 用户态 struct msghdr *, args[2]: flags
    event->network_event.sockfd = (s32)ctx->args[0];
    const void *dest_addr       = NULL;
    u32 addrlen                 = 0;
    struct hng_user_msghdr msg  = {};
    if (bpf_probe_read_user(&msg, sizeof(msg), (void *)ctx->args[1]) == 0) {
        dest_addr                  = msg.msg_name;
        addrlen                    = (u32)msg.msg_namelen;
        //! @note 字节数不在入参里：按 iovec 数组累加，至多 HNG_MAX_IOV 项
        event->network_event.count = sum_iov_len(msg.msg_iov, msg.msg_iovlen);
    }

    if (!parse_sockaddr(dest_addr, addrlen, event->network_event.dst_ip,
                        &event->network_event.dst_port,
                        &event->network_event.family,
                        event->network_event.unix_path,
                        sizeof(event->network_event.unix_path)) &&
        event->network_event.family != AF_UNIX) {
        /**
         * @note 只有 IP 目标与 AF_UNIX 目标算「目标已知」：前者已填 ip/port，
         *       后者已由 parse_sockaddr 写出 sun_path。已 connect 的套接字可传空
         *       msg_name，连接信息由 connect 事件记录，本次不暂存；未预留任何
         *       资源，exit 侧据此不计 pending_lost。
         */
        return 0;
    }

    fill_local_info(get_socket_sk((u32)ctx->args[0]), &event->network_event);

    hng_stash_pending(event);
    return 0;
}

/**
 * @brief 处理 sys_enter_socket 事件并暂存采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过暂存。
 */
SEC("tracepoint/syscalls/sys_enter_socket")
int trace_socket(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_network_event(SYSCALL_EVENT_SOCKET);
    if (!event) return 0;

    //! @note args[0]: int family, args[1]: int type, args[2]: int protocol；
    //!       新 fd 在返回值里，sockfd 保持 init 的 -1
    event->network_event.family   = (u32)ctx->args[0];
    event->network_event.type     = (u32)ctx->args[1];
    event->network_event.protocol = (u32)ctx->args[2];

    hng_stash_pending(event);
    return 0;
}

/**
 * @brief 处理 sys_enter_bind 事件并暂存采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过暂存。
 */
SEC("tracepoint/syscalls/sys_enter_bind")
int trace_bind(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_network_event(SYSCALL_EVENT_BIND);
    if (!event) return 0;

    //! @note args[0]: sockfd, args[1]: const struct sockaddr *addr
    event->network_event.sockfd = (s32)ctx->args[0];
    struct sockaddr sa;
    if (bpf_probe_read_user(&sa, sizeof(sa), (void *)ctx->args[1]) == 0) {
        event->network_event.family = sa.sa_family;
    }

    hng_stash_pending(event);
    return 0;
}

/**
 * @brief 处理 sys_enter_recvfrom 事件并暂存采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过暂存。
 * @note 源地址仅用于记录本次接收的对端；已 connect 的套接字可传空地址，
 *       此时 src_ip/src_port 保持 0，事件照常暂存。
 */
SEC("tracepoint/syscalls/sys_enter_recvfrom")
int trace_recvfrom(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_network_event(SYSCALL_EVENT_RECVFROM);
    if (!event) return 0;

    //! @note args[0]: sockfd, args[1]: void *buf, args[2]: size_t len,
    //!       args[3]: int flags, args[4]: 源 sockaddr, args[5]: addrlen
    event->network_event.sockfd = (s32)ctx->args[0];
    event->network_event.count  = ctx->args[2];
    parse_sockaddr((const void *)ctx->args[4], (u32)ctx->args[5],
                   event->network_event.src_ip, &event->network_event.src_port,
                   &event->network_event.family, event->network_event.unix_path,
                   sizeof(event->network_event.unix_path));

    hng_stash_pending(event);
    return 0;
}

/**
 * @brief 处理 sys_enter_accept4 事件并暂存采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过暂存。
 * @note 新 fd 在返回值里；args[3] 的 SOCK_* 标志复用 type 字段承载。
 */
SEC("tracepoint/syscalls/sys_enter_accept4")
int trace_accept4(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_network_event(SYSCALL_EVENT_ACCEPT4);
    if (!event) return 0;

    //! @note args[0]: sockfd, args[3]: int flags (SOCK_NONBLOCK/SOCK_CLOEXEC)
    //! @note flags 用专用字段承载：type 表示套接字类型，两者语义不同
    event->network_event.sockfd = (s32)ctx->args[0];
    event->network_event.flags  = (u32)ctx->args[3];

    hng_stash_pending(event);
    return 0;
}

/**
 * @brief 处理 sys_enter_listen 事件并暂存采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过暂存。
 */
SEC("tracepoint/syscalls/sys_enter_listen")
int trace_listen(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_network_event(SYSCALL_EVENT_LISTEN);
    if (!event) return 0;

    //! @note args[0]: sockfd, args[1]: int backlog
    event->network_event.sockfd  = (s32)ctx->args[0];
    event->network_event.backlog = (s32)ctx->args[1];

    hng_stash_pending(event);
    return 0;
}

/** @} */

/**
 * @name KERNEL_EVENT 类别的 syscall 拦截
 * @{
 */

/**
 * @brief 处理 sys_enter_ptrace 事件并暂存采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过暂存。
 */
SEC("tracepoint/syscalls/sys_enter_ptrace")
int trace_ptrace(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_kernel_event(SYSCALL_EVENT_PTRACE);
    if (!event) return 0;

    //! @note args[0]: int request (PTRACE_*), args[1]: pid_t pid — 目标进程,
    //!       args[3]: void *data — POKETEXT 是写入的字，其余请求含义不同，
    //!       一律原样保留
    event->kernel_event.command    = (u32)ctx->args[0];
    event->kernel_event.target_pid = (u32)ctx->args[1];
    event->kernel_event.arg        = ctx->args[3];

    hng_stash_pending(event);
    return 0;
}

/**
 * @brief 处理 sys_enter_bpf 事件并暂存采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过暂存。
 */
SEC("tracepoint/syscalls/sys_enter_bpf")
int trace_bpf(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_kernel_event(SYSCALL_EVENT_BPF);
    if (!event) return 0;

    //! @note args[0]: int cmd (BPF_*), args[1]: union bpf_attr *,
    //!       args[2]: unsigned int size — 用户给出的属性大小
    event->kernel_event.command = (u32)ctx->args[0];
    /**
     * @note 按用户给出的 size 截断读取（上限 16 字节）：短属性的命令不会因为
     *       多读越界而在页边界失败。size 本身留在 arg 里，可用于区分命令版本。
     * @note 分支两条路径都给出可证的上界（掩码 0x0f 对应 sizeof-1，16 是 2 的
     *       幂）：helper 的长度参数必须非负且有界，否则 verifier 拒绝加载。
     */
    __u32 attr_size             = sizeof(event->kernel_event.bpf_attr);
    if ((__u32)ctx->args[2] < sizeof(event->kernel_event.bpf_attr)) {
        attr_size = (__u32)ctx->args[2] & 0x0fu;
    }
    event->kernel_event.arg = attr_size;
    if (attr_size != 0 &&
        bpf_probe_read_user(event->kernel_event.bpf_attr, attr_size,
                            (void *)ctx->args[1]) == 0) {
        event->kernel_event.bpf_type = decode_bpf_type(
            event->kernel_event.command, (const void *)ctx->args[1]);
    }

    hng_stash_pending(event);
    return 0;
}

/**
 * @brief 处理 sys_enter_init_module 事件并暂存采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过暂存。
 * @note 模块镜像在用户态内存里，只记录长度；uargs 指针存入 arg。
 */
SEC("tracepoint/syscalls/sys_enter_init_module")
int trace_init_module(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_kernel_event(SYSCALL_EVENT_INIT_MODULE);
    if (!event) return 0;

    //! @note args[0]: void *image, args[1]: unsigned long len,
    //!       args[2]: const char *uargs
    event->kernel_event.module_len = (u32)ctx->args[1];
    event->kernel_event.arg        = ctx->args[2];

    hng_stash_pending(event);
    return 0;
}

/**
 * @brief 处理 sys_enter_finit_module 事件并暂存采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过暂存。
 */
SEC("tracepoint/syscalls/sys_enter_finit_module")
int trace_finit_module(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_kernel_event(SYSCALL_EVENT_FINIT_MODULE);
    if (!event) return 0;

    //! @note args[0]: int fd, args[1]: const char *uargs,
    //!       args[2]: int flags — params 指针存入 arg
    event->kernel_event.arg = ctx->args[1];

    hng_stash_pending(event);
    return 0;
}

/**
 * @brief 处理 sys_enter_delete_module 事件并暂存采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过暂存。
 */
SEC("tracepoint/syscalls/sys_enter_delete_module")
int trace_delete_module(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_kernel_event(SYSCALL_EVENT_DELETE_MODULE);
    if (!event) return 0;

    //! @note args[0]: const char *name_user, args[1]: unsigned int flags
    if (ctx->args[0]) {
        bpf_probe_read_user_str(event->kernel_event.module_name,
                                sizeof(event->kernel_event.module_name),
                                (void *)ctx->args[0]);
    }
    event->kernel_event.arg = ctx->args[1];

    hng_stash_pending(event);
    return 0;
}

/**
 * @brief 处理 sys_enter_kexec_load 事件并暂存采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过暂存。
 * @note 段数组内容不读（用户内存，且大），只记录入口与段数。
 */
SEC("tracepoint/syscalls/sys_enter_kexec_load")
int trace_kexec_load(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_kernel_event(SYSCALL_EVENT_KEXEC_LOAD);
    if (!event) return 0;

    //! @note args[0]: unsigned long entry, args[1]: unsigned long nr_segments,
    //!       args[2]: struct kexec_segment *segments, args[3]: flags
    event->kernel_event.kexec_entry    = ctx->args[0];
    event->kernel_event.kexec_segments = (u32)ctx->args[1];
    event->kernel_event.arg            = ctx->args[3];

    hng_stash_pending(event);
    return 0;
}

/**
 * @brief 处理 sys_enter_reboot 事件并暂存采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过暂存。
 */
SEC("tracepoint/syscalls/sys_enter_reboot")
int trace_reboot(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_kernel_event(SYSCALL_EVENT_REBOOT);
    if (!event) return 0;

    //! @note args[0]: int magic1, args[1]: int magic2,
    //!       args[2]: unsigned int cmd (LINUX_REBOOT_CMD_*)
    event->kernel_event.reboot_cmd = (u32)ctx->args[2];

    hng_stash_pending(event);
    return 0;
}

/**
 * @brief 处理 sys_enter_sethostname 事件并暂存采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过暂存。
 */
SEC("tracepoint/syscalls/sys_enter_sethostname")
int trace_sethostname(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_kernel_event(SYSCALL_EVENT_SETHOSTNAME);
    if (!event) return 0;

    //! @note args[0]: char *name, args[1]: int len
    if (ctx->args[0]) {
        bpf_probe_read_user_str(event->kernel_event.hostname,
                                sizeof(event->kernel_event.hostname),
                                (void *)ctx->args[0]);
    }
    event->kernel_event.arg = ctx->args[1];

    hng_stash_pending(event);
    return 0;
}

/**
 * @brief 处理 module_load tracepoint：记录被加载的模块名。
 * @param[in] ctx raw entry 上下文。
 * @return 始终返回 0；事件空间不足时跳过提交。
 * @note entry 布局：trace_entry(8) + taints(4) + __data_loc name(4)。
 */
SEC("tracepoint/module/module_load")
int trace_module_load(void *ctx)
{
    struct syscall_event *event =
        init_kernel_trace_event(SYSCALL_EVENT_MODULE_LOAD);
    if (!event) return 0;

    hng_read_trace_string(event->kernel_event.module_name,
                          sizeof(event->kernel_event.module_name), ctx, 12);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

/**
 * @brief 处理 module_free tracepoint：记录被卸载的模块名。
 * @param[in] ctx raw entry 上下文。
 * @return 始终返回 0；事件空间不足时跳过提交。
 * @note entry 布局：trace_entry(8) + __data_loc name(4)。
 */
SEC("tracepoint/module/module_free")
int trace_module_free(void *ctx)
{
    struct syscall_event *event =
        init_kernel_trace_event(SYSCALL_EVENT_MODULE_FREE);
    if (!event) return 0;

    hng_read_trace_string(event->kernel_event.module_name,
                          sizeof(event->kernel_event.module_name), ctx, 8);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

/** @} */

/**
 * @name SIGNAL_EVENT 类别的 syscall 拦截
 * @{
 */

/**
 * @brief 处理 sys_enter_kill 事件并暂存采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过暂存。
 */
SEC("tracepoint/syscalls/sys_enter_kill")
int trace_kill(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_signal_event(SYSCALL_EVENT_KILL);
    if (!event) return 0;

    //! @note args[0]: pid_t pid, args[1]: int sig
    event->signal_event.target_pid = (u32)ctx->args[0];
    event->signal_event.sig        = (u32)ctx->args[1];

    hng_stash_pending(event);
    return 0;
}

/**
 * @brief 处理 sys_enter_tkill 事件并暂存采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过暂存。
 */
SEC("tracepoint/syscalls/sys_enter_tkill")
int trace_tkill(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_signal_event(SYSCALL_EVENT_TKILL);
    if (!event) return 0;

    //! @note args[0]: pid_t tid, args[1]: int sig
    event->signal_event.target_pid = (u32)ctx->args[0];
    event->signal_event.sig        = (u32)ctx->args[1];

    hng_stash_pending(event);
    return 0;
}

/**
 * @brief 处理 sys_enter_tgkill 事件并暂存采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过暂存。
 */
SEC("tracepoint/syscalls/sys_enter_tgkill")
int trace_tgkill(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_signal_event(SYSCALL_EVENT_TGKILL);
    if (!event) return 0;

    //! @note args[0]: pid_t tgid, args[1]: pid_t tid, args[2]: int sig
    event->signal_event.target_pid = (u32)ctx->args[0];
    event->signal_event.target_tid = (u32)ctx->args[1];
    event->signal_event.sig        = (u32)ctx->args[2];

    hng_stash_pending(event);
    return 0;
}

/**
 * @brief 处理 sys_enter_rt_sigqueueinfo 事件并暂存采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过暂存。
 * @note si_code 位于用户态 siginfo_t 的固定偏移；读取失败时保持 0。
 */
SEC("tracepoint/syscalls/sys_enter_rt_sigqueueinfo")
int trace_rt_sigqueueinfo(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event =
        init_signal_event(SYSCALL_EVENT_RT_SIGQUEUEINFO);
    if (!event) return 0;

    //! @note args[0]: pid_t pid, args[1]: int sig, args[2]: siginfo_t __user *
    event->signal_event.target_pid = (u32)ctx->args[0];
    event->signal_event.sig        = (u32)ctx->args[1];
    __s32 si_code                  = 0;
    if (bpf_probe_read_user(
            &si_code, sizeof(si_code),
            (const char *)ctx->args[2] + HNG_SIGINFO_SI_CODE_OFF) == 0) {
        event->signal_event.si_code = si_code;
    }

    hng_stash_pending(event);
    return 0;
}

/** @} */

/**
 * @name 系统调用 exit 探针
 * @details
 * 每个被采集的系统调用各一个，按 subtype 走对应的 hng_commit_<subtype>：
 * 取回 enter 暂存的事件、补上返回值与完成时刻的事件头后提交。生命周期事件
 * 不在此列，仍由各自的探针直接提交。
 * @note sendto/sendmsg 的 enter 在目标地址不可解析时合法地不写暂存表，故其 exit
 *       不计 pending_lost；其余系统调用的缺条目都按真正的丢失计。
 * @{
 */

/**
 * @brief 定义一个系统调用的 exit 探针。
 * @param[in] probe tracepoint 名后缀，与同名 enter 探针共用。
 * @param[in] event_name 对应的系统调用事件名。
 * @param[in] subtype 事件名所属的子类型，编译期选定提交分支与记录长度。
 * @param[in] count_lost 暂存条目缺失时是否计入 pending_lost。
 */
#define HNG_DEFINE_EXIT_PROBE_IMPL(probe, event_name, subtype, count_lost) \
    SEC("tracepoint/syscalls/sys_exit_" #probe)                            \
    int trace_exit_##probe(struct trace_event_raw_sys_exit *ctx)           \
    {                                                                      \
        return hng_commit_##subtype(ctx->ret, event_name, count_lost);     \
    }

/// @brief enter 必然暂存（角色过滤除外）的系统调用的 exit 探针
#define HNG_DEFINE_EXIT_PROBE(probe, event_name, subtype) \
    HNG_DEFINE_EXIT_PROBE_IMPL(probe, event_name, subtype, 1)

/// @brief enter 可能合法跳过暂存的系统调用的 exit 探针
#define HNG_DEFINE_EXIT_PROBE_OPTIONAL(probe, event_name, subtype) \
    HNG_DEFINE_EXIT_PROBE_IMPL(probe, event_name, subtype, 0)

// EXEC
HNG_DEFINE_EXIT_PROBE(execve, SYSCALL_EVENT_EXECVE, EXEC_EVENT)
HNG_DEFINE_EXIT_PROBE(execveat, SYSCALL_EVENT_EXECVEAT, EXEC_EVENT)

// CREDENTIAL
HNG_DEFINE_EXIT_PROBE(setuid, SYSCALL_EVENT_SETUID, CREDENTIAL_EVENT)
HNG_DEFINE_EXIT_PROBE(setgid, SYSCALL_EVENT_SETGID, CREDENTIAL_EVENT)
HNG_DEFINE_EXIT_PROBE(capset, SYSCALL_EVENT_CAPSET, CREDENTIAL_EVENT)
HNG_DEFINE_EXIT_PROBE(setreuid, SYSCALL_EVENT_SETREUID, CREDENTIAL_EVENT)
HNG_DEFINE_EXIT_PROBE(setresuid, SYSCALL_EVENT_SETRESUID, CREDENTIAL_EVENT)
HNG_DEFINE_EXIT_PROBE(setfsuid, SYSCALL_EVENT_SETFSUID, CREDENTIAL_EVENT)
HNG_DEFINE_EXIT_PROBE(setresgid, SYSCALL_EVENT_SETRESGID, CREDENTIAL_EVENT)
HNG_DEFINE_EXIT_PROBE(setgroups, SYSCALL_EVENT_SETGROUPS, CREDENTIAL_EVENT)
HNG_DEFINE_EXIT_PROBE_OPTIONAL(prctl, SYSCALL_EVENT_PRCTL, CREDENTIAL_EVENT)

// NAMESPACE
HNG_DEFINE_EXIT_PROBE(unshare, SYSCALL_EVENT_UNSHARE, NAMESPACE_EVENT)
HNG_DEFINE_EXIT_PROBE(setns, SYSCALL_EVENT_SETNS, NAMESPACE_EVENT)
HNG_DEFINE_EXIT_PROBE(mount, SYSCALL_EVENT_MOUNT, NAMESPACE_EVENT)
HNG_DEFINE_EXIT_PROBE(umount2, SYSCALL_EVENT_UMOUNT2, NAMESPACE_EVENT)
HNG_DEFINE_EXIT_PROBE(pivot_root, SYSCALL_EVENT_PIVOT_ROOT, NAMESPACE_EVENT)
HNG_DEFINE_EXIT_PROBE(chroot, SYSCALL_EVENT_CHROOT, NAMESPACE_EVENT)

// FILE
HNG_DEFINE_EXIT_PROBE(open, SYSCALL_EVENT_OPEN, FILE_EVENT)
HNG_DEFINE_EXIT_PROBE(openat, SYSCALL_EVENT_OPENAT, FILE_EVENT)
HNG_DEFINE_EXIT_PROBE(openat2, SYSCALL_EVENT_OPENAT2, FILE_EVENT)
HNG_DEFINE_EXIT_PROBE(creat, SYSCALL_EVENT_CREAT, FILE_EVENT)
HNG_DEFINE_EXIT_PROBE(unlink, SYSCALL_EVENT_UNLINK, FILE_EVENT)
HNG_DEFINE_EXIT_PROBE(link, SYSCALL_EVENT_LINK, FILE_EVENT)
HNG_DEFINE_EXIT_PROBE(rename, SYSCALL_EVENT_RENAME, FILE_EVENT)
HNG_DEFINE_EXIT_PROBE(renameat, SYSCALL_EVENT_RENAMEAT, FILE_EVENT)
HNG_DEFINE_EXIT_PROBE(renameat2, SYSCALL_EVENT_RENAMEAT2, FILE_EVENT)
HNG_DEFINE_EXIT_PROBE(unlinkat, SYSCALL_EVENT_UNLINKAT, FILE_EVENT)
HNG_DEFINE_EXIT_PROBE(linkat, SYSCALL_EVENT_LINKAT, FILE_EVENT)
HNG_DEFINE_EXIT_PROBE(symlink, SYSCALL_EVENT_SYMLINK, FILE_EVENT)
HNG_DEFINE_EXIT_PROBE(symlinkat, SYSCALL_EVENT_SYMLINKAT, FILE_EVENT)
HNG_DEFINE_EXIT_PROBE(chmod, SYSCALL_EVENT_CHMOD, FILE_EVENT)
HNG_DEFINE_EXIT_PROBE(fchmod, SYSCALL_EVENT_FCHMOD, FILE_EVENT)
HNG_DEFINE_EXIT_PROBE(fchmodat, SYSCALL_EVENT_FCHMODAT, FILE_EVENT)
HNG_DEFINE_EXIT_PROBE(truncate, SYSCALL_EVENT_TRUNCATE, FILE_EVENT)
HNG_DEFINE_EXIT_PROBE(ftruncate, SYSCALL_EVENT_FTRUNCATE, FILE_EVENT)
HNG_DEFINE_EXIT_PROBE(mknod, SYSCALL_EVENT_MKNOD, FILE_EVENT)
HNG_DEFINE_EXIT_PROBE(mknodat, SYSCALL_EVENT_MKNODAT, FILE_EVENT)
HNG_DEFINE_EXIT_PROBE(memfd_create, SYSCALL_EVENT_MEMFD_CREATE, FILE_EVENT)
HNG_DEFINE_EXIT_PROBE(open_by_handle_at, SYSCALL_EVENT_OPEN_BY_HANDLE_AT,
                      FILE_EVENT)
HNG_DEFINE_EXIT_PROBE(name_to_handle_at, SYSCALL_EVENT_NAME_TO_HANDLE_AT,
                      FILE_EVENT)
HNG_DEFINE_EXIT_PROBE(chdir, SYSCALL_EVENT_CHDIR, FILE_EVENT)
HNG_DEFINE_EXIT_PROBE(fchdir, SYSCALL_EVENT_FCHDIR, FILE_EVENT)

// MEMORY
HNG_DEFINE_EXIT_PROBE(mmap, SYSCALL_EVENT_MMAP, MEMORY_EVENT)
HNG_DEFINE_EXIT_PROBE(mprotect, SYSCALL_EVENT_MPROTECT, MEMORY_EVENT)
HNG_DEFINE_EXIT_PROBE(mremap, SYSCALL_EVENT_MREMAP, MEMORY_EVENT)
HNG_DEFINE_EXIT_PROBE(munmap, SYSCALL_EVENT_MUNMAP, MEMORY_EVENT)

// NETWORK
HNG_DEFINE_EXIT_PROBE(connect, SYSCALL_EVENT_CONNECT, NETWORK_EVENT)
HNG_DEFINE_EXIT_PROBE_OPTIONAL(sendto, SYSCALL_EVENT_SENDTO, NETWORK_EVENT)
HNG_DEFINE_EXIT_PROBE_OPTIONAL(sendmsg, SYSCALL_EVENT_SENDMSG, NETWORK_EVENT)
HNG_DEFINE_EXIT_PROBE(socket, SYSCALL_EVENT_SOCKET, NETWORK_EVENT)
HNG_DEFINE_EXIT_PROBE(bind, SYSCALL_EVENT_BIND, NETWORK_EVENT)
HNG_DEFINE_EXIT_PROBE(recvfrom, SYSCALL_EVENT_RECVFROM, NETWORK_EVENT)
HNG_DEFINE_EXIT_PROBE(accept4, SYSCALL_EVENT_ACCEPT4, NETWORK_EVENT)
HNG_DEFINE_EXIT_PROBE(listen, SYSCALL_EVENT_LISTEN, NETWORK_EVENT)

// KERNEL
HNG_DEFINE_EXIT_PROBE(ptrace, SYSCALL_EVENT_PTRACE, KERNEL_EVENT)
HNG_DEFINE_EXIT_PROBE(bpf, SYSCALL_EVENT_BPF, KERNEL_EVENT)
HNG_DEFINE_EXIT_PROBE(init_module, SYSCALL_EVENT_INIT_MODULE, KERNEL_EVENT)
HNG_DEFINE_EXIT_PROBE(finit_module, SYSCALL_EVENT_FINIT_MODULE, KERNEL_EVENT)
HNG_DEFINE_EXIT_PROBE(delete_module, SYSCALL_EVENT_DELETE_MODULE, KERNEL_EVENT)
HNG_DEFINE_EXIT_PROBE(kexec_load, SYSCALL_EVENT_KEXEC_LOAD, KERNEL_EVENT)
HNG_DEFINE_EXIT_PROBE(reboot, SYSCALL_EVENT_REBOOT, KERNEL_EVENT)
HNG_DEFINE_EXIT_PROBE(sethostname, SYSCALL_EVENT_SETHOSTNAME, KERNEL_EVENT)

// SIGNAL
HNG_DEFINE_EXIT_PROBE(kill, SYSCALL_EVENT_KILL, SIGNAL_EVENT)
HNG_DEFINE_EXIT_PROBE(tkill, SYSCALL_EVENT_TKILL, SIGNAL_EVENT)
HNG_DEFINE_EXIT_PROBE(tgkill, SYSCALL_EVENT_TGKILL, SIGNAL_EVENT)
HNG_DEFINE_EXIT_PROBE(rt_sigqueueinfo, SYSCALL_EVENT_RT_SIGQUEUEINFO,
                      SIGNAL_EVENT)

/** @} */

char LICENSE[] SEC("license") = "GPL";
