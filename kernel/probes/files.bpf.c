/**
 * @file files.bpf.c
 * @brief 监控文件访问，用于后续描绘文件访问画像
 * @details 提供信息：访问发起者、文件路径、打开方式
 * @author red_shinku
 * @date 2026.08.05
 */

#include "../include/vmlinux.h"
#include "../include/event_head.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// extern int LINUX_KERNEL_VERSION __kconfig;

struct file_access_data {
    struct event_head head;

    u32 pid;
    char comm[16];
    char filename[256];
    u64 flags;
};

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_file_openat(struct trace_event_raw_sys_enter *ctx)
{
    struct file_access_data data = {};
    init_event_head(&data.head);

    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), (void *)ctx->args[1]);
    data.flags = ctx->args[2];

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_open")
int trace_file_open(struct trace_event_raw_sys_enter *ctx)
{
    struct file_access_data data = {};
    init_event_head(&data.head);

    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), (void *)ctx->args[0]);
    data.flags = ctx->args[1];

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_creat")
int trace_file_creat(struct trace_event_raw_sys_enter *ctx)
{
    struct file_access_data data = {};
    init_event_head(&data.head);

    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), (void *)ctx->args[0]);
    data.flags = O_CREAT | O_WRONLY | O_TRUNC;

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat2")
int trace_file_openat2(struct trace_event_raw_sys_enter *ctx)
{
    // if(LINUX_KERNEL_VERSION < KERNEL_VERSION(5, 6, 0)) {
    //     return 0;
    // }
    struct file_access_data data = {};
    init_event_head(&data.head);

    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), (void *)ctx->args[1]);

    struct open_how how;
    if (bpf_probe_read_user(&how, sizeof(how), (void *)ctx->args[2]) == 0) {
        data.flags = how.flags;
    } else {
        data.flags = 0;
    }

    return 0;
}