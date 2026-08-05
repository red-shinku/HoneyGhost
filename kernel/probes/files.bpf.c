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

struct file_open_data {
    struct event_head head;

    u32 pid;
    char comm[16];
    char filename[256];
    u64 flags;
};

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_file_open(struct trace_event_raw_sys_enter *ctx)
{
    struct file_open_data data = {};
    init_event_head(&data.head);

    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), (void *)ctx->args[1]);
    data.flags = ctx->args[2];

    return 0;
}