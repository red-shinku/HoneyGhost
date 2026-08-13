/**
 * @file files.bpf.c
 * @brief 监控文件访问，用于后续描绘文件访问画像
 * @details 提供信息：访问发起者、文件路径、打开方式
 * @author red_shinku
 * @date 2026.08.05
 */

#include "./include/vmlinux.h"
#include "../include/files_type.h"
#include "../include/uapi_const.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// extern int LINUX_KERNEL_VERSION __kconfig;

/**
 * @brief RingBuf，存储文件事件的数据（file_access_data）
 *       用户态程序通过该结构获取数据
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} file_access_events SEC(".maps");

/**
 * @brief 文件事件数据结构的初始化函数
 * @return NULL 初始化失败
 * @return struct file_access_data* 初始化成功，返回指针
 */
static __always_inline struct file_access_data *init_file_access_data(void)
{
    struct file_access_data *data = bpf_ringbuf_reserve(&file_access_events, sizeof(struct file_access_data), 0);
    if (!data) {
        return NULL;
    }
    init_event_head(&data->head);

    return data;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_file_openat(struct trace_event_raw_sys_enter *ctx)
{
    struct file_access_data *data = init_file_access_data();
    if (!data) return 0;

    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    bpf_probe_read_user_str(&data->filename, sizeof(data->filename), (void *)ctx->args[1]);
    data->flags = ctx->args[2];

    bpf_ringbuf_submit(data, BPF_RB_NO_WAKEUP);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_open")
int trace_file_open(struct trace_event_raw_sys_enter *ctx)
{
    struct file_access_data *data = init_file_access_data();
    if (!data) return 0;

    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    bpf_probe_read_user_str(&data->filename, sizeof(data->filename), (void *)ctx->args[0]);
    data->flags = ctx->args[1];

    bpf_ringbuf_submit(data, BPF_RB_NO_WAKEUP);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_creat")
int trace_file_creat(struct trace_event_raw_sys_enter *ctx)
{
    struct file_access_data *data = init_file_access_data();
    if (!data) return 0;

    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    bpf_probe_read_user_str(&data->filename, sizeof(data->filename), (void *)ctx->args[0]);
    data->flags = O_CREAT | O_WRONLY | O_TRUNC;

    bpf_ringbuf_submit(data, BPF_RB_NO_WAKEUP);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat2")
int trace_file_openat2(struct trace_event_raw_sys_enter *ctx)
{
    // if(LINUX_KERNEL_VERSION < KERNEL_VERSION(5, 6, 0)) {
    //     return 0;
    // }
    struct file_access_data *data = init_file_access_data();
    if (!data) return 0;

    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    bpf_probe_read_user_str(&data->filename, sizeof(data->filename), (void *)ctx->args[1]);

    struct open_how how;
    if (bpf_probe_read_user(&how, sizeof(how), (void *)ctx->args[2]) == 0) {
        data->flags = how.flags;
    }
    else {
        data->flags = 0;
    }

    bpf_ringbuf_submit(data, BPF_RB_NO_WAKEUP);

    return 0;
}

// TODO: 错误处理？