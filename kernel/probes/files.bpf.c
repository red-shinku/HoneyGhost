/**
 * @file files.bpf.c
 * @brief 监控文件访问，用于后续描绘文件访问画像
 * @details 提供信息：访问发起者、文件路径、打开方式
 * @author red_shinku
 * @date 2026.08.05
 */

#include "kernel/include/vmlinux.h"
#include "kernel/include/role_filter.bpf.h"
#include "kernel/include/files_type.h"
#include "kernel/include/uapi_const.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/** @note 当前不启用 LINUX_KERNEL_VERSION 的 kconfig 声明及版本判断。 */

/**
 * @brief RingBuf，存储文件事件的数据（file_access_data）
 *       用户态程序通过该结构获取数据
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} file_access_events SEC(".maps");

/**
 * @brief 判定当前进程是否处于非初始 mount 命名空间
 * @details
 * 路径参数是在调用进程的挂载命名空间视图中解释的，容器内与宿主机对同一路径的
 * 语义不同。通过 task->nsproxy->mnt_ns->ns.inum 读取当前挂载命名空间的 inode：
 * 初始挂载命名空间的 inode 恒为 0xF0000000（4026531840，宿主根命名空间，各内核
 * 版本稳定），其余为容器 / 自定义命名空间（inode 或大于或小于该值，故用精确比较）。
 * 读取失败按"不在命名空间中"保守处理。
 * @return 非初始挂载命名空间返回 1，否则返回 0。
 */
static __always_inline __u8 current_is_innamespace(void)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) {
        return 0;
    }
    struct nsproxy *nsproxy = BPF_CORE_READ(task, nsproxy);
    if (!nsproxy) {
        return 0;
    }
    struct mnt_namespace *mnt_ns = BPF_CORE_READ(nsproxy, mnt_ns);
    if (!mnt_ns) {
        return 0;
    }
    unsigned int inum = BPF_CORE_READ(mnt_ns, ns.inum);
    return inum == 4026531840 ? 0 : 1;
}

/**
 * @brief 文件事件数据结构的初始化函数
 * @return 初始化成功时返回 ringbuf 事件指针；角色被过滤或空间不足时返回 NULL。
 * @note 调用者须对返回的事件执行提交或丢弃，完成 ringbuf 资源处理。
 */
static __always_inline struct file_access_data *init_file_access_data(void)
{
    if (!hng_should_collect()) return NULL;
    struct file_access_data *data = bpf_ringbuf_reserve(&file_access_events, sizeof(struct file_access_data), 0);
    if (!data) {
        return NULL;
    }
    init_event_head(&data->head);
    data->is_innamespace = current_is_innamespace();

    return data;
}

/**
 * @brief 处理 sys_enter_openat 事件并提交采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过提交。
 */
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

/**
 * @brief 处理 sys_enter_open 事件并提交采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过提交。
 */
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

/**
 * @brief 处理 sys_enter_creat 事件并提交采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过提交。
 */
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

/**
 * @brief 处理 sys_enter_openat2 事件并提交采集结果。
 * @param[in] ctx 系统调用入口的 tracepoint 上下文。
 * @return 始终返回 0；未命中采集条件或无法构造事件时跳过提交。
 */
SEC("tracepoint/syscalls/sys_enter_openat2")
int trace_file_openat2(struct trace_event_raw_sys_enter *ctx)
{
    /**
     * @note 以下版本判断示例尚未启用，保留为兼容性说明。
     * @code{.c}
     * if (LINUX_KERNEL_VERSION < KERNEL_VERSION(5, 6, 0)) {
     *     return 0;
     * }
     * @endcode
     */
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

char LICENSE[] SEC("license") = "GPL";

//! @todo 完善文件事件采集失败时的错误处理。
