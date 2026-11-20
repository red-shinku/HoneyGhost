#ifndef HNG_EXEC_HELPERS_BPF_H_
#define HNG_EXEC_HELPERS_BPF_H_

#include "kernel/include/syscall_event_type.h"

#include <bpf/bpf_helpers.h>

/// @brief execve 扫描 envp 的项数上限
#define HNG_MAX_ENVP 16

/// @brief 判前缀用的环境变量头部字节数，须覆盖最长的 "LD_LIBRARY_PATH=" 及其 NUL
#define HNG_ENV_HEAD_LEN 18

/// @brief "LD_PRELOAD=" 与 "LD_LIBRARY_PATH=" 的长度（含 '='）
#define HNG_LD_PRELOAD_LEN 11
#define HNG_LD_LIBRARY_PATH_LEN 16

/**
 * @brief 读取 argv 数组下标 index 处的字符串
 * @param[out] dst 目标缓冲，接收以 NUL 结尾的参数
 * @param[in] sz 容量
 * @param[in] argv_ptr 用户态 argv 数组
 * @param[in] index 数组下标
 * @return 该下标存在且非 NULL 时返回 true；数组提前结束或读取失败返回 false
 * @note 返回值只表示「数组还有这一项」；空串参数同样返回 true。
 */
static __always_inline bool read_argv_entry(char *dst, __u32 sz, __u64 argv_ptr,
                                            __u32 index)
{
    if (!argv_ptr) {
        return false;
    }
    const char *entry = NULL;
    if (bpf_probe_read_user(&entry, sizeof(entry),
                            (void *)(argv_ptr + (__u64)index * sizeof(char *))) ||
        !entry) {
        return false;
    }
    if (bpf_probe_read_user_str(dst, sz, entry) < 0) {
        dst[0] = '\0';
    }
    return true;
}

/**
 * @brief 依次填充 argv0..argv3
 * @param[out] e 目标 exec 事件载荷
 * @param[in] argv_ptr 用户态 argv 数组
 * @note 用户的 argv 数组可以提前以 NULL 结尾：某一项不存在即停止，其余保持
 *       init 的清零空串；不越界读取，故不会把 envp 的首项当成参数。
 */
static __always_inline void fill_exec_argv(struct exec_event *e, __u64 argv_ptr)
{
    if (!read_argv_entry(e->argv0, sizeof(e->argv0), argv_ptr, 0)) return;
    if (!read_argv_entry(e->argv1, sizeof(e->argv1), argv_ptr, 1)) return;
    if (!read_argv_entry(e->argv2, sizeof(e->argv2), argv_ptr, 2)) return;
    read_argv_entry(e->argv3, sizeof(e->argv3), argv_ptr, 3);
}

/**
 * @brief 变量串是否以 "LD_PRELOAD=" 开头
 * @param head 环境变量串的头部，至少 HNG_LD_PRELOAD_LEN 字节
 */
static __always_inline bool is_ld_preload(const char *head)
{
    return head[0] == 'L' && head[1] == 'D' && head[2] == '_' && head[3] == 'P' &&
           head[4] == 'R' && head[5] == 'E' && head[6] == 'L' && head[7] == 'O' &&
           head[8] == 'A' && head[9] == 'D' && head[10] == '=';
}

/**
 * @brief 变量串是否以 "LD_LIBRARY_PATH=" 开头
 * @param head 环境变量串的头部，至少 HNG_LD_LIBRARY_PATH_LEN 字节
 */
static __always_inline bool is_ld_library_path(const char *head)
{
    return head[0] == 'L' && head[1] == 'D' && head[2] == '_' && head[3] == 'L' &&
           head[4] == 'I' && head[5] == 'B' && head[6] == 'R' && head[7] == 'A' &&
           head[8] == 'R' && head[9] == 'Y' && head[10] == '_' &&
           head[11] == 'P' && head[12] == 'A' && head[13] == 'T' &&
           head[14] == 'H' && head[15] == '=';
}

/**
 * @brief 扫描 envp 前 HNG_MAX_ENVP 项，取出 LD_PRELOAD/LD_LIBRARY_PATH 的值
 * @param[out] e 目标 exec 事件载荷；ld_preload 与 ld_library_path 由本函数填写
 * @param[in] envp_ptr 用户态 envp 数组
 * @note 先读变量头部判前缀，命中后再从值的起点重读整串，故不命中的变量不会
 *       写进目标字段；字符串直接读进 map value 的字段，栈上只有头部缓冲。
 * @note 数组提前以 NULL 结尾时停止；两项都未出现时字段保持 init 的清零空串。
 */
static __always_inline void fill_exec_env(struct exec_event *e, __u64 envp_ptr)
{
    if (!envp_ptr) {
        return;
    }
#ifdef __clang__
#pragma clang loop unroll(full)
#endif
    for (int i = 0; i < HNG_MAX_ENVP; ++i) {
        const char *entry = NULL;
        if (bpf_probe_read_user(&entry, sizeof(entry),
                                (void *)(envp_ptr + (__u64)i * sizeof(char *))) ||
            !entry) {
            break;
        }
        //! @note 逐项清零：短串只写到自己的 NUL，残留字节会让前缀比较误命中
        char head[HNG_ENV_HEAD_LEN] = {};
        if (bpf_probe_read_user_str(head, sizeof(head), entry) < 0) {
            continue;
        }
        if (is_ld_library_path(head)) {
            bpf_probe_read_user_str(e->ld_library_path,
                                    sizeof(e->ld_library_path),
                                    entry + HNG_LD_LIBRARY_PATH_LEN);
        }
        else if (is_ld_preload(head)) {
            bpf_probe_read_user_str(e->ld_preload, sizeof(e->ld_preload),
                                    entry + HNG_LD_PRELOAD_LEN);
        }
    }
}
#endif
