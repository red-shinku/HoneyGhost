#ifndef HNG_SYSCALL_PATH_HELPERS_BPF_H_
#define HNG_SYSCALL_PATH_HELPERS_BPF_H_

#include "kernel/include/path_resolver.bpf.h"
#include "kernel/include/syscall_event_type.h"

/**
 * @brief 解析一条路径并记录解析状态位。
 * @param[out] dst 目标缓冲，接收绝对路径；解析失败时是用户原始串
 * @param[in] sz dst 容量
 * @param[out] path_flags 解析状态位，失败时按结果或上 PATH_*
 * @param[in] user_path 用户态路径串
 * @param[in] dirfd 基准目录 fd；AT_FDCWD 表示当前工作目录
 * @note 返回 -1 置 PATH_UNRESOLVED、返回 -2 置 PATH_TRUNCATED，成功不置位。
 * @note path_flags 由调用者的 init 函数预先清零。
 * @see hng_resolve_user_path
 */
static __always_inline void hng_fill_file_path(char *dst, __u32 sz,
                                               __u32 *path_flags,
                                               const void *user_path, int dirfd)
{
    long written = hng_resolve_user_path(dst, sz, user_path, dirfd);
    if (written == -1) {
        *path_flags |= PATH_UNRESOLVED;
    }
    else if (written == -2) {
        *path_flags |= PATH_TRUNCATED;
    }
}

/**
 * @brief 依次解析文件事件的两条路径。
 * @param[in,out] file 目标文件事件载荷；path1/path2 及其状态位由本函数填写
 * @param[in] path1 用户态主路径串
 * @param[in] dirfd path1 的基准目录 fd
 * @param[in] path2 用户态第二路径串；无第二路径时传 NULL
 * @param[in] dirfd2 path2 的基准目录 fd
 * @note 两条路径串行解析，解析器（约 256B 栈）同一时刻只有一份在用；路径串为
 *       NULL 时对应字段留空串、状态位保持 init 的清零值。
 * @see hng_fill_file_path
 */
static __always_inline void hng_fill_file_paths(struct file_event *file,
                                                const void *path1, int dirfd,
                                                const void *path2, int dirfd2)
{
    if (path1) {
        hng_fill_file_path(file->path1, sizeof(file->path1), &file->path1_flags,
                           path1, dirfd);
    }
    if (path2) {
        hng_fill_file_path(file->path2, sizeof(file->path2), &file->path2_flags,
                           path2, dirfd2);
    }
}
#endif
