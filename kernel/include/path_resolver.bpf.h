/**
 * @file path_resolver.bpf.h
 * @brief eBPF 侧把 struct path 解析为绝对路径、把用户态的路径转换为绝对路径。
 * @details
 * 解析不访问文件系统，只在有界深度内逐级上溯 dentry：遇到挂载点根时经
 * mnt_parent/mnt_mountpoint 跨到父挂载，直到进程根（通常为 fs->root）或
 * 文件系统根。解析结果与用户实际使用的路径逐段一致，不做符号链接展开，
 * 也不做 "."、".." 的词法归一。
 *
 * 该头文件同时被内核探针与主机侧单元测试引用：指针运算一律显式转换为
 * char * 或 struct mount *，不使用 void * 算术。
 */
#ifndef HNG_PATH_RESOLVER_BPF_H_
#define HNG_PATH_RESOLVER_BPF_H_

#include "kernel/include/syscall_event_type.h"
#include "kernel/include/uapi_const.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

/// @brief dentry 上溯的最大级数；到达该级数仍未到根即判定无法解析
#define HNG_PATH_MAX_DEPTH 32

/**
 * @brief 读取当前进程文件描述符表中 fd 对应的 struct file。
 * @param fd 文件描述符
 * @return 对应的 file；fd 为负、越界、未打开或任一环节读取失败时返回 NULL。
 * @note 仅用于本次探针内的读取，不转移所有权；fd 被并发关闭时读到的是当时的快照。
 */
static __always_inline struct file *hng_file_from_fd(int fd)
{
    if (fd < 0) {
        return NULL;
    }
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) {
        return NULL;
    }
    struct files_struct *files = BPF_CORE_READ(task, files);
    if (!files) {
        return NULL;
    }
    struct fdtable *fdt = BPF_CORE_READ(files, fdt);
    if (!fdt) {
        return NULL;
    }
    __u32 max_fds = BPF_CORE_READ(fdt, max_fds);
    if ((__u32)fd >= max_fds) {
        return NULL;
    }
    struct file **fd_array = BPF_CORE_READ(fdt, fd);
    if (!fd_array) {
        return NULL;
    }
    struct file *file = NULL;
    if (bpf_probe_read_kernel(&file, sizeof(file), &fd_array[fd])) {
        return NULL;
    }
    return file;
}

/**
 * @brief 由 struct path 中的 vfsmount 反推所属的 struct mount。
 * @param mnt 内嵌在 struct mount 中的 vfsmount
 * @return 所属 mount；mnt 非法时结果不可用。
 * @note struct mount 的 mnt 字段不一定在偏移 0，偏移由 CO-RE 重定位给出。
 */
static __always_inline struct mount *hng_mount_of(struct vfsmount *mnt)
{
    return (struct mount *)((char *)mnt -
                            bpf_core_field_offset(struct mount, mnt));
}

/**
 * @brief 取 struct mount 内嵌的 vfsmount 地址。
 * @param mount_ptr 目标 mount
 * @return 内嵌 vfsmount；偏移同样由 CO-RE 重定位给出。
 */
static __always_inline struct vfsmount *hng_mount_vfsmount(
    struct mount *mount_ptr)
{
    return (struct vfsmount *)((char *)mount_ptr +
                               bpf_core_field_offset(struct mount, mnt));
}

/**
 * @brief 把 struct path 解析为绝对路径写入 dst。
 * @param dst 目标缓冲（ringbuf 记录或 map value 内）
 * @param sz 目标缓冲容量
 * @param path 起始 path
 * @param root 停止边界；通常为进程的 fs->root
 * @return 写入长度（含 NUL）；-1 表示无法解析，-2 表示结果超出 sz
 * @note 逐级上溯 dentry，遇 mnt->mnt_root 经 mnt_parent/mnt_mountpoint 跨挂载点，
 *       最多 HNG_PATH_MAX_DEPTH 级；结果以 '/' 开头，各段之间只有一个 '/'。
 * @note path 与 root 指向可直接读取的 struct path 副本；内核字段的 CO-RE 读取由
 *       调用者完成。上溯阶段的 dentry 指针全部落在栈上，占用
 *       HNG_PATH_MAX_DEPTH * sizeof(void *) 字节。
 */
static __always_inline long hng_path_str(char *dst, __u32 sz,
                                         const struct path *path,
                                         const struct path *root)
{
    if (!dst || !path || !root) {
        return -1;
    }
    if (sz < 2) {
        return -2;
    }

    struct vfsmount *mnt             = path->mnt;
    const struct dentry *dentry      = path->dentry;
    const struct vfsmount *root_mnt  = root->mnt;
    const struct dentry *root_dentry = root->dentry;
    if (!mnt || !dentry || !root_mnt || !root_dentry) {
        return -1;
    }

    /**
     * @note segs[0] 是起点，下标越大越靠近根。上溯循环全展开且下标为常量，
     *       verifier 才能确认每次读取的栈槽已经写过。
     */
    const struct dentry *segs[HNG_PATH_MAX_DEPTH] = {};
    __u32 depth                                   = 0;
    int done                                      = 0;

#ifdef __clang__
#pragma clang loop unroll(full)
#endif
    for (int i = 0; i < HNG_PATH_MAX_DEPTH; ++i) {
        if (done) {
            break;
        }
        if (dentry == root_dentry && mnt == root_mnt) {
            done = 1;
            break;
        }
        if (dentry == BPF_CORE_READ(mnt, mnt_root)) {
            struct mount *mount_ptr = hng_mount_of(mnt);
            struct mount *parent    = BPF_CORE_READ(mount_ptr, mnt_parent);
            //! @note 根 mount 的 mnt_parent 指向自身：已到挂载树顶端
            if (!parent || parent == mount_ptr) {
                done = 1;
                break;
            }
            dentry = BPF_CORE_READ(mount_ptr, mnt_mountpoint);
            mnt    = hng_mount_vfsmount(parent);
            if (!dentry || !mnt) {
                return -1;
            }
            //! @note 跨挂载后可能正好落在根上：根 dentry 本身不构成路径段
            if (dentry == root_dentry && mnt == root_mnt) {
                done = 1;
                break;
            }
        }
        segs[i]               = dentry;
        depth                 = (__u32)i + 1;

        struct dentry *parent = BPF_CORE_READ(dentry, d_parent);
        //! @note d_parent 指向自身即文件系统根，无法再上溯
        if (!parent || parent == dentry) {
            done = 1;
            break;
        }
        dentry = parent;
    }
    //! @note 最后一段的父正好是根时，级数用尽但确实已到根
    if (!done && dentry == root_dentry && mnt == root_mnt) {
        done = 1;
    }
    if (!done) {
        return -1;
    }

    //! @note 根路径只有开头的 '/'；其余段按「根 → 起点」的顺序写入
    __u32 off = 1;
    dst[0]    = '/';
#ifdef __clang__
#pragma clang loop unroll(full)
#endif
    for (int i = HNG_PATH_MAX_DEPTH - 1; i >= 0; --i) {
        if ((__u32)i >= depth) {
            continue;
        }
        if (off > 1) {
            if (off >= sz) {
                dst[sz - 1] = '\0';
                return -2;
            }
            dst[off] = '/';
            ++off;
        }
        long n = bpf_probe_read_kernel_str(dst + off, sz - off,
                                           BPF_CORE_READ(segs[i], d_name.name));
        if (n < 0) {
            return -1;
        }
        //! @note helper 不区分「恰好填满」与「被截断」，写满缓冲一律按截断处理
        if ((__u32)n >= sz - off) {
            dst[sz - 1] = '\0';
            return -2;
        }
        /**
         * @note 掩码不能省，且 next 必须先过 barrier_var：没有屏障时编译器能据
         *       上面的截断检查推出 next < sz，把掩码当成无操作删掉；而 verifier
         *       不跟踪跨轮相关性，只按寄存器范围算长度参数 sz - off，会得到含
         *       负值的范围并以 "R2 min value is negative" 拒绝加载。
         * @note 掩码要求 sz 是 2 的幂（调用点恒为 MAX_PATH_LEN=256）。截断检查
         *       已保证 next ≤ sz-1，这里的掩码在语义上是无操作。
         */
        __u32 next = off + (__u32)n - 1;
        barrier_var(next);
        off = next & (sz - 1);
    }
    dst[off] = '\0';
    return (long)off + 1;
}

/**
 * @brief 无法解析时把用户原始串写入 dst。
 * @param dst 目标缓冲
 * @param sz 容量
 * @param user_path 用户态路径串
 * @return 恒为 -1
 * @note dst 始终以 NUL 结尾；用户串读不到时为空串，超长时保留截断前缀。
 */
static __always_inline long hng_keep_raw_path(char *dst, __u32 sz,
                                              const void *user_path)
{
    long n = bpf_probe_read_user_str(dst, sz, user_path);
    if (n < 0) {
        dst[0] = '\0';
        return -1;
    }
    if ((__u32)n >= sz) {
        dst[sz - 1] = '\0';
    }
    return -1;
}

/**
 * @brief 绝对用户串直接写入 dst。
 * @param dst 目标缓冲
 * @param sz 容量
 * @param user_path 用户态绝对路径串
 * @return 写入长度（含 NUL）；-1 读不到，-2 超出 sz
 */
static __always_inline long hng_copy_absolute(char *dst, __u32 sz,
                                              const void *user_path)
{
    long n = bpf_probe_read_user_str(dst, sz, user_path);
    if (n < 0) {
        dst[0] = '\0';
        return -1;
    }
    if ((__u32)n >= sz) {
        dst[sz - 1] = '\0';
        return -2;
    }
    return n;
}

/**
 * @brief 把用户给出的路径解析为绝对路径。
 * @param dst 目标缓冲
 * @param sz 容量
 * @param user_path 用户态路径串
 * @param dirfd 基准目录 fd；AT_FDCWD 表示当前工作目录
 * @return 写入长度（含 NUL）；-1 无法解析（dst 保留用户原始串，读不到时为空）、
 *         -2 截断（dst 为已写入的绝对前缀）
 * @note 词法归一（尾斜杠、//、.、..）都由用户态完成，内核只保证结果以 '/'
 *       开头；相对路径以基准目录为前缀拼接，取不到基准时按无法解析处理。
 * @note 空的用户串（AT_EMPTY_PATH）返回 1，即写入的只有 NUL。
 */
static __always_inline long hng_resolve_user_path(char *dst, __u32 sz,
                                                  const void *user_path,
                                                  int dirfd)
{
    if (!dst || sz == 0) {
        return -1;
    }
    dst[0] = '\0';
    if (!user_path) {
        return -1;
    }

    char first = 0;
    if (bpf_probe_read_user(&first, 1, user_path)) {
        return -1;
    }
    if (first == '\0') {
        return 1;
    }
    if (first == '/') {
        return hng_copy_absolute(dst, sz, user_path);
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) {
        return hng_keep_raw_path(dst, sz, user_path);
    }
    struct fs_struct *fs = BPF_CORE_READ(task, fs);
    if (!fs) {
        return hng_keep_raw_path(dst, sz, user_path);
    }

    struct path base = {};
    if (dirfd == AT_FDCWD) {
        BPF_CORE_READ_INTO(&base, fs, pwd);
    }
    else {
        struct file *file = hng_file_from_fd(dirfd);
        if (!file) {
            return hng_keep_raw_path(dst, sz, user_path);
        }
        BPF_CORE_READ_INTO(&base, file, f_path);
    }
    struct path root = {};
    BPF_CORE_READ_INTO(&root, fs, root);

    long n = hng_path_str(dst, sz, &base, &root);
    if (n == -2) {
        return -2;
    }
    if (n < 0) {
        return hng_keep_raw_path(dst, sz, user_path);
    }

    __u32 off = 0;
    if (n == 2) {
        //! @note 基准恰为根：dst 已以 '/' 开头，不再补分隔符
        off = 1;
    }
    else {
        off = (__u32)n - 1;
        if (off + 1 >= sz) {
            return -2;
        }
        dst[off] = '/';
        ++off;
    }

    long m = bpf_probe_read_user_str(dst + off, sz - off, user_path);
    if (m < 0) {
        return hng_keep_raw_path(dst, sz, user_path);
    }
    if ((__u32)m >= sz - off) {
        dst[sz - 1] = '\0';
        return -2;
    }
    return (long)(off + (__u32)m);
}

/**
 * @brief 把当前任务的进程镜像写入 EXEC 事件的 image 字段。
 * @param pending 暂存中的 EXEC 事件；image 与 image_flags 由本函数填写
 * @note 镜像取 task->mm->exe_file 的 f_path，解析边界取 task->fs->root。
 * @note mm、exe_file、fs 任一为空，或路径解析失败时置 PATH_UNRESOLVED，
 *       image 为空串；解析被截断时置 PATH_TRUNCATED 并保留绝对前缀。
 * @note exec 失败时同样调用：此时 mm->exe_file 仍是旧镜像，由事件的 ret
 *       区分成功与失败。
 * @note 结果直接写入 map value，不在栈上另开路径缓冲；本函数自身只用
 *       hng_path_str 的固定栈占用。
 */
static __always_inline void hng_fill_exec_image(struct syscall_event *pending)
{
    if (!pending) {
        return;
    }
    pending->exec_event.image[0]    = '\0';
    pending->exec_event.image_flags = PATH_UNRESOLVED;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) {
        return;
    }
    struct mm_struct *mm = BPF_CORE_READ(task, mm);
    if (!mm) {
        return;
    }
    struct file *exe_file = BPF_CORE_READ(mm, exe_file);
    if (!exe_file) {
        return;
    }
    struct fs_struct *fs = BPF_CORE_READ(task, fs);
    if (!fs) {
        return;
    }

    struct path image_path = {};
    BPF_CORE_READ_INTO(&image_path, exe_file, f_path);
    struct path root = {};
    BPF_CORE_READ_INTO(&root, fs, root);

    long written =
        hng_path_str(pending->exec_event.image, sizeof(pending->exec_event.image),
                     &image_path, &root);
    if (written == -1) {
        pending->exec_event.image_flags = PATH_UNRESOLVED;
        pending->exec_event.image[0]    = '\0';
    }
    else if (written == -2) {
        pending->exec_event.image_flags = PATH_TRUNCATED;
    }
    else {
        pending->exec_event.image_flags = 0;
    }
}

/**
 * @brief 把 mmap 的源文件路径写入 MEMORY 事件的 path 字段。
 * @param pending 暂存中的 MEMORY 事件；path 与 path_flags 由本函数填写
 * @note 匿名映射（MAP_ANONYMOUS 或 fd < 0）不解析：path 为空串、path_flags 为 0。
 * @note 文件映射取 fd → struct file → f_path，解析边界取 task->fs->root；mmap
 *       不关闭源 fd，故 exit 侧仍读得到同一文件。
 * @note file、fs 取不到或路径解析失败时置 PATH_UNRESOLVED 并留空串；解析被
 *       截断时置 PATH_TRUNCATED 并保留绝对前缀。
 * @note 结果直接写入 map value，不在栈上另开路径缓冲；本函数自身只用
 *       hng_path_str 的固定栈占用。
 * @see hng_fill_exec_image, hng_path_str
 */
static __always_inline void hng_fill_mmap_path(struct syscall_event *pending)
{
    if (!pending) {
        return;
    }
    pending->memory_event.path[0]    = '\0';
    pending->memory_event.path_flags = 0;
    if (pending->memory_event.fd < 0 || pending->memory_event.anonymous) {
        return;
    }

    struct file *file = hng_file_from_fd(pending->memory_event.fd);
    if (!file) {
        pending->memory_event.path_flags = PATH_UNRESOLVED;
        return;
    }
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) {
        pending->memory_event.path_flags = PATH_UNRESOLVED;
        return;
    }
    struct fs_struct *fs = BPF_CORE_READ(task, fs);
    if (!fs) {
        pending->memory_event.path_flags = PATH_UNRESOLVED;
        return;
    }

    struct path file_path = {};
    BPF_CORE_READ_INTO(&file_path, file, f_path);
    struct path root = {};
    BPF_CORE_READ_INTO(&root, fs, root);

    long written =
        hng_path_str(pending->memory_event.path,
                     sizeof(pending->memory_event.path), &file_path, &root);
    if (written == -1) {
        pending->memory_event.path_flags = PATH_UNRESOLVED;
        pending->memory_event.path[0]    = '\0';
    }
    else if (written == -2) {
        pending->memory_event.path_flags = PATH_TRUNCATED;
    }
}

#endif  // HNG_PATH_RESOLVER_BPF_H_
