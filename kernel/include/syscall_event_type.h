/**
 * @file syscall_event_type.h
 * @brief 此文件定义系统调用事件收集模块的数据结构
 * @details
 *
 * 将九种事件用union联合到 syscall_event 中
 * 事件收集均放回该结构
 * 用户态直接引用该头文件以使用相关结构
 *
 * @author red_shinku
 * @date 2026.08.12
 */

#ifndef _BPF_SYSCALL_TYPE_H_
#define _BPF_SYSCALL_TYPE_H_

#include "kernel/include/syscall_event_head.h"

// syscall参数最大长度
#define MAX_ARG_LEN 64
// 路径最大长度
#define MAX_PATH_LEN 256

struct process_event {
    // （kprobe wake_up_new_task），事件头 head 即新进程，因此不再携带
    // clone_flags（原用于区分 clone 创建线程/进程，现由 head 语义替代）。
    __s32
        exit_code;  ///< 进程退出码；正常退出为状态码，被信号终止为信号编号的负数
    __u8 derived_flags;  ///< 进程诞生事件的派生标志，见 HNG_PROCESS_DERIVED_*
    __s32 exit_signal;   ///< 终止信号号（task->exit_code & 0x7f）；正常退出为 0
    char old_comm[16];   ///< task_rename 的旧进程名
    char new_comm[16];   ///< task_rename 的新进程名
    char cgroup_path[256];  ///< cgroup_attach_task 的目标 cgroup 路径
    /// 被操作任务的 pid：改名对象或 cgroup 迁移的被迁移者
    __u32 target_pid;
};

struct exec_event {
    char invoked[MAX_PATH_LEN];    ///< 用户给出的原始路径（可相对、可裸名、可空）
    char image[MAX_PATH_LEN];      ///< 实际执行的镜像绝对路径
    char argv0[MAX_ARG_LEN];       ///< argv[0]（程序名或启动命令）
    char argv1[MAX_ARG_LEN];       ///< argv[1]（第一个参数；无参数时为空串）
    char argv2[MAX_ARG_LEN];       ///< argv[2]；参数不足时为空串
    char argv3[MAX_ARG_LEN];       ///< argv[3]；参数不足时为空串
    char ld_preload[MAX_ARG_LEN];  ///< LD_PRELOAD 的值（已去掉变量名前缀）
    char ld_library_path[MAX_ARG_LEN];  ///< LD_LIBRARY_PATH 的值（已去掉前缀）
    __u32 flags;                        ///< execveat 有效，AT_* 标志
    __u32 image_flags;                  ///< image 的解析状态位，见 enum path_flag
};

/// @brief 请求的凭据类别；数值与 proto credential_semantic_data.kind 一致
enum credential_kind {
    CREDENTIAL_UID   = 1,  ///< requested 是目标 UID 序列
    CREDENTIAL_GID   = 2,  ///< requested 是目标 GID 序列
    CREDENTIAL_CAPS  = 3,  ///< requested 无意义，看 cap_* 字段
    CREDENTIAL_PRCTL = 4,  ///< prctl 的安全相关 option，见 prctl_option
};

struct credential_event {
    __u32 kind;             ///< @see credential_kind
    __u32 requested_count;  ///< requested 的有效个数（0..3）
    __u32 requested[3];     ///< 请求的目标 UID/GID；capset 时为 0
    __u64 cap_effective;    ///< Effective Capability
    __u64 cap_permitted;    ///< Permitted Capability
    __u64 cap_inheritable;  ///< Inheritable Capability
    __u32 prctl_option;     ///< prctl 的 option；非 prctl 为 0
    __u64 arg2;             ///< prctl 的 arg2；非 prctl 为 0
    __u32 securebits;       ///< PR_SET_SECUREBITS 的新值；其余为 0
};

struct namespace_event {
    __u64 flags;    ///< unshare 的 CLONE_* 全量掩码；setns 为 0
    __u32 ns_mask;  ///< 涉及的 CLONE_NEW* 位：unshare 为掩码，setns 为单个类型
    __s32 fd;       ///< setns 的目标 fd；unshare 为 -1
    char source[MAX_PATH_LEN];  ///< mount 的源、pivot_root 的新根；无则空串
    char target[MAX_PATH_LEN];  ///< mount 的挂载点、umount2/chroot 的路径
    __u32 source_flags;         ///< source 的解析状态位，见 enum path_flag
    __u32 target_flags;         ///< target 的解析状态位，见 enum path_flag
    char fstype[32];            ///< mount 的文件系统类型；其余为空串
    __u64 mount_flags;          ///< mount 的 MS_*；umount2 的 MNT_*；其余为 0
};

/// @brief 路径字段的解析状态位
/// @details 与 proto 的 path_flags 同值，内核与用户态共用。
enum path_flag {
    PATH_TRUNCATED  = 1 << 0,  ///< 路径超出缓冲被截断
    PATH_UNRESOLVED = 1 << 1,  ///< 无法解析为绝对路径，承载的是原始串
};

struct file_event {
    char path1[MAX_PATH_LEN];  ///< 主路径（open 族唯一路径、rename/link 的源）
    char path2[MAX_PATH_LEN];  ///< 第二路径（rename 目标、link 的新名）；无则空串
    __u32 path1_flags;         ///< path1 的解析状态位，见 enum path_flag
    __u32 path2_flags;         ///< path2 的解析状态位，见 enum path_flag
    __s32 dirfd;               ///< path1 的基准目录；无 *at 语义时为 AT_FDCWD
    __s32 dirfd2;              ///< path2 的基准目录；无 path2 时为 AT_FDCWD
    __u32 flags;  ///< open/openat/openat2 的 O_* 标志；renameat2 的 RENAME_* 标志
    __u32 mode;   ///< creat()/open(O_CREAT) 创建权限；openat2 可扩展保存 mode
    __u32 at_flags;   ///< *at 族的 AT_* 标志
    __u64 resolve;    ///< openat2 的 open_how.resolve
    __s64 length;     ///< truncate 的目标长度
    __u32 dev;        ///< mknod 的设备号
    __u8 handle[16];  ///< 文件句柄前 16 字节（open_by_handle_at 族）
    __s32 fd;         ///< 以 fd 为参数的操作；无则 -1
};

struct memory_event {
    __u64 prot;               ///< PROT_* 权限（mmap/mprotect）
    __u64 flags;              ///< MAP_* 标志（mmap）或保留扩展
    __u64 addr;               ///< 请求地址；实际地址在事件的 ret
    __u64 length;             ///< 映射/保护的字节数
    __u64 offset;             ///< mmap 的文件区段起点；mprotect 为 0
    __s32 fd;                 ///< mmap 的文件 fd；匿名映射与 mprotect 为 -1
    __u8 anonymous;           ///< MAP_ANONYMOUS：匿名内存
    __u8 wx;                  ///< prot 同时含 PROT_WRITE 与 PROT_EXEC
    char path[MAX_PATH_LEN];  ///< mmap 的源文件绝对路径；匿名时为空
    __u32 path_flags;         ///< path 的解析状态位，见 enum path_flag
};

struct network_event {
    __u32 family;         ///< AF_INET / AF_INET6 / AF_UNIX 等地址族
    __u32 type;           ///< SOCK_STREAM / SOCK_DGRAM 等
    __u32 protocol;       ///< IPPROTO_TCP 等协议号
    __u32 dst_ip[4];      ///< 目标 IP（网络字节序）：IPv4 用 [0]，IPv6 用 [0..3]
    __u32 src_ip[4];      ///< 来源 IP（网络字节序）：recvfrom 的源地址
    __u16 dst_port;       ///< 目标端口（主机字节序）
    __u16 src_port;       ///< 源端口（主机字节序）；connect 的 enter 阶段可能为 0
    __s32 sockfd;         ///< 涉及套接字的 fd；socket 事件为 -1（新 fd 在 ret）
    __u64 count;          ///< sendto/sendmsg/recvfrom 的字节数；其余为 0
    __s32 backlog;        ///< listen 的积压队列长度；其余为 0
    __u32 flags;          ///< accept4 的 SOCK_NONBLOCK/SOCK_CLOEXEC；其余为 0
    char unix_path[108];  ///< AF_UNIX 的 sun_path；抽象命名空间以 '@' 开头
};

struct kernel_event {
    __u32 command;      ///< ptrace 请求类型（PTRACE_*）或 bpf 命令（BPF_*）
    __u32 target_pid;   ///< ptrace 的 pid 参数；bpf 为 0
    __u64 arg;          ///< ptrace 的数据参数（POKETEXT 的 data）；bpf 为属性大小
    __u32 bpf_attr[4];  ///< bpf：union bpf_attr 的前 16 字节
    __u32 bpf_type;     ///< bpf：按 cmd 解出的类型；解不出为 0
    char module_name[64];  ///< 模块名（delete_module 与 module_load/free）
    __u32 module_len;      ///< init_module 的镜像长度
    __u64 kexec_entry;     ///< kexec_load 的入口地址
    __u32 kexec_segments;  ///< kexec_load 的段数
    __u32 reboot_cmd;      ///< reboot 的命令（LINUX_REBOOT_CMD_*）
    char hostname[64];     ///< sethostname 的新主机名
};

struct signal_event {
    __u32 sig;         ///< 信号号
    __u32 target_pid;  ///< kill 的 pid、tgkill 的 tgid、tkill 的 tid
    __u32 target_tid;  ///< tgkill 的 tid；其余为 0
    __s32 si_code;     ///< rt_sigqueueinfo 的 si_code；其余为 0
};

/**
 * @brief 通用 syscall 事件结构
 * @details 通过 union 统一九种事件类型，hdr 位于结构体开头。
 */
struct syscall_event {
    struct syscall_event_head hdr;
    union {
        struct process_event process_event;
        struct exec_event exec_event;
        struct credential_event credential_event;
        struct namespace_event namespace_event;
        struct file_event file_event;
        struct memory_event memory_event;
        struct network_event network_event;
        struct kernel_event kernel_event;
        struct signal_event signal_event;
    };
};

#endif  //_BPF_SYSCALL_TYPE_H_