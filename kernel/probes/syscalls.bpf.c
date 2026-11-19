/**
 * @file syscalls.bpf.c
 * @brief 监控关键系统调用
 * @details 收集带语义的系统调用信息。
 *
 * 被采集的系统调用采用 enter 暂存、exit 提交：enter 探针把组装好的事件写入
 * hng_pending，对应 exit 探针取回、补上返回值后提交 ringbuf。事件因此按完成序
 * 下发，头里的 ret 是真实返回值。
 *
 * 这个模块收集的数据将用于马尔科夫序列的基线学习，或
 * 结合序列基线进行异常分析。因此获取的信息应当具有语义、能反映行为特征。
 *
 * @author red_shinku
 * @date 2026.08.06
 */

#include "kernel/include/vmlinux.h"
#include "kernel/include/path_resolver.bpf.h"
#include "kernel/include/role_filter.bpf.h"
#include "kernel/include/syscall_event_type.h"
#include "kernel/include/uapi_const.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
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
 * @brief ringbuf 预留失败计数；每 CPU 一个 u64，用户态按 CPU 求和
 * @note 失败包括 ringbuf 满与 NMI 上下文拿不到锁，故名为 reserve_failures
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} reserve_failures SEC(".maps");

/// @brief 记录一次 ringbuf 预留失败；只在失败分支调用
static __always_inline void count_reserve_failure(void)
{
    __u32 key   = 0;
    __u64 *lost = bpf_map_lookup_elem(&reserve_failures, &key);
    if (lost) {
        __sync_fetch_and_add(lost, 1);
    }
}

/**
 * @brief enter 侧暂存表：key 为 pid_tgid，value 为已组装的完整事件
 * @details enter 探针末尾写入，对应系统调用的 exit 探针取回后补上返回值再提交。
 * @note 用普通 LRU hash 而非 LRU_PERCPU_HASH：后者的 key 也是全局的，value 按 CPU
 *       分槽，enter 写入的值只有同一 CPU 上的 exit 才读得到，而任务在系统调用中
 *       可被迁移到其它 CPU；配对必须跨 CPU 成立。
 * @note 2048 条只为容纳「enter 后任务未走到 exit」的滞留条目，写满由 LRU 淘汰。
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 2048);
    __type(key, __u64);
    __type(value, struct syscall_event);
} hng_pending SEC(".maps");

/**
 * @brief enter 侧组装事件用的 per-CPU 槽
 * @note 只在一次探针内使用：同一探针内组装完成即写入 hng_pending，不跨探针持有。
 *       事件尺寸超过 eBPF 的 512B 栈上限，故不放栈上。
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct syscall_event);
} hng_scratch SEC(".maps");

/**
 * @brief exit 时暂存条目缺失的计数；每 CPU 一个 u64，用户态按 CPU 求和
 * @note 只计入「enter 本应暂存却查不到」，即 LRU 淘汰或异常；角色过滤造成的
 *       不暂存、sendto/sendmsg 目标不可解析造成的主动不暂存都不计入。
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} pending_lost SEC(".maps");

/// @brief 记录一次暂存条目丢失；只在 exit 侧判定为丢失时调用
static __always_inline void count_pending_lost(void)
{
    __u32 key   = 0;
    __u64 *lost = bpf_map_lookup_elem(&pending_lost, &key);
    if (lost) {
        __sync_fetch_and_add(lost, 1);
    }
}

/// @brief 取本 CPU 的事件暂存槽；取不到返回 NULL
static __always_inline struct syscall_event *hng_scratch_event(void)
{
    __u32 key = 0;
    return bpf_map_lookup_elem(&hng_scratch, &key);
}

/**
 * @name 各事件类型的初始化函数，取本 CPU 的暂存槽并初始化事件头。
 * 事件在本 CPU 槽内组装，enter 探针末尾写入暂存表，由对应 exit 探针提交。
 * 生命周期事件不经配对，仍预留 ringbuf 后直接提交（见 init_process_event）。
 * @{
 */

/**
 * @brief 初始化进程生命周期事件，并预留 ringbuf 事件空间。
 * @param[in] name 系统调用事件名。
 * @return 成功时返回事件指针；空间不足时返回 NULL。
 * @note 生命周期事件不经 enter/exit 配对，调用者直接提交或丢弃。
 * @note 生命周期事件绕过角色过滤，以维护完整进程树。
 * @note 只预留头与 process_event 的定长记录；返回指针便于调用者填头与
 *       process_event，记录中不含 union 的其余载荷。
 */
static __always_inline struct syscall_event *init_process_event(
    enum syscall_event_name name)
{
    struct syscall_event *event = bpf_ringbuf_reserve(
        &syscall_events,
        sizeof(struct syscall_event_head) + sizeof(struct process_event), 0);
    if (!event) {
        count_reserve_failure();
        return NULL;
    }
    init_syscall_event_head(&event->hdr, name);
    event->process_event.exit_code = 0;
    return event;
}

/**
 * @brief 初始化 exec_event，并取本 CPU 的事件暂存槽。
 * @param[in] name 系统调用事件名。
 * @return 成功时返回暂存槽内的事件指针；槽不可用时返回 NULL。
 * @note 事件在本 CPU 槽内组装，enter 探针末尾写入暂存表，由对应 exit 探针提交。
 */
static __always_inline struct syscall_event *init_exec_event(
    enum syscall_event_name name)
{
    struct syscall_event *event = hng_scratch_event();
    if (!event) return NULL;
    init_syscall_event_head(&event->hdr, name);
    __builtin_memset(event->exec_event.filename, 0,
                     sizeof(event->exec_event.filename));
    __builtin_memset(event->exec_event.argv0, 0, sizeof(event->exec_event.argv0));
    __builtin_memset(event->exec_event.argv1, 0, sizeof(event->exec_event.argv1));
    event->exec_event.flags = 0;
    return event;
}

/**
 * @brief 初始化 credential_event，并取本 CPU 的事件暂存槽。
 * @param[in] name 系统调用事件名。
 * @return 角色被过滤或槽不可用时返回 NULL，否则返回暂存槽内的事件指针。
 * @note 事件在本 CPU 槽内组装，enter 探针末尾写入暂存表，由对应 exit 探针提交。
 * @note 先检查角色白名单，通过后才占用事件槽。
 */
static __always_inline struct syscall_event *init_credential_event(
    enum syscall_event_name name)
{
    if (!hng_should_collect()) return NULL;
    struct syscall_event *event = hng_scratch_event();
    if (!event) return NULL;
    init_syscall_event_head(&event->hdr, name);
    //! @note 联合体整体清零（capset 为最大成员，覆盖整个 union）
    event->credential_event.capset.effective   = 0;
    event->credential_event.capset.permitted   = 0;
    event->credential_event.capset.inheritable = 0;
    return event;
}

/**
 * @brief 初始化 namespace_event，并取本 CPU 的事件暂存槽。
 * @param[in] name 系统调用事件名。
 * @return 角色被过滤或槽不可用时返回 NULL，否则返回暂存槽内的事件指针。
 * @note 事件在本 CPU 槽内组装，enter 探针末尾写入暂存表，由对应 exit 探针提交。
 * @note 先检查角色白名单，通过后才占用事件槽。
 */
static __always_inline struct syscall_event *init_namespace_event(
    enum syscall_event_name name)
{
    if (!hng_should_collect()) return NULL;
    struct syscall_event *event = hng_scratch_event();
    if (!event) return NULL;
    init_syscall_event_head(&event->hdr, name);
    event->namespace_event.ns_type = 0;
    event->namespace_event.flags   = 0;
    return event;
}

/**
 * @brief 初始化 file_event，并取本 CPU 的事件暂存槽。
 * @param[in] name 系统调用事件名。
 * @return 角色被过滤或槽不可用时返回 NULL，否则返回暂存槽内的事件指针。
 * @note 事件在本 CPU 槽内组装，enter 探针末尾写入暂存表，由对应 exit 探针提交。
 * @note 先检查角色白名单，通过后才占用事件槽。
 */
static __always_inline struct syscall_event *init_file_event(
    enum syscall_event_name name)
{
    if (!hng_should_collect()) return NULL;
    struct syscall_event *event = hng_scratch_event();
    if (!event) return NULL;
    init_syscall_event_head(&event->hdr, name);
    __builtin_memset(event->file_event.path, 0, sizeof(event->file_event.path));
    event->file_event.flags      = 0;
    event->file_event.mode       = 0;
    event->file_event.path_flags = 0;
    return event;
}

/**
 * @brief 初始化 memory_event，并取本 CPU 的事件暂存槽。
 * @param[in] name 系统调用事件名。
 * @return 角色被过滤或槽不可用时返回 NULL，否则返回暂存槽内的事件指针。
 * @note 事件在本 CPU 槽内组装，enter 探针末尾写入暂存表，由对应 exit 探针提交。
 * @note 先检查角色白名单，通过后才占用事件槽。
 */
static __always_inline struct syscall_event *init_memory_event(
    enum syscall_event_name name)
{
    if (!hng_should_collect()) return NULL;
    struct syscall_event *event = hng_scratch_event();
    if (!event) return NULL;
    init_syscall_event_head(&event->hdr, name);
    event->memory_event.prot  = 0;
    event->memory_event.flags = 0;
    return event;
}

/**
 * @brief 初始化 network_event，并取本 CPU 的事件暂存槽。
 * @param[in] name 系统调用事件名。
 * @return 角色被过滤或槽不可用时返回 NULL，否则返回暂存槽内的事件指针。
 * @note 事件在本 CPU 槽内组装，enter 探针末尾写入暂存表，由对应 exit 探针提交。
 * @note 先检查角色白名单，通过后才占用事件槽。
 */
static __always_inline struct syscall_event *init_network_event(
    enum syscall_event_name name)
{
    if (!hng_should_collect()) return NULL;
    struct syscall_event *event = hng_scratch_event();
    if (!event) return NULL;
    init_syscall_event_head(&event->hdr, name);
    event->network_event.family   = 0;
    event->network_event.type     = 0;
    event->network_event.protocol = 0;
    __builtin_memset(event->network_event.dst_ip, 0,
                     sizeof(event->network_event.dst_ip));
    event->network_event.dst_port = 0;
    event->network_event.src_port = 0;
    return event;
}

/**
 * @brief 初始化 kernel_event，并取本 CPU 的事件暂存槽。
 * @param[in] name 系统调用事件名。
 * @return 角色被过滤或槽不可用时返回 NULL，否则返回暂存槽内的事件指针。
 * @note 事件在本 CPU 槽内组装，enter 探针末尾写入暂存表，由对应 exit 探针提交。
 * @note 先检查角色白名单，通过后才占用事件槽。
 */
static __always_inline struct syscall_event *init_kernel_event(
    enum syscall_event_name name)
{
    if (!hng_should_collect()) return NULL;
    struct syscall_event *event = hng_scratch_event();
    if (!event) return NULL;
    init_syscall_event_head(&event->hdr, name);
    event->kernel_event.command = 0;
    event->kernel_event.arg     = 0;
    return event;
}

/**
 * @name enter/exit 配对
 * @details
 * 每个被采集的系统调用都有 enter 与 exit 两个探针：enter 把事件组装进本 CPU 槽后
 * 写入 hng_pending；exit 取回同一线程的条目，按完成时刻重填事件头、补上返回值，
 * 再提交 ringbuf。由此：
 * - 事件按**完成序**下发，hdr.head.ret 是系统调用的真实返回值；
 * - 同一线程的系统调用不会重叠，故 pid_tgid 足以标识一次未完成的事件；
 * - 被信号打断后重启的系统调用各有一次 enter/exit，即产生两条事件；
 * - exec 成功的 exit 已换镜像，头里的 uid/euid/comm 即新镜像的值；
 * - enter 后任务被 kill（没有 exit）的条目滞留，由 hng_pending 的 LRU 淘汰兜底。
 * @{
 */

/**
 * @brief 把 enter 组装好的事件写入当前线程的暂存条目。
 * @param[in] event 本 CPU 暂存槽内的事件；为空时不做任何事。
 * @note 覆盖同键旧条目：同一线程不会有两个未完成的被采集系统调用。
 */
static __always_inline void hng_stash_pending(struct syscall_event *event)
{
    if (!event) return;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&hng_pending, &pid_tgid, event, BPF_ANY);
}

/**
 * @brief 复制 exec_event 载荷。
 * @note 大结构按字段复制：整体 __builtin_memcpy 可能退化成对 memcpy 的调用。
 */
static __always_inline void hng_copy_exec_event(struct exec_event *dst,
                                                const struct exec_event *src)
{
    __builtin_memcpy(dst->filename, src->filename, sizeof(dst->filename));
    __builtin_memcpy(dst->argv0, src->argv0, sizeof(dst->argv0));
    __builtin_memcpy(dst->argv1, src->argv1, sizeof(dst->argv1));
    dst->flags = src->flags;
}

/// @brief 复制 credential_event 载荷。
static __always_inline void hng_copy_credential_event(
    struct credential_event *dst, const struct credential_event *src)
{
    __builtin_memcpy(dst, src, sizeof(*dst));
}

/// @brief 复制 namespace_event 载荷。
static __always_inline void hng_copy_namespace_event(
    struct namespace_event *dst, const struct namespace_event *src)
{
    dst->ns_type = src->ns_type;
    dst->flags   = src->flags;
}

/// @brief 复制 file_event 载荷。
static __always_inline void hng_copy_file_event(struct file_event *dst,
                                                const struct file_event *src)
{
    __builtin_memcpy(dst->path, src->path, sizeof(dst->path));
    dst->flags      = src->flags;
    dst->mode       = src->mode;
    dst->path_flags = src->path_flags;
}

/// @brief 复制 memory_event 载荷。
static __always_inline void hng_copy_memory_event(struct memory_event *dst,
                                                  const struct memory_event *src)
{
    dst->prot  = src->prot;
    dst->flags = src->flags;
}

/// @brief 复制 network_event 载荷。
static __always_inline void hng_copy_network_event(
    struct network_event *dst, const struct network_event *src)
{
    dst->family   = src->family;
    dst->type     = src->type;
    dst->protocol = src->protocol;
    __builtin_memcpy(dst->dst_ip, src->dst_ip, sizeof(dst->dst_ip));
    dst->dst_port = src->dst_port;
    dst->src_port = src->src_port;
}

/// @brief 复制 kernel_event 载荷。
static __always_inline void hng_copy_kernel_event(struct kernel_event *dst,
                                                  const struct kernel_event *src)
{
    dst->command = src->command;
    dst->arg     = src->arg;
}

/**
 * @brief 生成一个按 subtype 定长提交的 exit 侧函数。
 * @param[in] subtype_id 该分支处理的子类型，同时构成函数名后缀。
 * @param[in] payload 该子类型的载荷结构体名；记录长度 = 头 + 该结构体。
 * @details 预留长度是编译期常量，分支内只访问自己的载荷类型。不能用运行期
 *          变量当预留长度跨分支写：verifier 对变长 PTR_TO_MEM 的越界判定会
 *          变保守，且分支与长度不匹配时是运行期越界。记录头里的 subtype 取
 *          本分支的参数，保证长度前缀与载荷布局一致。
 * @note 暂存条目的名字与 name 不符时按残留条目丢弃，不提交；ringbuf 预留
 *       失败时删除条目并计入 reserve_failures，避免污染下一次 exit。
 */
#define HNG_DEFINE_COMMIT(subtype_id, payload)                                \
    static __always_inline int hng_commit_##subtype_id(                       \
        __s64 ret, enum syscall_event_name name, int count_lost)              \
    {                                                                         \
        __u64 pid_tgid = bpf_get_current_pid_tgid();                          \
        const struct syscall_event *pending =                                 \
            bpf_map_lookup_elem(&hng_pending, &pid_tgid);                     \
        if (!pending) {                                                       \
            if (count_lost && hng_should_collect()) {                         \
                count_pending_lost();                                         \
            }                                                                 \
            return 0;                                                         \
        }                                                                     \
        if (pending->hdr.name != name) {                                      \
            bpf_map_delete_elem(&hng_pending, &pid_tgid);                     \
            if (count_lost && hng_should_collect()) {                         \
                count_pending_lost();                                         \
            }                                                                 \
            return 0;                                                         \
        }                                                                     \
        char *record = bpf_ringbuf_reserve(                                   \
            &syscall_events,                                                  \
            sizeof(struct syscall_event_head) + sizeof(struct payload), 0);   \
        if (!record) {                                                        \
            bpf_map_delete_elem(&hng_pending, &pid_tgid);                     \
            count_reserve_failure();                                          \
            return 0;                                                         \
        }                                                                     \
        struct syscall_event_head *hdr = (struct syscall_event_head *)record; \
        struct payload *dst =                                                 \
            (struct payload *)(record + sizeof(struct syscall_event_head));   \
        hng_copy_##payload(dst, &pending->payload);                           \
        init_syscall_event_head(hdr, name);                                   \
        hdr->subtype  = subtype_id;                                           \
        hdr->head.ret = ret;                                                  \
        bpf_map_delete_elem(&hng_pending, &pid_tgid);                         \
        bpf_ringbuf_submit(record, 0);                                        \
        return 0;                                                             \
    }

HNG_DEFINE_COMMIT(EXEC_EVENT, exec_event)
HNG_DEFINE_COMMIT(CREDENTIAL_EVENT, credential_event)
HNG_DEFINE_COMMIT(NAMESPACE_EVENT, namespace_event)
HNG_DEFINE_COMMIT(FILE_EVENT, file_event)
HNG_DEFINE_COMMIT(MEMORY_EVENT, memory_event)
HNG_DEFINE_COMMIT(NETWORK_EVENT, network_event)
HNG_DEFINE_COMMIT(KERNEL_EVENT, kernel_event)

/** @} */

/**
 * @brief 解析用户态 sockaddr 地址，提取地址族、IP 与端口
 * @param[in] addr 用户态 sockaddr 指针，允许为 NULL
 * @param[in] addrlen sockaddr 长度
 * @param[out] ip_out 目标 IP（网络字节序）：IPv4 用 [0]，IPv6 用 [0..3]
 * @param[out] port_out 目标端口（主机字节序）
 * @param[out] family_out 地址族
 * @return 解析成功且地址族为 IPv4 / IPv6 时返回 true，否则返回 false。
 * @note 仅在返回 true 时使用输出参数；地址族非 INET/INET6、长度不足或读取失败
 *       均返回 false。
 */
static __always_inline bool parse_sockaddr(const void *addr, u32 addrlen,
                                           u32 ip_out[4], u16 *port_out,
                                           u32 *family_out)
{
    if (!addr) {
        return false;
    }

    struct sockaddr sa;
    if (bpf_probe_read_user(&sa, sizeof(sa), addr)) {
        return false;
    }

    if (sa.sa_family == AF_INET) {
        if (addrlen < sizeof(struct sockaddr_in)) {
            return false;
        }
        struct sockaddr_in sin;
        if (bpf_probe_read_user(&sin, sizeof(sin), addr)) {
            return false;
        }
        *family_out = AF_INET;
        *port_out   = bpf_ntohs(sin.sin_port);
        ip_out[0]   = sin.sin_addr.s_addr;
        return true;
    }
    else if (sa.sa_family == AF_INET6) {
        if (addrlen < sizeof(struct sockaddr_in6)) {
            return false;
        }
        struct sockaddr_in6 sin6;
        if (bpf_probe_read_user(&sin6, sizeof(sin6), addr)) {
            return false;
        }
        *family_out = AF_INET6;
        *port_out   = bpf_ntohs(sin6.sin6_port);
        ip_out[0]   = sin6.sin6_addr.in6_u.u6_addr32[0];
        ip_out[1]   = sin6.sin6_addr.in6_u.u6_addr32[1];
        ip_out[2]   = sin6.sin6_addr.in6_u.u6_addr32[2];
        ip_out[3]   = sin6.sin6_addr.in6_u.u6_addr32[3];
        return true;
    }

    return false;
}

/**
 * @brief 通过当前进程的 fd 获取套接字指针
 * @details 复用 fd → struct file 的通用读取，再取 file 的 private_data 为
 *          struct sock *，任一环节读取失败均返回 NULL。
 * @param[in] fd 文件描述符
 * @return 内核持有的套接字指针，失败返回 NULL。
 * @note 返回值仅用于本次探针中的读取，不转移所有权。
 * @see hng_file_from_fd
 */
static __always_inline struct sock *get_socket_sk(u32 fd)
{
    struct file *file = hng_file_from_fd((int)fd);
    if (!file) {
        return NULL;
    }

    struct socket *socket = BPF_CORE_READ(file, private_data);
    if (!socket) {
        return NULL;
    }

    return BPF_CORE_READ(socket, sk);
}

/**
 * @brief 从套接字读取本地信息（源端口、协议号）并写入事件
 * @param[in] sk 套接字指针，允许为 NULL
 * @param[in,out] data 网络事件数据，仅更新本地端口与协议号
 */
static __always_inline void fill_local_info(struct sock *sk,
                                            struct network_event *data)
{
    if (!sk) {
        return;
    }
    data->src_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    data->protocol = BPF_CORE_READ(sk, sk_protocol);
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
    init_event_head_parent(&event->hdr.head,
                           BPF_CORE_READ(task, group_leader, real_parent));

    //! @note 低 7 位非零表示被信号终止，否则高位是退出状态码
    s32 code = BPF_CORE_READ(task, exit_code);
    if (code & 0x7f) {
        event->process_event.exit_code = -(code & 0x7f);
    }
    else {
        event->process_event.exit_code = code >> 8;
    }

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
    event->credential_event.setuid.uid = (u32)ctx->args[0];

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
    event->credential_event.setgid.gid = (u32)ctx->args[0];

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

    hng_stash_pending(event);
    return 0;
}

/** @} */

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

    event->namespace_event.ns_type = (u32)ctx->args[1];
    event->namespace_event.flags   = 0;

    hng_stash_pending(event);
    return 0;
}

/** @} */

/**
 * @name FILE_EVENT 类别的 syscall 拦截
 * @{
 */

/**
 * @brief 解析文件事件的路径并记录解析状态位。
 * @param[out] file 目标文件事件载荷，path 与 path_flags 由本函数填写
 * @param[in] user_path 用户态路径串
 * @param[in] dirfd 基准目录 fd；AT_FDCWD 表示当前工作目录
 * @note 返回 -1 置 PATH_UNRESOLVED、返回 -2 置 PATH_TRUNCATED，成功不置位。
 * @note path_flags 由 init_file_event 预先清零。
 * @see hng_resolve_user_path
 */
static __always_inline void hng_fill_file_path(struct file_event *file,
                                               const void *user_path, int dirfd)
{
    long written =
        hng_resolve_user_path(file->path, sizeof(file->path), user_path, dirfd);
    if (written == -1) {
        file->path_flags |= PATH_UNRESOLVED;
    }
    else if (written == -2) {
        file->path_flags |= PATH_TRUNCATED;
    }
}

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

    //! @note args[0]: const char *filename；open 没有 dirfd，基准为当前工作目录
    hng_fill_file_path(&event->file_event, (const void *)ctx->args[0], AT_FDCWD);
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
    hng_fill_file_path(&event->file_event, (const void *)ctx->args[1],
                       (int)ctx->args[0]);
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
    hng_fill_file_path(&event->file_event, (const void *)ctx->args[1],
                       (int)ctx->args[0]);
    //! @note args[2]: struct open_how *
    struct open_how how;
    if (bpf_probe_read_user(&how, sizeof(how), (void *)ctx->args[2]) == 0) {
        event->file_event.flags = (u32)how.flags;
        event->file_event.mode  = (u32)how.mode;
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

    //! @note args[0]: const char *filename；creat 没有 dirfd，基准为当前工作目录
    hng_fill_file_path(&event->file_event, (const void *)ctx->args[0], AT_FDCWD);
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

    event->file_event.flags = (u32)ctx->args[4];

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

    //! @note args[2]: int prot (PROT_*)
    event->memory_event.prot  = ctx->args[2];
    //! @note args[3]: int flags (MAP_*)
    event->memory_event.flags = ctx->args[3];

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

    //! @note args[2]: int prot (PROT_*)
    event->memory_event.prot = ctx->args[2];

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
    if (parse_sockaddr((const void *)ctx->args[1], (u32)ctx->args[2],
                       event->network_event.dst_ip,
                       &event->network_event.dst_port,
                       &event->network_event.family)) {
        fill_local_info(get_socket_sk((u32)ctx->args[0]), &event->network_event);
    }
    else {
        /**
         * @note 解析不出 IPv4/IPv6 时只填 sockaddr 中读到的地址族，
         * 目标地址与端口保持 0
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
 * @note 仅在目标 sockaddr 能解析为 IPv4/IPv6 时暂存；已 connect 的套接字通常
 *       不再携带目标地址，其连接信息由 connect 事件记录。
 */
SEC("tracepoint/syscalls/sys_enter_sendto")
int trace_sendto(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_network_event(SYSCALL_EVENT_SENDTO);
    if (!event) return 0;

    //! @note args[0]: sockfd, args[4]: 目标 sockaddr, args[5]: addrlen
    if (!parse_sockaddr((const void *)ctx->args[4], (u32)ctx->args[5],
                        event->network_event.dst_ip,
                        &event->network_event.dst_port,
                        &event->network_event.family)) {
        //! @note 未预留任何资源，也不写暂存表；exit 侧据此不计 pending_lost
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
 * @note 仅在 msg_name 能解析为 IPv4/IPv6 时暂存；已 connect 的套接字可传空的
 *       msg_name，此时连接信息已由 connect 事件记录，跳过本次暂存。
 */
SEC("tracepoint/syscalls/sys_enter_sendmsg")
int trace_sendmsg(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *event = init_network_event(SYSCALL_EVENT_SENDMSG);
    if (!event) return 0;

    //! @note args[0]: sockfd, args[1]: struct msghdr *, args[2]: flags
    const void *dest_addr = NULL;
    u32 addrlen           = 0;
    struct msghdr msg;
    if (bpf_probe_read_user(&msg, sizeof(msg), (void *)ctx->args[1]) == 0) {
        dest_addr = msg.msg_name;
        addrlen   = (u32)msg.msg_namelen;
    }

    if (!parse_sockaddr(dest_addr, addrlen, event->network_event.dst_ip,
                        &event->network_event.dst_port,
                        &event->network_event.family)) {
        //! @note 未预留任何资源，也不写暂存表；exit 侧据此不计 pending_lost
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

    //! @note args[1]: const struct sockaddr *addr
    struct sockaddr sa;
    if (bpf_probe_read_user(&sa, sizeof(sa), (void *)ctx->args[1]) == 0) {
        event->network_event.family = sa.sa_family;
    }

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

    //! @note args[0]: int request (PTRACE_*)
    event->kernel_event.command = (u32)ctx->args[0];
    //! @note args[1]: pid_t pid — 目标进程
    event->kernel_event.arg     = ctx->args[1];

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

    //! @note args[0]: int cmd (BPF_*)
    event->kernel_event.command = (u32)ctx->args[0];
    //! @note args[2]: unsigned int size — attr 大小（可用于推断 BPF 命令版本）
    event->kernel_event.arg     = ctx->args[2];

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

// NAMESPACE
HNG_DEFINE_EXIT_PROBE(unshare, SYSCALL_EVENT_UNSHARE, NAMESPACE_EVENT)
HNG_DEFINE_EXIT_PROBE(setns, SYSCALL_EVENT_SETNS, NAMESPACE_EVENT)

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

// MEMORY
HNG_DEFINE_EXIT_PROBE(mmap, SYSCALL_EVENT_MMAP, MEMORY_EVENT)
HNG_DEFINE_EXIT_PROBE(mprotect, SYSCALL_EVENT_MPROTECT, MEMORY_EVENT)

// NETWORK
HNG_DEFINE_EXIT_PROBE(connect, SYSCALL_EVENT_CONNECT, NETWORK_EVENT)
HNG_DEFINE_EXIT_PROBE_OPTIONAL(sendto, SYSCALL_EVENT_SENDTO, NETWORK_EVENT)
HNG_DEFINE_EXIT_PROBE_OPTIONAL(sendmsg, SYSCALL_EVENT_SENDMSG, NETWORK_EVENT)
HNG_DEFINE_EXIT_PROBE(socket, SYSCALL_EVENT_SOCKET, NETWORK_EVENT)
HNG_DEFINE_EXIT_PROBE(bind, SYSCALL_EVENT_BIND, NETWORK_EVENT)

// KERNEL
HNG_DEFINE_EXIT_PROBE(ptrace, SYSCALL_EVENT_PTRACE, KERNEL_EVENT)
HNG_DEFINE_EXIT_PROBE(bpf, SYSCALL_EVENT_BPF, KERNEL_EVENT)

/** @} */

char LICENSE[] SEC("license") = "GPL";
