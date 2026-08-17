/**
 * @file networks.bpf.c
 * @brief 从tracepoint收集网络连接数据
 * @details
 *
 * 仅收集特定角色的出站连接的数据，即 TCP connect、UDP sendto / sendmsg。
 * 在内核态程序区分一个出站连接是否属于特定角色的方法是：通过 eBPF map，查询当前 PID
 * 是否属于特定角色。具体归属由用户态负责。
 * 入站流量（服务端接收）由对端随机发起、高度分散，无法形成稳定的语义与基线，不收集。
 *
 * 全部使用 sys_enter tracepoint，sys_exit 事件在新版内核中不携带系统调用参数。
 * 所以由于 connect 的本地源端口（作为客户端的临时端口）在进入系统调用时尚未分配，src_port 可能为 0，
 * 但这并不影响语义。
 *
 * 这个模块不考虑系统层和云原生语义层的网络连接的区分，直接从相关系统调用中获取数据并上交。
 * 考虑云环境网络访问的影响。例如，通常随着 Pod 的重新调度，访问该 Pod 的物理 IP 也会变化，
 * 这时候这些 IP 都不具备稳定特征可供学习，无法成为基线。
 * 这些问题，包括eBPF难以捕捉到的其他云语义网络信息，都在用户态解决。
 *
 * @author red_shinku
 * @date 2026.08.07
 */

#include "../include/vmlinux.h"
#include "../include/networks_type.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// vmlinux.h 只提供类型定义，不提供宏常量，此处自行定义
#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif

/**
 * @brief RingBuf，存储网络事件的数据
 *       用户态程序通过该结构获取事件数据
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} network_events SEC(".maps");

/**
 * @brief 网络事件数据结构的初始化函数
 * @return NULL 初始化失败
 * @return struct network_data* 初始化成功，返回指针
 */
static __always_inline struct network_data *init_network_data(void)
{
    struct network_data *data = bpf_ringbuf_reserve(&network_events, sizeof(struct network_data), 0);
    if (!data) {
        return NULL;
    }
    init_event_head(&data->head);
    data->family = 0;
    __builtin_memset(data->dst_ip, 0, sizeof(data->dst_ip));
    data->src_port = 0;
    data->dst_port = 0;
    data->protocol = 0;

    return data;
}

/**
 * @brief 解析用户态 sockaddr 地址，提取地址族、IP 与端口
 * @param addr       用户态 sockaddr 指针
 * @param addrlen    sockaddr 长度
 * @param ip_out     输出的 IP 地址（IPv4 使用 [0]，IPv6 使用 [0..3]）
 * @param port_out   输出的端口（主机字节序）
 * @param family_out 输出的地址族
 * @return true 解析成功且为 IPv4 / IPv6 地址族
 */
static __always_inline bool parse_sockaddr(const void *addr, u32 addrlen, u32 ip_out[4], u16 *port_out, u32 *family_out)
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
 * @details 从 task_struct 的文件描述符表逐层读取（CO-RE），返回 fd 对应的
 *          struct sock *，任一环节读取失败均返回 NULL。
 * @param fd 文件描述符
 * @return struct sock* 套接字指针，失败返回 NULL
 */
static __always_inline struct sock *get_socket_sk(u32 fd)
{
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

    u32 max_fds = BPF_CORE_READ(fdt, max_fds);
    if (fd >= max_fds) {
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
 * @param sk   套接字指针，允许为 NULL
 * @param data 网络事件数据
 */
static __always_inline void fill_local_info(struct sock *sk, struct network_data *data)
{
    if (!sk) {
        return;
    }
    data->src_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    data->protocol = BPF_CORE_READ(sk, sk_protocol);
}

// ============================================================================
// 出站流量：全部拦截
// ============================================================================

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_network_connect(struct trace_event_raw_sys_enter *ctx)
{
    struct network_data *data = init_network_data();
    if (!data) return 0;

    // args[0]: sockfd, args[1]: 目标 sockaddr, args[2]: addrlen
    if (!parse_sockaddr((const void *)ctx->args[1], (u32)ctx->args[2], data->dst_ip, &data->dst_port, &data->family)) {
        bpf_ringbuf_discard(data, BPF_RB_NO_WAKEUP);
        return 0;
    }

    // 源端口为本地临时端口，sys_enter 阶段可能尚未分配，为 0
    fill_local_info(get_socket_sk((u32)ctx->args[0]), data);

    bpf_ringbuf_submit(data, BPF_RB_NO_WAKEUP);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int trace_network_sendto(struct trace_event_raw_sys_enter *ctx)
{
    struct network_data *data = init_network_data();
    if (!data) return 0;

    // args[0]: sockfd, args[4]: 目标 sockaddr, args[5]: addrlen
    if (!parse_sockaddr((const void *)ctx->args[4], (u32)ctx->args[5], data->dst_ip, &data->dst_port, &data->family)) {
        bpf_ringbuf_discard(data, BPF_RB_NO_WAKEUP);
        return 0;
    }

    fill_local_info(get_socket_sk((u32)ctx->args[0]), data);

    bpf_ringbuf_submit(data, BPF_RB_NO_WAKEUP);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendmsg")
int trace_network_sendmsg(struct trace_event_raw_sys_enter *ctx)
{
    struct network_data *data = init_network_data();
    if (!data) return 0;

    // args[0]: sockfd, args[1]: struct msghdr*, args[2]: flags
    const void *dest_addr = NULL;
    u32 addrlen           = 0;
    struct msghdr msg;
    if (bpf_probe_read_user(&msg, sizeof(msg), (void *)ctx->args[1]) == 0) {
        dest_addr = msg.msg_name;
        addrlen   = (u32)msg.msg_namelen;
    }

    // 已 connect 的套接字可传 NULL 的 msg_name，此时跳过（连接信息已由 connect 事件记录）
    if (!parse_sockaddr(dest_addr, addrlen, data->dst_ip, &data->dst_port, &data->family)) {
        bpf_ringbuf_discard(data, BPF_RB_NO_WAKEUP);
        return 0;
    }

    fill_local_info(get_socket_sk((u32)ctx->args[0]), data);

    bpf_ringbuf_submit(data, BPF_RB_NO_WAKEUP);
    return 0;
}
