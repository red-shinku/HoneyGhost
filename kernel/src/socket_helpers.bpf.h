#ifndef HNG_SOCKET_HELPERS_BPF_H_
#define HNG_SOCKET_HELPERS_BPF_H_

#include "kernel/include/path_resolver.bpf.h"
#include "kernel/include/syscall_event_type.h"
#include "kernel/include/uapi_const.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

/// @brief sendmsg 累加分散缓冲区长度的项数上限；超出部分不计入
#define HNG_MAX_IOV 8

/**
 * @brief 把 AF_UNIX 的 sun_path 写入 unix_path
 * @param[out] dst 目标缓冲
 * @param[in] sz 容量
 * @param[in] addr 用户态 sockaddr
 * @param[in] addrlen sockaddr 长度；不足 sa_family 加一个字节时跳过
 * @note 抽象命名空间（sun_path[0] 为 NUL）以 '@' 前缀呈现其余字节，其余情形
 *       原样拷贝到首个 NUL；读不到时留空串。
 * @note sun_path 在 struct sockaddr 内偏移 2（sa_family_t 之后）。
 */
static __always_inline void copy_unix_path(char *dst, __u32 sz, const void *addr,
                                           u32 addrlen)
{
    //! @note 至少要能放下 '@' 与 NUL，否则下面按 sz 计算的边界会下溢
    if (!dst || sz < 3) {
        return;
    }
    dst[0] = '\0';
    if (!addr || addrlen < 3) {
        return;
    }

    char first = 0;
    if (bpf_probe_read_user(&first, 1, (const char *)addr + 2)) {
        return;
    }
    if (first == '\0') {
        /**
         * @note 抽象命名空间的名字从 sun_path[1] 起、由 addrlen 定长给出且不以
         *       NUL 结尾：按字节数拷贝，避免把名字之后的残留字节读进事件。
         */
        dst[0]         = '@';
        __u32 name_len = addrlen - 3;
        if (name_len > sz - 2) {
            name_len = sz - 2;
        }
        if (name_len == 0 ||
            bpf_probe_read_user(dst + 1, name_len, (const char *)addr + 3)) {
            dst[1] = '\0';
            return;
        }
        dst[name_len + 1] = '\0';
        return;
    }
    if (bpf_probe_read_user_str(dst, sz, (const char *)addr + 2) < 0) {
        dst[0] = '\0';
    }
}

/**
 * @brief 解析用户态 sockaddr 地址，提取地址族、IP 与端口
 * @param[in] addr 用户态 sockaddr 指针，允许为 NULL
 * @param[in] addrlen sockaddr 长度
 * @param[out] ip_out 目标 IP（网络字节序）：IPv4 用 [0]，IPv6 用 [0..3]
 * @param[out] port_out 目标端口（主机字节序）
 * @param[out] family_out 地址族
 * @param[out] unix_out AF_UNIX 的 sun_path，见 @ref copy_unix_path
 * @param[in] unix_sz unix_out 的容量
 * @return 解析成功且地址族为 IPv4 / IPv6 时返回 true，否则返回 false。
 * @note 仅在返回 true 时使用 ip_out/port_out/family_out；地址族非 INET/INET6、
 *       长度不足或读取失败均返回 false。
 * @note unix_out 与返回值无关：AF_UNIX 时即使返回 false 也已经写出，供呈现层
 *       按 sun_path 呈现目标；其余地址族保持空串。
 */
static __always_inline bool parse_sockaddr(const void *addr, u32 addrlen,
                                           u32 ip_out[4], u16 *port_out,
                                           u32 *family_out, char *unix_out,
                                           __u32 unix_sz)
{
    if (!addr) {
        return false;
    }

    struct sockaddr sa;
    if (bpf_probe_read_user(&sa, sizeof(sa), addr)) {
        return false;
    }
    //! @note 地址族先写出：AF_UNIX 不解析 IP，但调用方仍要知道目标是 UNIX 域
    *family_out = sa.sa_family;

    if (sa.sa_family == AF_UNIX) {
        //! @note 目标的不是 IP 地址：只记录 sun_path，由调用方按地址族处理
        copy_unix_path(unix_out, unix_sz, addr, addrlen);
        return false;
    }
    else if (sa.sa_family == AF_INET) {
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
 * @brief 用户态 struct msghdr 的头部（UAPI 布局）
 * @note vmlinux.h 的 struct msghdr 是内核布局（msg_iov 由 msg_iter 取代），不能
 *       用来读用户态入参；此处只列到 msg_iovlen，x86_64 下 msg_iov 在偏移 16。
 */
struct hng_user_msghdr {
    void *msg_name;         ///< 目标地址；可为 NULL
    __u32 msg_namelen;      ///< 目标地址长度
    __u32 __pad;            ///< 对齐填充，与 UAPI 结构一致
    struct iovec *msg_iov;  ///< 分散缓冲区数组
    __u64 msg_iovlen;       ///< 数组元素个数（用户给出，不可信）
};

/**
 * @brief 累加分散缓冲区的长度，得到 sendmsg 的字节数
 * @param[in] iov 用户态 iovec 数组
 * @param[in] count 元素个数；超出 HNG_MAX_IOV 的部分不计入
 * @return 前 HNG_MAX_IOV 项 iov_len 之和；读取失败处停止累加
 * @note 只读每个 iovec 的 iov_len，不读它指向的数据。
 */
static __always_inline __u64 sum_iov_len(const struct iovec *iov, __u64 count)
{
    __u64 total = 0;
#ifdef __clang__
#pragma clang loop unroll(full)
#endif
    for (int i = 0; i < HNG_MAX_IOV; ++i) {
        if (!iov || (__u64)i >= count) {
            break;
        }
        struct iovec entry = {};
        if (bpf_probe_read_user(&entry, sizeof(entry), &iov[i])) {
            break;
        }
        total += entry.iov_len;
    }
    return total;
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
#endif
