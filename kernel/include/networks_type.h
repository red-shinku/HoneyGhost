#ifndef _BPF_NETWORK_TYPE_H_
#define _BPF_NETWORK_TYPE_H_

#include "kernel/include/event_head.h"

struct network_data {
    struct event_head head;

    __u32 family;     ///< AF_INET / AF_INET6地址族
    __u32 dst_ip[4];  ///< 目标IP地址，IPv4使用dst_ip[0]，IPv6使用dst_ip[0..3]
    __u16 src_port;   ///< 源端口
    __u16 dst_port;   ///< 目标端口
    __u32 protocol;   ///< 协议号
};

#endif  //_BPF_NETWORK_TYPE_H_