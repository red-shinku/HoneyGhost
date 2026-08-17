#ifndef SYSCALL_EVENT_HPP
#define SYSCALL_EVENT_HPP

/**
 * @file syscall_event.hpp
 * @brief 系统调用语义事件的输出结构定义
 * @details
 * 头部（syscall_semantic_head）为手写 POD 结构，记录进程身份上下文；
 * 载荷（hng::process_semantic_data 等八个消息）由 proto 生成，两者组合为
 * syscall_semantic_data，即语义化模块推向下游（控制平面 / 检测）队列的元素类型。
 *
 * 载荷与内核侧原始结构（kernel/include/syscalls_type.h）内容相似但不复用，
 * 全部重新定义，不组合任何 eBPF 侧数据结构。
 *
 * @author red_shinku
 * @date 2026.08.16
 */

#include "syscall_event.pb.h"
#include <cstdint>
#include <variant>

namespace hng {

// 系统调用语义事件头部：进程身份上下文
struct syscall_semantic_head {
    uint32_t pid;
    uint64_t pid_start_time;
    uint32_t ppid;
    uint64_t ppid_start_time;
};

// 系统调用语义事件：手写头部 + proto 生成的载荷
// 八种事件互斥，variant 的索引即事件类别（对应 syscall_event_type 枚举）
struct syscall_semantic_data {
    syscall_semantic_head head;

    std::variant<hng::process_semantic_data,
        hng::exec_semantic_data,
        hng::credential_semantic_data,
        hng::namespace_semantic_data,
        hng::file_syscall_semantic_data,
        hng::memory_semantic_data,
        hng::network_syscall_semantic_data,
        hng::kernel_semantic_data>
        data;
};

}  // namespace hng

#endif  // SYSCALL_EVENT_HPP
