/**
 * @file file_event.hpp
 * @brief 文件语义事件的输出结构定义
 * @details
 * 头部（file_event_head）为手写 POD 结构，复用内核态通用事件头并追加进程名；
 * 载荷（hng::file_event_data）由 proto 生成，两者组合为 file_semantic_data，
 * 即语义化模块推向下游（控制平面 / 检测）队列的元素类型。
 *
 * @author red_shinku
 * @date 2026.08.14
 */

#ifndef FILE_EVENT_HPP
#define FILE_EVENT_HPP

#include "file_event.pb.h"
#include <cstdint>

namespace hng {

// 文件语义事件头部：进程身份 + 发起进程名
struct file_event_head {
    uint32_t pid;
    uint64_t pid_start_time;
    uint32_t ppid;
    uint64_t ppid_start_time;
    char comm[16];  ///< 发起文件访问的进程名
};

// 文件语义事件：手写头部 + proto 生成的载荷
struct file_semantic_data {
    struct file_event_head head;  ///< 头部
    hng::file_event_data data;    ///< 载荷（语义化结果）
};

}  // namespace hng

#endif  // FILE_EVENT_HPP
