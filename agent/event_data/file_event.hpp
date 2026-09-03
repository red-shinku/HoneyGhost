/**
 * @file file_event.hpp
 * @brief 文件语义事件的输出结构定义
 * @details
 * 头部（hng::event_head）为手写通用 POD 结构，记录进程身份与顶层事件大类
 * （hng::EventType）；进程名 comm 与文件访问属性同属载荷（hng::file_event_data，
 * 由 proto 生成）。两者组合为
 * file_semantic_data，
 * 即语义化模块推向下游（控制平面 / 检测）队列的元素类型。
 *
 * @author red_shinku
 * @date 2026.08.14
 */

#ifndef FILE_EVENT_HPP
#define FILE_EVENT_HPP

#include "event_head.hpp"
#include "file_event.pb.h"

namespace hng {

// 文件语义事件：手写头部 + proto 生成的载荷
struct file_semantic_data {
    hng::event_head head;       ///< 头部
    hng::file_event_data data;  ///< 载荷（语义化结果）
};

}  // namespace hng

#endif  // FILE_EVENT_HPP
