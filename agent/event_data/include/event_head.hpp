#ifndef _USER_MODE_EVENT_HEAD_HPP_
#define _USER_MODE_EVENT_HEAD_HPP_

#include <cstdint>
#include <string>
#include "agent/event_data/include/event_type.hpp"
#include "kernel/include/syscall_event_head.h"

namespace hng {

/**
 * @brief 通用事件头（各语义事件共用的手写头部）
 * @details 前四项为进程身份（pid/ppid 各自配 start_time，作为进程唯一性 Process
 * 的判定依据）；subtype 为语义子类型，取自内核侧 syscall_event_type，0
 * 表示未归类。
 */
struct event_head {
    uint32_t pid;
    uint64_t pid_start_time;
    uint32_t ppid;
    uint64_t ppid_start_time;

    uint32_t uid;      ///< 真实 UID
    uint32_t euid;     ///< 有效 UID
    uint32_t mnt_ns;   ///< 挂载命名空间 inode
    int64_t ret;       ///< 系统调用返回值；本阶段恒 0
    std::string comm;  ///< 事件主体进程名

    EventType type;  ///< 事件来源
    /// 语义子类型；默认 UNKNOWN_EVENT，避免默认构造后取到不定值
    enum syscall_event_type subtype = UNKNOWN_EVENT;
};

}  // namespace hng

#endif  //_USER_MODE_EVENT_HEAD_HPP_