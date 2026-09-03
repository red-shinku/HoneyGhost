#ifndef _USER_MODE_EVENT_HEAD_HPP_
#define _USER_MODE_EVENT_HEAD_HPP_

#include <cstdint>
#include "agent/event_data/event_type.hpp"

namespace hng {

/**
 * @brief 通用事件头（各语义事件共用的手写头部）
 * @details 前四项为进程身份（pid/ppid 各自配 start_time，作为进程唯一性 Process
 * 的判定依据）；末项 type 为顶层事件大类（hng::EventType），标记事件所属采集流。
 */
struct event_head {
    uint32_t pid;
    uint64_t pid_start_time;
    uint32_t ppid;
    uint64_t ppid_start_time;

    EventType type;  ///< 顶层事件大类
};

}  // namespace hng

#endif  //_USER_MODE_EVENT_HEAD_HPP_