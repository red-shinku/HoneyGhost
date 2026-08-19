#ifndef _USER_MODE_EVENT_HEAD_HPP_
#define _USER_MODE_EVENT_HEAD_HPP_

#include <cstdint>
namespace hng {

struct event_head {
    uint32_t pid;
    uint64_t pid_start_time;
    uint32_t ppid;
    uint64_t ppid_start_time;
};

}  // namespace hng

#endif  //_USER_MODE_EVENT_HEAD_HPP_