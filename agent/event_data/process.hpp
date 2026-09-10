#ifndef _USER_MODE_PROCESS_HPP
#define _USER_MODE_PROCESS_HPP

#include "agent/event_data/event_head.hpp"

namespace hng {

/**
 * @brief 进程的唯一性表示
 */
struct Process {
    uint32_t pid;
    uint64_t pid_start_time;
};

/**
 * @brief 进程结构记录
 * @details 仅承载进程自身的结构事实（身份与父子关系、存活子进程计数）。
 */
struct ProcessMessage {
    ProcessMessage(const hng::event_head& ehead)
    {
        pid             = ehead.pid;
        ppid            = ehead.ppid;
        pid_start_time  = ehead.pid_start_time;
        ppid_start_time = ehead.ppid_start_time;
        child_count     = 0;
    }
    ProcessMessage() {}

    uint32_t ppid;
    uint32_t pid;
    uint64_t pid_start_time;
    uint64_t ppid_start_time;

    uint32_t child_count;

    // 虚拟PID，用于标记一个不存在的父进程
    // 这个父进程生前启动了一批持续运行的子进程
    // 这些子进程的 ppid 为 fake_pid
    // 目前设计直接让 原 pid + starttime 作为键
    // 故这里注释掉
    // uint64_t fake_pid;
};

}  // namespace hng

#endif  //_USER_MODE_PROCESS_HPP