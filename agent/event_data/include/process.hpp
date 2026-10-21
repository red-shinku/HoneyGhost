#ifndef _USER_MODE_PROCESS_HPP
#define _USER_MODE_PROCESS_HPP

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>

#include "agent/event_data/include/event_head.hpp"

namespace hng {

/**
 * @brief 进程的唯一性表示
 * @details 身份由 (pid, pid_start_time) 共同决定：pid 会被内核复用，
 * 同 pid 而 start_time 不同即为另一个进程实体
 */
struct Process {
    uint32_t pid;
    uint64_t pid_start_time;

    /// @brief 同一进程实体：两个字段均相等
    bool operator==(const Process& other) const
    {
        return pid == other.pid && pid_start_time == other.pid_start_time;
    }
};

/**
 * @brief hng::Process 的类型，区分真实进程、虚拟根进程
 */
enum class ProcessKind : uint8_t {
    // 真实运行在宿主机上的进程
    REAL    = 1,
    // 系统中定义的虚拟根进程
    VIRTUAL = 0
};

/**
 * @brief 进程具体信息记录
 */
struct ProcessMessage {
    ProcessMessage(const hng::event_head& ehead)
    {
        pid             = ehead.pid;
        ppid            = ehead.ppid;
        pid_start_time  = ehead.pid_start_time;
        ppid_start_time = ehead.ppid_start_time;
        child_count     = 0;
        kind            = ProcessKind::REAL;
    }
    ProcessMessage()
        : ppid(0),
          pid(0),
          ppid_start_time(0),
          pid_start_time(0),
          kind(ProcessKind::REAL),
          child_count(0)
    {
    }

    uint32_t ppid;
    uint32_t pid;
    uint64_t ppid_start_time;
    uint64_t pid_start_time;
    /// 最近一次 exec 的镜像路径；未知时为空
    std::string exe;
    /// 进程性质；注册时为 REAL，转入虚拟根后为 VIRTUAL
    ProcessKind kind;
    uint32_t child_count;
};

}  // namespace hng

namespace std {

/**
 * @brief hng::Process 的哈希
 * @details 须与 hng::Process::operator== 覆盖同一组字段，
 * 保证相等者哈希相同
 */
template <>
struct hash<hng::Process> {
    std::size_t operator()(const hng::Process& p) const
    {
        return std::hash<uint32_t>{}(p.pid) ^
               (std::hash<uint64_t>{}(p.pid_start_time) << 1);
    }
};

}  // namespace std

#endif  //_USER_MODE_PROCESS_HPP