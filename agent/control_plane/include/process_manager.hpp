#ifndef _CONTROL_PLANE_PROCESSMANAGER_HPP
#define _CONTROL_PLANE_PROCESSMANAGER_HPP

#include <cstdint>
#include <unordered_map>

class Process {
    /* data */
   public:
    Process(/* args */);
    ~Process();

   private:
    uint32_t ppid;
    uint32_t pid;
    uint64_t start_time;

    uint16_t roleID;     ///< 缓存的roleID
    uint32_t contextID;  ///< 缓存的contextID

    bool is_role_root;
    bool is_context_root;
};

class ProcessManager {
   public:
    ProcessManager(/* args */);
    ~ProcessManager();

   private:
    // TODO: 这是一个高频访问的结构，可能需要优化为分片map+读写锁
    std::unordered_map<uint32_t, Process> process;  ///< PID -> Process
};

#endif  // _CONTROL_PLANE_PROCESSMANAGER_HPP