#ifndef _CONTROL_PLANE_PROCESSMANAGER_HPP
#define _CONTROL_PLANE_PROCESSMANAGER_HPP

#include <cstdint>
#include <array>
#include <unordered_map>
#include <shared_mutex>
#include <optional>

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

/**
 * @brief 进程树结构的分片，使用读写锁管理一个分片
 */
struct ProcessShard {
    // mutable，在 const 函数中锁变量允许修改
    mutable std::shared_mutex smtx;
    std::unordered_map<uint32_t, Process> process;  ///< PID -> Process
};

class ProcessManager {
   public:
    ProcessManager(/* args */);
    ~ProcessManager();

   private:
    static constexpr size_t kShardCount = 64;

    // 维护一组进程树的分片，PID 通过哈希落到对应的分片中
    // 该数据结构是频繁访问的，局部的共享锁一定程度上优化了访问
    std::array<ProcessShard, kShardCount> shard;

    // 返回 PID 的所属分片位置
    size_t shard_index(uint32_t pid) const
    {
        return std::hash<uint32_t>{}(pid) % kShardCount;
    }

    // 查找并返回值类型的 Process
    std::optional<Process> lookup(uint32_t pid) const;
};

#endif  // _CONTROL_PLANE_PROCESSMANAGER_HPP