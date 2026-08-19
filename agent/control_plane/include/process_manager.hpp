#ifndef _CONTROL_PLANE_PROCESSMANAGER_HPP
#define _CONTROL_PLANE_PROCESSMANAGER_HPP

#include <cstdint>
#include <array>
#include <unordered_map>
#include <shared_mutex>
#include <optional>
#include <functional>

#include "agent/util/include/raw_event_queue_ss.hpp"
#include "agent/event_data/event_head.hpp"

struct Process {
    Process(const hng::event_head& ehead)
    {
        pid        = ehead.pid;
        ppid       = ehead.ppid;
        start_time = ehead.pid_start_time;
    }

    uint32_t ppid;
    uint32_t pid;
    uint64_t start_time;

    uint32_t child_count;

    uint16_t roleID;     ///< 缓存的roleID
    uint32_t contextID;  ///< 缓存的contextID

    bool is_role_root;
    bool is_context_root;

    // 是否为后台进程 (且 ppid=1)
    bool is_backing;

    // 虚拟PID，用于标记一个不存在的父进程
    // 这个父进程生前启动了一批持续运行的子进程
    // 子进程的 ppid 为 fake_pid
    uint64_t fake_pid;
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

    // 查找并返回值类型的 Process
    // 注册到 函数表 中，工作平面组件可以直接调用查询
    std::optional<Process> lookup(uint32_t pid, uint64_t start_time) const;

    void register_pid(hng::event_head ehead);

    void unregister_pid(uint32_t pid, uint64_t start_time);

   private:
    // 进程树分片数量
    static constexpr size_t kShardCount = 32;

    // 任务队列
    hng::RawEventQueue_SS<std::function<void()>> task;

    // 维护一组进程树的分片，PID 通过哈希落到对应的分片中
    // 该数据结构是频繁访问的，局部的共享锁一定程度上优化了访问
    std::array<ProcessShard, kShardCount> shard;

    // 返回 PID 的所属分片位置
    size_t shard_index(uint32_t pid) const
    {
        return std::hash<uint32_t>{}(pid) % kShardCount;
    }

    // 实际将新的 Process 插入 PID 树的操作
    // 如果树中 PID 已存在，只有 start_time 不一致时
    // 才会直接替换旧 Process
    void addPID(Process&& data);

    // 实际删除 PID 树节点 TODO: 后台进程（未退出的子进程）怎么办
    void deletePID(uint32_t pid, uint64_t start_time);

    std::optional<Process&> lookup_ref(uint32_t pid, uint64_t start_time);

    // 递增 / 递减父进程的引用计数
    // 这是线程不安全的
    void update_child_count_add(uint32_t pid, uint64_t start_time);
    void update_child_count_decrease(uint32_t pid, uint64_t start_time);

    // TODO: 对 contextID、roleID 的 Process缓存更新（来自其他控制面组件）

    void work();
};

#endif  // _CONTROL_PLANE_PROCESSMANAGER_HPP