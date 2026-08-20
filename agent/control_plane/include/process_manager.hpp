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
        pid             = ehead.pid;
        ppid            = ehead.ppid;
        pid_start_time  = ehead.pid_start_time;
        ppid_start_time = ehead.ppid_start_time;
        child_count     = 0;
        roleID          = 0;
        contextID       = 0;
        is_role_root    = false;
        is_context_root = false;
        is_backing      = false;
    }

    uint32_t ppid;
    uint32_t pid;
    uint64_t pid_start_time;
    uint64_t ppid_start_time;

    uint32_t child_count;

    uint16_t roleID;     ///< 缓存的roleID
    uint32_t contextID;  ///< 缓存的contextID

    bool is_role_root;
    bool is_context_root;

    // 是否为后台进程
    bool is_backing;

    // 虚拟PID，用于标记一个不存在的父进程
    // 这个父进程生前启动了一批持续运行的子进程
    // 这些子进程的 ppid 为 fake_pid
    // 目前设计直接让 原 pid + starttime 作为键
    // 故这里注释掉
    // uint64_t fake_pid;
};

/**
 * @brief 进程树结构的分片，使用读写锁管理一个分片
 * @details map 单键 PID，值 Process
 */
struct ProcessShard {
    // mutable，在 const 函数中锁变量允许修改
    mutable std::shared_mutex smtx;
    std::unordered_map<uint32_t, Process> process;  ///< PID -> Process
};

/**
 * @brief 虚拟根进程的 map 键
 */
struct VProcessKey {
    uint32_t pid;
    uint64_t pid_start_time;

    bool operator==(const VProcessKey& other) const
    {
        return other.pid == pid && other.pid_start_time == pid_start_time;
    }
};

/**
 * @brief
 */
struct VProcessShard {
    struct KeyHash {
        std::size_t operator()(const VProcessKey& k) const
        {
            return std::hash<int>{}(k.pid) ^
                   (std::hash<int>{}(k.pid_start_time) << 1);
        }
    };
    mutable std::shared_mutex smtx;
    std::unordered_map<VProcessKey, Process, KeyHash> vprocess;
};

class ProcessManager {
   public:
    ProcessManager(/* args */);
    ~ProcessManager();

    /**
     * @brief 查找并返回值类型的 Process
     *  注册到 函数表 中，工作平面组件可以直接调用查询
     */
    std::optional<Process> lookup(uint32_t pid, uint64_t start_time) const;

    /**
     * @brief 在虚拟根树中按 pid + pid_start_time 查询已退出父进程的 Process
     *  仅当父进程退出时仍留有存活子进程时才有记录；
     *  供工作平面组件追溯已退出的父进程
     */
    std::optional<Process> lookup_vroot(uint32_t pid,
                                        uint64_t pid_start_time) const;

    void register_pid(hng::event_head ehead);

    void unregister_pid(uint32_t pid, uint64_t start_time);

   private:
    // 进程树分片数量
    static constexpr size_t kShardCount = 32;

    // 任务队列
    hng::RawEventQueue_SS<std::function<void()>> task;

    // 维护一组进程树的分片，PID 通过哈希落到对应的分片中
    // 该数据结构是频繁访问的，局部的共享锁一定程度上优化了访问
    std::array<ProcessShard, kShardCount> ptree_shard;

    // 存储虚拟根进程节点
    // 即那些已经退出，但其创建的子进程仍在运行的进程。
    // 这些进程的 pid + starttime 组合会被保留，用于子进程追溯
    std::array<VProcessShard, kShardCount> vptree_root;

    // 返回 PID 的所属分片位置
    size_t shard_index(uint32_t pid) const
    {
        return std::hash<uint32_t>{}(pid) % kShardCount;
    }

    /**
     * @brief 实际将新的 PID 节点 插入 PID 树
     * @details 操作是幂等的
     *  如果树中 PID 已存在，只有 start_time 不一致时
     *  才会直接替换旧 Process。
     */
    void addPID(Process&& data);

    /**
     * @brief 实际删除 PID 树节点
     * @details
     *  删除时，根据子进程计数，判断是否需要
     *  保留该 Process 为虚拟根节点
     */
    void deletePID(uint32_t pid, uint64_t start_time);

    /**
     * @brief 进程的引用查询，供控制面内部更新其缓存字段
     *  返回的引用在锁释放后仍可被使用，仅限单工作线程内调用
     */
    std::optional<Process&> lookup_ref(uint32_t pid, uint64_t start_time);

    /**
     * @brief 虚拟根进程的引用查询，供控制面内部更新其缓存字段
     *   返回的引用在锁释放后仍可被使用，仅限单工作线程内调用
     */
    std::optional<Process&> lookup_vroot_ref(uint32_t pid,
                                             uint64_t pid_start_time);

    // 递增 / 递减父进程的引用计数
    // 这是线程不安全的
    void update_child_count_add(uint32_t pid, uint64_t start_time);
    void update_child_count_decrease(uint32_t pid, uint64_t start_time);

    // TODO: 对 contextID、roleID 的 Process缓存更新（来自其他控制面组件）

    void work();
};

#endif  // _CONTROL_PLANE_PROCESSMANAGER_HPP