/**
 * @file process_manager.hpp
 * @brief 控制平面的 进程管理器 组件
 * @author red_shinku
 * @date 2026.8.20
 */

#ifndef _CONTROL_PLANE_PROCESSMANAGER_HPP
#define _CONTROL_PLANE_PROCESSMANAGER_HPP

#include <array>
#include <unordered_map>
#include <shared_mutex>
#include <functional>

#include "agent/util/include/raw_event_queue_ss.hpp"
#include "process_service.hpp"

/**
 * @brief 进程树结构的分片，使用读写锁管理一个分片
 * @details map 单键 PID，值 Process
 */
struct ProcessShard {
    // mutable，在 const 函数中锁变量允许修改
    mutable std::shared_mutex smtx;
    std::unordered_map<uint32_t, hng::Process> process;  ///< PID -> Process
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
 * @brief 虚拟根进程的 map 分片
 */
struct VProcessShard {
    struct KeyHash {
        std::size_t operator()(const VProcessKey& k) const
        {
            return std::hash<uint32_t>{}(k.pid) ^
                   (std::hash<uint64_t>{}(k.pid_start_time) << 1);
        }
    };
    mutable std::shared_mutex smtx;
    std::unordered_map<VProcessKey, hng::Process, KeyHash> vprocess;
};

class ProcessManager : public ProcessService {
   public:
    ProcessManager();
    ~ProcessManager();

    /**
     * @brief 按 pid + pid_start_time 查询进程
     *  内部同时查找存活进程树(ptree)与虚拟根树(父进程已退出的后台进程),
     *  工作平面无需关心进程是否后台
     */
    std::optional<hng::Process> lookup(uint32_t pid,
                                       uint64_t start_time) const override;

    void register_pid(hng::event_head ehead) override;

    void unregister_pid(uint32_t pid, uint64_t start_time) override;

   private:
    // 进程树分片数量
    static constexpr size_t kShardCount        = 32;

    // 任务队列容量(注册/注销事件),SPSC 队列,容量需为 2 的幂
    static constexpr size_t kTaskQueueCapacity = 4096;

    // 任务队列,只支持单生产者单消费者的安全并发
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
    void addPID(hng::Process&& data);

    /**
     * @brief 实际删除 PID 树节点
     * @details
     *  删除时，根据子进程计数，判断是否需要
     *  保留该 Process 为虚拟根节点。
     *  只要 PID 从 ptree_shard 中实际删除，其父进程的孩子计数就会递减
     */
    void deletePID(uint32_t pid, uint64_t start_time);

    /**
     * @brief 递增 / 递减父进程的引用计数
     *  父进程存活时更新其 ptree 计数,已退出时回退更新虚拟根计数;
     *  内部自行加独占锁,线程安全;两者皆未命中时静默放弃
     */
    void update_child_count_add(uint32_t pid, uint64_t start_time);
    void update_child_count_decrease(uint32_t pid, uint64_t start_time);

    /**
     * @brief 递减虚拟根进程的引用计数,计数归零后清理虚拟根节点
     *  内部自行对虚拟根所属分片加独占锁,线程安全;
     *  目标进程不在虚拟根中时静默放弃更新
     */
    void update_vroot_child_count_decrease(uint32_t pid, uint64_t start_time);

    // TODO: 对 contextID、roleID 的 Process缓存更新（来自其他控制面组件）

    void work();
};

#endif  // _CONTROL_PLANE_PROCESSMANAGER_HPP