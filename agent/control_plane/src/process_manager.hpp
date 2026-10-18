/**
 * @file process_manager.hpp
 * @brief 控制平面的 进程管理器 组件
 * @author red_shinku
 * @date 2026.8.20
 */

#ifndef _CONTROL_PLANE_PROCESSMANAGER_HPP
#define _CONTROL_PLANE_PROCESSMANAGER_HPP

#include <array>
#include <atomic>
#include <unordered_map>
#include <shared_mutex>

#include "agent/control_plane/include/role_service.hpp"
#include "agent/util/include/notification_queue.hpp"
#include "agent/control_plane/include/context_service.hpp"
#include "agent/control_plane/include/process_service.hpp"

/**
 * @brief 进程树结构的分片，使用读写锁管理一个分片
 * @details map 单键 PID，值 Process
 */
struct ProcessShard {
    // mutable，在 const 函数中锁变量允许修改
    mutable std::shared_mutex smtx;
    std::unordered_map<uint32_t, hng::ProcessMessage>
        process;  ///< PID -> Process
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
    std::unordered_map<VProcessKey, hng::ProcessMessage, KeyHash> vprocess;
};

/// @brief 进程管理器的异常态观测快照
struct ProcessManagerStats {
    /// 累计：注册时发现该 pid 的旧实例仍在实进程树中
    /// @details 即 pid 已被复用，而旧实例的退出事件缺失或晚于本条到达。
    /// 出现即说明采集侧丢过事件或跨通道乱序；旧实例已按退役路径处理
    uint64_t pid_reused = 0;
};

class ProcessManager : public ProcessLookupService, public ProcessJoinService {
   public:
    ProcessManager();
    ~ProcessManager();

    /**
     * @brief 按 pid + pid_start_time 查询进程
     *  内部同时查找存活进程树(ptree)与虚拟根树(父进程已退出的后台进程),
     *  工作平面无需关心进程是否后台
     */
    std::optional<hng::ProcessMessage> lookup(hng::Process p) const override;

    /// @brief 按 pid 反查进程实体；存活进程优先，其次虚拟根
    std::optional<hng::Process> resolve(uint32_t pid) const override;

    /// @brief 通知注册新 PID：入队即返回
    /// @note 可被任意采集线程调用
    void register_pid(hng::event_head ehead) override;

    /// @brief 通知注销 PID：入队即返回
    void unregister_pid(hng::Process p) override;

    /// @brief 消费线程入口：取队列、落地、按判定推送完全删除通知，阻塞直到 stop()
    /// @note 不持线程，线程由装配方创建；析构前须已返回
    void run();

    /// @brief 停止消费；幂等，可从任意线程调用
    /// @note 已入队的任务仍会被落地，队列取空后 run() 返回；此后的入队被拒绝
    void stop();

    /// @brief 注入 contextservice 接口依赖
    void set_context_service(ContextClearService* c_svc);

    /// @brief 注入角色归属接口依赖（可空）
    void set_role_join_service(RoleJoinService* service);

    /// @brief 注入角色清理接口依赖（可空）
    void set_role_clear_service(RoleClearService* service);

    /// @brief 异常态观测快照
    /// @note 只供 ProcessManager 的装配者/运维端使用
    ProcessManagerStats stats() const;

   private:
    // 进程树分片数量
    static constexpr size_t kShardCount = 32;

    /// @brief 入队任务：注册或注销一个进程
    struct Task {
        enum class Kind { ADD, REMOVE };

        Kind kind = Kind::ADD;
        hng::ProcessMessage add;  ///< kind 为 ADD 时有效
        hng::Process remove;      ///< kind 为 REMOVE 时有效
    };

    ContextClearService* ctx_clear_service_ = nullptr;
    RoleJoinService* role_join_service_     = nullptr;
    RoleClearService* role_clear_service_   = nullptr;

    // 任务队列：多生产者、无界，写入方是各个采集线程与其他组件的转交
    hng::NotificationQueue<Task> task;

    // 消费线程写、任意线程读，故为原子
    std::atomic<uint64_t> pid_reused_{0};

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
    void addPID(hng::ProcessMessage&& data);

    /**
     * @brief 实际删除 PID 树节点
     * @details
     *  删除时，根据子进程计数，判断是否需要
     *  保留该 Process 为虚拟根节点。
     *  只要 PID 从 ptree_shard 中实际删除，其父进程的孩子计数就会递减
     */
    void deletePID(hng::Process p);

    /**
     * @brief 退役一条已从实进程树取下的进程记录
     * @details 有存活子进程时转入虚拟根（待其子进程全部退出后再报完全删除），
     *  否则报完全删除。两种情况都递减其父进程的孩子计数。
     * @param old 已从 ptree 取出的记录，含其孩子计数
     * @note 调用方须已释放分片锁：本函数会写虚拟根、改父计数、发通知
     */
    void retire(hng::ProcessMessage&& old);

    /**
     * @brief 递增 / 递减父进程的引用计数
     *  父进程存活时更新其 ptree 计数,已退出时回退更新虚拟根计数;
     *  内部自行加独占锁,线程安全;两者皆未命中时静默放弃
     */
    void update_child_count_add(hng::Process p);
    void update_child_count_decrease(hng::Process p);

    /**
     * @brief 递减虚拟根进程的引用计数,计数归零后清理虚拟根节点
     *  内部自行对虚拟根所属分片加独占锁,线程安全;
     *  目标进程不在虚拟根中时静默放弃更新
     */
    void update_vroot_child_count_decrease(hng::Process p);

    /**
     * @brief 上报进程已被完全删除
     * @details 进程在实进程树与虚拟根树中均无记录、不再可能被追溯时调用，
     *  则通知其他组件 尝试删除与该进程 相关联的记录
     */
    void notify_process_fully_removed(hng::Process p);

    /// @brief 落地一条队列任务
    void land(Task& task);
};

#endif  // _CONTROL_PLANE_PROCESSMANAGER_HPP