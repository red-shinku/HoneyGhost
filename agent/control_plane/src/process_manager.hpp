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
#include <chrono>
#include <functional>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <variant>
#include <vector>

#include "agent/control_plane/include/process_lifecycle_sink.hpp"
#include "agent/control_plane/include/role_service.hpp"
#include "agent/util/include/notification_queue.hpp"
#include "agent/control_plane/include/process_service.hpp"
#include "agent/util/include/tombstone_table.hpp"

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
/// @details 除 tombstone_depth 为当前值外，其余字段为累计计数。
struct ProcessManagerStats {
    /// 累计：注册时发现该 pid 的旧实例仍在实进程树中
    /// @details 即 pid 已被复用，而旧实例的退出事件缺失或晚于本条到达。
    /// 出现即说明采集侧丢过事件或跨通道乱序；旧实例已按退役路径处理
    uint64_t pid_reused      = 0;

    /// 累计：注册的进程已有墓碑，ADD 被当作迟到事件丢弃的次数
    uint64_t stale_add       = 0;

    /// 累计：注册时父进程身份既不在实进程树也不在虚拟根中的次数
    /// @details 这类 ADD 照常插入，但不更新任何父进程的孩子计数
    uint64_t parent_missing  = 0;

    /// 当前：墓碑表中的条目数
    uint64_t tombstone_depth = 0;
};

/// @brief 进程管理器接收的关系修复配置
/// @details 默认值可直接运行；测试通过覆盖参数注入假时钟与小容量、短寿命。
struct ProcessManagerOptions {
    hng::TombstoneOptions tombstones;  ///< 已退出进程墓碑表
    /// 当前时间来源，必须是单调时钟
    std::function<hng::RelationTimePoint()> now = [] {
        return std::chrono::steady_clock::now();
    };
};

class ProcessManager : public ProcessLookupService,
                       public ProcessJoinService,
                       public ProcessUpdateService,
                       public ProcessLivenessService {
   public:
    /// @param options 墓碑表与时钟
    explicit ProcessManager(ProcessManagerOptions options = {});
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

    /// @brief 通知更新进程镜像路径：入队即返回
    /// @note 可被任意采集线程调用
    void update_exe_image(hng::Process p, std::string exe) override;

    /// @brief 消费线程入口：取队列、落地、推送进程退出通知，阻塞直到 stop()
    /// @note 不持线程，线程由装配方创建；析构前须已返回
    void run();

    /// @brief 停止消费；幂等，可从任意线程调用
    /// @note 已入队的任务仍会被落地，队列取空后 run() 返回；此后的入队被拒绝
    void stop();

    /// @brief 该身份是否已有未过期的墓碑
    /// @note 命中但已过期的墓碑会被就地清除
    /// @note 只回答“已知退出”，不要求证明存活；未知身份返回 false
    bool is_exited(hng::Process p) const override;

    /// @brief 注册进程生命周期订阅者
    /// @param sink 空指针忽略；须存活到 run() 返回之后
    /// @note 只可在 run() 之前调用，此后不再变更
    void add_process_lifecycle_sink(ProcessLifecycleSink* sink);

    /// @brief 注入角色归属接口依赖（可空）
    void set_role_join_service(RoleJoinService* service);

    /// @brief 异常态观测快照
    /// @note 只供 ProcessManager 的装配者/运维端使用
    ProcessManagerStats stats() const;

   private:
    // 进程树分片数量
    static constexpr size_t kShardCount = 32;

    /// @brief 入队任务：注册、注销一个进程，或更新其镜像
    struct Task {
        enum class Kind { ADD, REMOVE, UPDATE_IMAGE };

        Kind kind = Kind::ADD;
        hng::ProcessMessage add;     ///< kind 为 ADD 时有效
        hng::Process remove;         ///< kind 为 REMOVE 时有效
        hng::Process image_process;  ///< kind 为 UPDATE_IMAGE 时有效
        std::string image_exe;       ///< kind 为 UPDATE_IMAGE 时有效
    };

    /// 注册的订阅者，不接管生命周期；run() 之后不再变更
    std::vector<ProcessLifecycleSink*> lifecycle_sinks_;
    RoleJoinService* role_join_service_ = nullptr;

    ProcessManagerOptions options_;

    // 墓碑表与进程树是两套独立的锁；持本锁时不得做通知、角色转交或进程树操作
    mutable std::mutex tombstone_mutex_;
    mutable hng::TombstoneTable<hng::Process, std::monostate> tombstones_;

    // 任务队列：多生产者、无界，写入方是各个采集线程与其他组件的转交
    hng::NotificationQueue<Task> task;

    // 消费线程写、任意线程读，故为原子
    std::atomic<uint64_t> pid_reused_{0};
    std::atomic<uint64_t> stale_add_{0};
    std::atomic<uint64_t> parent_missing_{0};

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
     * @note 身份已有墓碑时整条 ADD 丢弃，只计 stale_add：不插入、不更新父计数、
     *       不转交角色归属
     */
    void addPID(hng::ProcessMessage&& data);

    /**
     * @brief 实际删除 PID 树节点
     * @details
     *  删除时，根据子进程计数，判断是否需要
     *  保留该 Process 为虚拟根节点。
     *  只要 PID 从 ptree_shard 中实际删除，其父进程的孩子计数就会递减
     * @note 无论是否命中记录都先写墓碑再通知订阅者；重复退出幂等
     */
    void deletePID(hng::Process p);

    /// @brief 实际更新进程镜像路径
    /// @details 先按身份匹配实进程树，未命中再匹配虚拟根；都不命中则丢弃
    void update_exe_image_(hng::Process p, std::string exe);

    /**
     * @brief 退役一条已从实进程树取下的进程记录
     * @details 有实子进程时转入虚拟根，待其实子进程全部退出后删除记录；否则
     *  直接删除。两种情况都在退出时通知订阅者，并递减其父进程的孩子计数。
     * @param old 已从 ptree 取出的记录，含其孩子计数
     * @note 调用方须已释放分片锁：本函数会写虚拟根、改父计数、发通知
     * @note 先写墓碑再通知，订阅者在其退出回调内即可查到该身份已退出
     */
    void retire(hng::ProcessMessage&& old);

    /**
     * @brief 递增 / 递减父进程的引用计数
     *  父进程存活时更新其 ptree 计数,已退出时回退更新虚拟根计数;
     *  内部自行加独占锁,线程安全
     * @note 递增时 pid 为 0（森林根）或父身份两处都未命中则不计任何计数，
     *       后者另计 parent_missing
     */
    void update_child_count_add(hng::Process p);
    void update_child_count_decrease(hng::Process p);

    /**
     * @brief 递减虚拟根进程的引用计数,计数归零后清理虚拟根节点
     *  内部自行对虚拟根所属分片加独占锁,线程安全;
     *  目标进程不在虚拟根中时静默放弃更新
     */
    void update_vroot_child_count_decrease(hng::Process p);

    /// @brief 向全部订阅者转发进程退出
    /// @note 按身份转发；订阅方自行决定清理哪些内部关系，并须容忍重复投递
    /// @note 调用方不得持有墓碑锁或进程树分片锁
    void notify_process_exited(hng::Process p);

    /// @brief 当前时间；options_.now 为空时取 steady_clock
    hng::RelationTimePoint now() const;

    /// @brief 记录 p 已退出；同身份未过期的首条墓碑优先
    void add_tombstone_(hng::Process p);

    /// @brief 清除过期墓碑
    void expire_tombstones_();

    /// @brief 落地一条队列任务
    void land(Task& task);
};

#endif  // _CONTROL_PLANE_PROCESSMANAGER_HPP