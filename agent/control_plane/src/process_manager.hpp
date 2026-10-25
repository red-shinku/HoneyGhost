/**
 * @file process_manager.hpp
 * @brief 控制平面的 进程管理器 组件
 * @author red_shinku
 * @date 2026.8.20
 */

#ifndef _CONTROL_PLANE_PROCESSMANAGER_HPP
#define _CONTROL_PLANE_PROCESSMANAGER_HPP

#include <atomic>
#include <optional>
#include <string>
#include <vector>

#include "agent/control_plane/include/process_lifecycle_sink.hpp"
#include "agent/control_plane/include/process_seed_service.hpp"
#include "agent/control_plane/include/role_service.hpp"
#include "agent/util/include/component.hpp"
#include "agent/util/include/notification_queue.hpp"
#include "agent/control_plane/include/process_service.hpp"
#include "agent/control_plane/include/process_stats.hpp"
#include "agent/event_data/include/process_seed.hpp"

#include "agent/control_plane/src/process_store.hpp"

/// @brief 进程管理器
/// @details 表结构、虚拟根、墓碑与落地计数由 ProcessStore 持有；本类只负责队列、
/// 消费线程、退出通知、角色继承转交与查询面转发。
class ProcessManager : public ProcessLookupService,
                       public ProcessJoinService,
                       public ProcessUpdateService,
                       public ProcessLivenessService,
                       public ProcessSeedService {
   public:
    /// @param options 墓碑表与时钟
    explicit ProcessManager(ProcessStoreOptions options = {});
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

    /// @brief 用一次快照批量构造初始进程树
    /// @details 同步写入，不经通知队列；成功后状态迁移到 READY。
    /// @param batch 初始进程批次
    /// @return 落地统计；状态不是 CONSTRUCTED 时 rejected_state 为 1，不写表
    /// @pre 状态为 CONSTRUCTED；只调用一次
    /// @see ProcessSeedService::seed
    ProcessSeedReport seed(const hng::ProcessSeedBatch& batch) override;

    /// @brief 消费线程入口：取队列、落地、推送进程退出通知，阻塞直到 stop()
    /// @note 状态不是 READY 时立即返回，不消费队列；不持线程，线程由装配方
    ///       创建；析构前须已返回
    void run();

    /// @brief 停止消费；幂等，可从任意线程调用
    /// @note 已入队的任务仍会被落地，队列取空后 run() 返回；此后的入队被拒绝
    /// @note 未处于 RUNNING 时直接置 STOPPED，供 run() 之前与构造失败的清理
    void stop();

    /// @brief 当前生命周期状态
    /// @note 可从任意线程读取
    /// @see hng::Component
    hng::ComponentState state() const;

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
    /// @brief 入队任务：注册、注销一个进程，或更新其镜像
    struct Task {
        enum class Kind { ADD, REMOVE, UPDATE_IMAGE };

        Kind kind = Kind::ADD;
        hng::ProcessMessage add;     ///< kind 为 ADD 时有效
        hng::Process remove;         ///< kind 为 REMOVE 时有效
        hng::Process image_process;  ///< kind 为 UPDATE_IMAGE 时有效
        std::string image_exe;       ///< kind 为 UPDATE_IMAGE 时有效
    };

    /// @brief 落地一条队列任务
    /// @details 写表由 ProcessStore 完成；本类只处理退出通知与角色继承
    void land(Task& task);

    /// @brief 向全部订阅者转发进程退出
    /// @note 按身份转发；订阅方自行决定清理哪些内部关系，并须容忍重复投递
    /// @note 调用方不得持有墓碑锁或进程树分片锁
    void notify_process_exited(hng::Process p);

    /// 消费线程与任意线程都读，故为原子
    std::atomic<hng::ComponentState> state_{hng::ComponentState::CONSTRUCTED};

    /// 注册的订阅者，不接管生命周期；run() 之后不再变更
    std::vector<ProcessLifecycleSink*> lifecycle_sinks_;
    RoleJoinService* role_join_service_ = nullptr;

    // 任务队列：多生产者、无界，写入方是各个采集线程与其他组件的转交
    hng::NotificationQueue<Task> task;

    ProcessStore store_;
};

#endif  // _CONTROL_PLANE_PROCESSMANAGER_HPP
