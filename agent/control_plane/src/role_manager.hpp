/**
 * @file role_manager.hpp
 * @brief 控制平面的角色管理器组件
 * @details
 * 进程属于哪个角色的权威。把发现器按实例键产出的角色事件落成按进程索引的
 * 归属表，并为每个角色分配 roleID。不判定角色存活（权威在发现器的状态表）、
 * 不持久化。roleLabel 由内部件 RoleLabelBuilder 按身份来源生成。
 * 表与落地规则在 RoleRelationStore，本组件负责队列、消费线程、cgroup 读取与出口。
 * @author red_shinku
 * @date 2026.9.17
 */

#ifndef HNG_ROLE_MANAGER_HPP_
#define HNG_ROLE_MANAGER_HPP_

#include <atomic>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <variant>
#include <vector>

#include "agent/control_plane/include/process_lifecycle_sink.hpp"
#include "agent/control_plane/include/role_lifecycle_sink.hpp"
#include "agent/control_plane/include/role_stats.hpp"
#include "agent/control_plane/src/role_relation_store.hpp"
#include "agent/control_plane/include/role_service.hpp"
#include "agent/role_discovery/include/role_event_sink.hpp"
#include "agent/util/include/notification_queue.hpp"

/**
 * @brief 角色管理器外部 IO 的注入点
 * @details 字段留空时用真实实现。单元测试注入替身，以便不依赖真实 cgroup 目录。
 */
struct RoleManagerProbe {
    /// 按 cgroup 路径枚举进程的实现，留空时用 RoleCgroupReader::read
    std::function<std::vector<hng::Process>(const std::string& cgroup_path)>
        read_members;
    /// 进程存活视图，留空时不做存活过滤
    std::function<bool(hng::Process)> is_exited;
};

class RoleManager : public hng::role::RoleEventSink,
                    public RoleLookupService,
                    public RoleJoinService,
                    public ProcessLifecycleSink,
                    public RoleSupervisionService {
   public:
    /// @param probe IO 注入点，留空字段用真实实现
    /// @param options 关系修复配置：等待表、墓碑表与时钟
    explicit RoleManager(RoleManagerProbe probe      = {},
                         RoleRelationOptions options = {});

    /// @brief 注册一个下行出口
    /// @param sink 空指针忽略；同一实现重复注册会收到重复通知
    /// @note 只可在 run() 之前调用：出口列表是消费线程只读的数据
    void add_lifecycle_sink(RoleLifecycleSink* sink);

    /// @brief 接收一个角色事件：只入队，立即返回
    /// @note 跑在发现器线程上
    void on_role_event(const hng::role::RoleEvent& event) override;

    /// @brief 子进程继承父进程的角色归属：入队即返回
    void bind_to_role(hng::Process child, hng::Process parent) override;

    /// @brief 进程已退出：入队即返回
    void on_process_exited(hng::Process p) override;

    /// @brief 消费线程入口：取队列、落地、按跃迁调出口，阻塞直到 stop()
    /// @note 不持线程，线程由装配方创建；析构前须已返回
    void run();

    /// @brief 停止消费；幂等，可从任意线程调用
    /// @note 已入队的事件仍会被落地，队列取空后 run() 返回；此后的入队一律
    ///       被拒绝并计入 queue_rejected
    void stop();

    /**
     * \defgroup Rolemanager_lookup_service
     * Rolemanager 实现的 RoleLookupService 接口
     */
    /*@{*/

    /// \ingroup Rolemanager_lookup_service
    std::optional<uint32_t> lookup(hng::Process p) const override;

    /// \ingroup Rolemanager_lookup_service
    std::optional<hng::Role> role(uint32_t roleID) const override;

    /// \ingroup Rolemanager_lookup_service
    std::optional<hng::Process> main_process(uint32_t roleID) const override;

    /// \ingroup Rolemanager_lookup_service
    std::vector<hng::Role> roles() const override;

    /// \ingroup Rolemanager_lookup_service
    std::vector<hng::Role> supervised_roles() const override;

    /// \ingroup Rolemanager_lookup_service
    std::optional<hng::role::RoleIdentity> identity(
        uint32_t roleID) const override;

    /// \ingroup Rolemanager_lookup_service
    std::vector<hng::Process> members(uint32_t roleID) const override;

    /**
     * @} endgroup Rolemanager_lookup_service
     */

    /// @brief 登记或移除系统监管角色；roleID 不存在时忽略
    void set_supervised(uint32_t roleID, bool supervised) override;

    /// @brief 异常态观测快照
    RoleManagerStats stats() const override;

   private:
    /// @brief 入队消息：进程已退出
    struct ExitedMessage {
        hng::Process process;
    };

    /// @brief 入队消息：子进程继承归属
    struct BindMessage {
        hng::Process child;
        hng::Process parent;
    };

    /// 三类入口共用一个队列，按到达顺序串行落地
    using RoleTask =
        std::variant<hng::role::RoleEvent, BindMessage, ExitedMessage>;

    /// @brief 入队；生产者线程上只做这一次拷贝
    /// @note 被拒绝（已停止）时计数，不入队
    void enqueue(RoleTask task);

    /// @brief 落地一条队列消息
    void land(RoleTask& task);

    /// @brief 落地一个角色事件
    void land_event(const hng::role::RoleEvent& event);

    /// @brief 算成员集：载荷的成员 ∪ cgroup 重读结果 ∪ {锚点}
    /// @note cgroup 路径为空时不重读；已退出成员在此处过滤，不计入成员集
    std::vector<hng::Process> member_set(const hng::role::RolePayload& payload);

    /// @brief 锚点是否已知退出：先查注入的存活视图，再查关系表的墓碑
    bool anchor_exited(hng::Process p);

    /// @brief 按跃迁依次调全部下行出口；kind 为 NONE 时不产生生命周期通知
    void notify(const RoleTransition& transition);

    /// @brief 按角色依次调全部下行出口的成员新增通知
    void notify_members(const RoleMemberChanges& changes);

    RoleManagerProbe probe_;
    /// 注册的下行出口，不接管生命周期；run() 之后不再变更
    std::vector<RoleLifecycleSink*> lifecycle_sinks_;

    RoleRelationStore store_;

    /// 无界队列，入队不因容量而阻塞
    hng::NotificationQueue<RoleTask> queue_;

    /// 消费线程写、任意线程读，故为原子
    std::atomic<uint64_t> cgroup_read_empty_{0};
    std::atomic<uint64_t> queue_rejected_{0};
    std::atomic<uint64_t> dead_member_rejected_{0};
    std::atomic<uint64_t> dead_anchor_rejected_{0};
};

#endif  // HNG_ROLE_MANAGER_HPP_
