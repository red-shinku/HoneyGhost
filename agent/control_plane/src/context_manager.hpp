/**
 * @file context_manager.hpp
 * @brief 控制平面的上下文管理器组件
 * @author red_shinku
 * @date 2026.8.18
 */

#ifndef _CONTROL_PLANE_CONTEXTMANAGER_HPP
#define _CONTROL_PLANE_CONTEXTMANAGER_HPP

#include <atomic>
#include <cstdint>
#include <optional>
#include <variant>
#include <vector>

#include "agent/util/include/component.hpp"
#include "agent/util/include/notification_queue.hpp"
#include "agent/control_plane/include/context_service.hpp"
#include "agent/control_plane/include/process_lifecycle_sink.hpp"

#include "agent/control_plane/src/context_store.hpp"

/**
 * @brief 上下文管理器
 * @details
 * 上下文管理器负责 context 结构关系的管理，是单例的
 * 其中记录的 contextID 由工作平面的 context maintainer 模块生成并注册。
 * 具体 Context结构 维护在工作平面本地，形式是 contextID -> Context。
 * 工作平面本地也会维护每个角色的 Context 树关系，并且是第一手的。
 * 控制平面这里则是权威的，所有离散无状态事件的归属标准。
 *
 * 六个写接口都是通知写：入队即返回，落地在 run() 的消费线程上。故入队之后
 * 不得立即依赖查询结果，见 docs/red_shinku_logs/控制平面context归属重构.md §3.3。
 *
 * 表结构、延迟关系、墓碑与落地计数由 ContextStore 持有；本类只负责队列、
 * 消费线程、属性变更钩子与查询面转发。
 */
class ContextManager : public ContextLookupService,
                       public ContextJoinService,
                       public ContextUpdateService,
                       public ProcessLifecycleSink {
   public:
    /// @brief 构造管理器
    /// @param options 延迟表、墓碑表的参数与时间来源
    explicit ContextManager(ContextStoreOptions options = {});
    ~ContextManager();

    /// @brief 查询进程所属主 context 的 ID。
    /// 会先查询该进程所属 context 的根进程，其结果作为
    /// ContextKey 查 contexts 表
    std::optional<uint32_t> lookup(hng::Process p) const override;

    /// @brief 查询进程所属 附属 Context 的 ID（任意进程，经 process→根 映射解析）
    /// 会先查询该进程所属 context 的根进程，其结果作为
    /// ContextKey 查 extras 表
    std::optional<uint32_t> lookup_extra(hng::Process p) const override;

    /// @brief 指定属性的 contextID 集合，按 ID 升序
    std::vector<uint32_t> contexts_by_attr(hng::contextattr attr) const override;

    /// @brief 按 contextID 取根进程与成员集；未知 ID 返回空
    std::optional<ContextProcessSet> members(uint32_t contextID) const override;

    /// @brief 注册新的主 contextID（通知写）
    /// @param p context 代表进程
    /// @param newcontext 新 context 信息；kind 须为 DERIVE
    /// @param parent 父进程引用；落地时解析其 contextID
    /// @see ContextParentRef
    void register_context(hng::Process p, ContextDeriveDecision newcontext,
                          ContextParentRef parent) override;

    /// @brief 注册附属 context（通知写）
    /// @param p context 代表进程；须已有主 context
    /// @param contextID 附属 contextID
    /// @param attr 附属 context 属性
    void register_extra_context(hng::Process p, uint32_t contextID,
                                hng::contextattr attr) override;

    /// @brief 注销 contextID（通知写）
    /// 生成并将实际写操作 加入任务队列
    void unregister_context(hng::Process p) override;

    /// @brief 修改 context 属性（通知写）
    void set_attr(hng::Process p, uint32_t contextID,
                  hng::contextattr attr) override;

    /// @brief 归属落定：KEEP 子进程挂靠到父进程所属的 context（通知写）
    /// @param p 子进程
    /// @param parent 父进程引用；expected 为 true 且父未落定时暂存挂靠，
    ///        expected 为 false 时直接降级并保持未归属
    /// @see ContextParentRef
    void bind_to_ctxroot(hng::Process p, ContextParentRef parent) override;

    /// @brief 进程已退出（通知写）
    /// @details 从归属索引与成员集中移除该进程；成员集清空时删除整个 context。
    ///          根进程退出而其他成员仍在时，context 保留，键仍指向已退出的根
    void on_process_exited(hng::Process p) override;

    /// @brief 消费线程入口：取队列、按到达顺序串行落地，阻塞直到 stop()
    /// @note 不持线程，线程由装配方创建；析构前须已返回
    void run();

    /// @brief 停止消费；幂等，可从任意线程调用
    /// @note 已入队的任务仍会被落地，队列取空后 run() 返回；此后的入队被拒绝
    void stop();

    /// @brief 当前生命周期状态
    /// @note 可从任意线程读取
    /// @see hng::Component
    hng::ComponentState state() const;

    /// @brief 异常态观测快照
    ContextManagerStats stats() const override;

   private:
    /// @brief 入队任务：注册一个主 context
    struct AddTask {
        hng::Process process;
        uint32_t contextID;       ///< 新 context 的 ID，由工作面生成
        hng::contextattr attr;    ///< 新 context 的属性
        ContextParentRef parent;  ///< 父进程引用；落地时解析其 contextID
    };

    /// @brief 入队任务：注册一个附属 context
    struct ExtraTask {
        hng::Process process;
        uint32_t contextID;
        hng::contextattr attr;
    };

    /// @brief 入队任务：注销某个根进程的 context
    struct DelTask {
        hng::Process process;
    };

    /// @brief 入队任务：修改 context 属性
    struct SetAttrTask {
        hng::Process process;
        uint32_t contextID;
        hng::contextattr attr;
    };

    /// @brief 入队任务：把进程挂靠到父进程所属的 context
    struct BindTask {
        hng::Process process;
        ContextParentRef parent;
    };

    /// @brief 入队任务：进程已退出
    struct ExitedTask {
        hng::Process process;
    };

    /// 六个写接口共用一条队列：多生产者、无界，按到达顺序串行落地
    using Task = std::variant<AddTask, ExtraTask, DelTask, SetAttrTask, BindTask,
                              ExitedTask>;
    hng::NotificationQueue<Task> task;

    /// @brief 落地一条队列任务
    void land(Task& task);

    /// @brief 属性实际变更后的钩子
    /// @param attr 变更后的属性
    /// @note 当前为空实现，是向 eBPF map 注册 ATTACK/EXTRA_ATTACK 的挂点
    void apply_attr_hook_(hng::contextattr attr);

    /// 消费线程与任意线程都读，故为原子
    std::atomic<hng::ComponentState> state_{hng::ComponentState::CONSTRUCTED};

    ContextStore store_;
};

#endif  //_CONTROL_PLANE_CONTEXTMANAGER_HPP
