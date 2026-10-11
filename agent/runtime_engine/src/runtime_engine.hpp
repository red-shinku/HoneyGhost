/**
 * @file runtime_engine.hpp
 * @brief 运行时引擎
 * @author red-shinku
 * @date 2026.10.11
 */
#ifndef HNG_RUNTIME_ENGINE_HPP_
#define HNG_RUNTIME_ENGINE_HPP_

#include <atomic>
#include <cstddef>
#include <cstdint>

#include "agent/context_maintainer/include/context_maintainer.hpp"
#include "agent/control_plane/include/process_service.hpp"
#include "agent/control_plane/include/role_service.hpp"
#include "agent/runtime_engine/include/runtime_decision_sink.hpp"
#include "agent/runtime_engine/include/subscriber_reg_service.hpp"
#include "agent/runtime_engine/src/runtime_event_dispatcher.hpp"
#include "agent/runtime_engine/src/runtime_pipeline.hpp"
#include "agent/util/include/notification_queue.hpp"

/// @brief 运行时引擎的观测快照
struct RuntimeEngineStats {
    /// 累计：归属未落定（roleID 或 contextID 为 0）的事件数，一条事件最多计一次
    uint64_t unsettled_events = 0;
    /// 峰值：CLI 订阅表同时存在的订阅流数
    uint64_t peak_cli_streams = 0;
    /// 累计：stop() 之后的订阅命令入队被拒绝
    uint64_t queue_rejected   = 0;
};

/**
 * @brief 驱动语义事件流、向订阅者分发的顶层组件
 * @details 持有流水线与分发器，语义队列的唯一消费者，也是控制平面通知的驱动者。
 * 线程模型为串行单线程：每轮先落地订阅命令、再取一轮事件分发，忙轮询。
 * @note 语义队列、ContextMaintainer 与控制平面服务均不拥有；队列为空指针表示
 * 未接线。析构前 run() 须已返回。
 */
class RuntimeEngine final : public SubscriberRegService {
   public:
    /// @param syscall_queue 系统调用语义队列，未接线传 nullptr
    /// @param file_queue 文件语义队列，未接线传 nullptr
    /// @param ctx_maintainer 上下文维护模块，非拥有
    /// @param process_join 控制平面进程注册接口，非拥有
    /// @param role_join 控制平面角色归属接口，非拥有
    /// @param role_lookup 控制平面角色查询接口，非拥有
    RuntimeEngine(hng::SPSC_Queue<hng::syscall_semantic_data>* syscall_queue,
                  hng::SPSC_Queue<hng::file_semantic_data>* file_queue,
                  ContextMaintainer* ctx_maintainer,
                  ProcessJoinService* process_join, RoleJoinService* role_join,
                  RoleLookupService* role_lookup);

    /// @brief 登记系统订阅者
    /// @param sink 空指针忽略；须存活到引擎停机
    /// @note 只可在 run() 之前调用；同一实现重复注册会收到重复投递
    void add_system_sink(RuntimeDecisionSink* sink);

    /// @brief 引擎线程入口：轮询订阅命令与语义队列，直至 stop()
    /// @note 不持线程，线程由装配方创建；析构前须已返回
    void run();

    /// @brief 停止：此后不再取事件，命令入队一律被拒
    /// @note 幂等，可从任意线程调用；已入队的命令仍会落地（含注销回执），
    ///       run() 排空后返回，此后不再投递事件
    void stop();

    /// @brief 登记一路订阅流：入队即返回，落地在引擎线程上
    /// @note 落地前产生的事件不补发；重复登记以最后一次的过滤器为准
    bool subscribe(RuntimeEventSink* sink, RuntimeInfoFilter filter) override;

    /// @brief 注销一路订阅流：入队即返回，落地在引擎线程上
    /// @note 对未登记的 sink 注销是空操作，仍会收到回执
    bool unsubscribe(RuntimeEventSink* sink, UnsubscribeAck* ack) override;

    /// @brief 异常态观测快照；可从任意线程调用
    RuntimeEngineStats stats() const;

   private:
    /// 一轮最多取出的事件数：与语义队列条数（四条）一致
    static constexpr std::size_t kMaxDraftsPerRound = 4;

    /// @brief 订阅命令；两张表分别对应两个 kind
    struct Command {
        enum class Kind { SUBSCRIBE, UNSUBSCRIBE };

        Kind kind              = Kind::SUBSCRIBE;
        RuntimeEventSink* sink = nullptr;
        RuntimeInfoFilter filter;       ///< kind 为 SUBSCRIBE 时有效
        UnsubscribeAck* ack = nullptr;  ///< kind 为 UNSUBSCRIBE 时有效
    };

    /// @brief 取空命令队列并落地
    void land_commands();

    /// @brief 落地一条命令
    void land(Command& cmd);

    RuntimePipeline pipeline_;
    RuntimeEventDispatcher dispatcher_;

    /// 订阅命令队列：多生产者（任意线程）、单消费者（引擎线程）
    hng::NotificationQueue<Command> commands_;

    /// 停机标志：stop() 置位，run() 的循环条件；只由 stop() 写
    std::atomic<bool> stopped_{false};

    /// 以下计数只由引擎线程写、任意线程读，故为原子
    std::atomic<uint64_t> unsettled_events_{0};
    std::atomic<uint64_t> peak_cli_streams_{0};
    std::atomic<uint64_t> queue_rejected_{0};
};

#endif  // HNG_RUNTIME_ENGINE_HPP_
