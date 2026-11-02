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
#include "agent/runtime_engine/include/runtime_engine_component.hpp"
#include "agent/runtime_engine/include/subscriber_reg_service.hpp"
#include "agent/runtime_engine/src/runtime_event_dispatcher.hpp"
#include "agent/runtime_engine/src/runtime_pipeline.hpp"
#include "agent/util/include/event_loop.hpp"
#include "agent/util/include/event_wakeup.hpp"
#include "agent/util/include/notification_queue.hpp"

namespace hng {
template <class T>
class EventChannelReader;
struct file_semantic_data;
struct syscall_semantic_data;
}  // namespace hng

/**
 * @brief 驱动语义事件流、向订阅者分发的顶层组件
 * @details 持有流水线与分发器，语义通道的唯一读者，也是控制平面通知的驱动者。
 * 线程模型为串行单线程：每轮先落地订阅命令、再取至多 kMaxEventsPerWake 条事件
 * 分发；所有输入取空后阻塞在事件循环上，由写入方唤醒。
 * @note 语义通道、ContextMaintainer 与控制平面服务均不拥有；通道读端为空指针
 * 表示未接线。析构前 run() 须已返回。
 */
class RuntimeEngine final : public SubscriberRegService {
   public:
    /// @param syscall_input 系统调用语义通道读端，未接线传 nullptr
    /// @param file_input 文件语义通道读端，未接线传 nullptr
    /// @param ctx_maintainer 上下文维护模块，非拥有
    /// @param process_join 控制平面进程注册接口，非拥有
    /// @param process_update 控制平面进程镜像更新接口，非拥有
    /// @param role_join 控制平面角色归属接口，非拥有
    /// @param role_lookup 控制平面角色查询接口，非拥有
    /// @throws std::system_error 事件循环或命令唤醒 fd 创建失败
    RuntimeEngine(
        hng::EventChannelReader<hng::syscall_semantic_data>* syscall_input,
        hng::EventChannelReader<hng::file_semantic_data>* file_input,
        ContextMaintainer* ctx_maintainer, ProcessJoinService* process_join,
        ProcessUpdateService* process_update, RoleJoinService* role_join,
        RoleLookupService* role_lookup);

    /// @brief 登记系统订阅者
    /// @param sink 空指针忽略；须存活到引擎停机
    /// @note 只可在 run() 之前调用；同一实现重复注册会收到重复投递
    void add_system_sink(RuntimeDecisionSink* sink);

    /// @brief 引擎线程入口：分发语义事件与订阅命令，直至 stop()
    /// @note 不持线程，线程由装配方创建；析构前须已返回
    void run();

    /// @brief 停止：此后不再取事件，命令入队一律被拒
    /// @note 幂等，可从任意线程调用；已入队的命令仍会落地，run() 在排空命令、
    ///       已入队事件与订阅表之后返回
    void stop();

    /// @brief 登记一路订阅流：入队即返回，落地在引擎线程上
    /// @note 落地前产生的事件不补发；重复登记以最后一次的过滤器与回执为准
    bool subscribe(RuntimeEventSink* sink, RuntimeInfoFilter filter,
                   UnsubscribeAck* ack) override;

    /// @brief 注销一路订阅流：入队即返回，落地在引擎线程上
    /// @note 入队被拒只记账，不改变回执保证：停机清表时该流仍会收到回执
    void unsubscribe(RuntimeEventSink* sink) override;

    /// @brief 异常态观测快照；可从任意线程调用
    hng::RuntimeEngineStats stats() const;

   private:
    /// 一轮取事件的产物槽位数：每条已接线队列每轮至多产出一条
    static constexpr std::size_t kMaxDraftsPerRound = 4;

    /// 一次唤醒内最多分发的事件数：用尽即回到命令排空，使订阅命令的落地延迟
    /// 有上界
    static constexpr std::size_t kMaxEventsPerWake  = 256;

    /// 就绪源的标识，与事件循环的停机 tag 不冲突
    static constexpr std::uint64_t kCommandTag      = 1;
    static constexpr std::uint64_t kSyscallTag      = 2;
    static constexpr std::uint64_t kFileTag         = 3;

    /// @brief 订阅命令；两张表分别对应两个 kind
    struct Command {
        enum class Kind { SUBSCRIBE, UNSUBSCRIBE };

        Kind kind              = Kind::SUBSCRIBE;
        RuntimeEventSink* sink = nullptr;
        RuntimeInfoFilter filter;       ///< kind 为 SUBSCRIBE 时有效
        UnsubscribeAck* ack = nullptr;  ///< kind 为 SUBSCRIBE 时有效，可为空
    };

    /// @brief 把各唤醒源登记进事件循环
    /// @throws std::system_error 登记失败或超过事件循环的源上限
    void register_sources();

    /// @brief 取一个命令；取空时交还命令唤醒权并复查
    bool next_command(Command& cmd);

    /// @brief 取空命令队列并落地
    void land_commands();

    /// @brief 落地一条命令
    void land(Command& cmd);

    /// @brief 分发事件，直到两条输入都取空或达到 kMaxEventsPerWake
    /// @param[out] drafts 本轮产物，槽位数不得少于 kMaxDraftsPerRound
    /// @return 本次分发的事件数；0 表示输入已取空
    std::size_t drain_events(RuntimeDraft* drafts);

    RuntimePipeline pipeline_;
    RuntimeEventDispatcher dispatcher_;

    /// 引擎线程的等待与停机唤醒
    hng::EventLoop loop_;

    /// 命令入队的唤醒源：命令入队后由生产方通知
    hng::EventWakeup commands_wakeup_;

    /// 订阅命令队列：多生产者（任意线程）、单消费者（引擎线程）
    hng::NotificationQueue<Command> commands_;

    /// 停机标志：stop() 置位，run() 的循环条件；只由 stop() 写
    std::atomic<bool> stopped_{false};

    /// 以下计数只由引擎线程写、任意线程读，故为原子
    std::atomic<uint64_t> unsettled_events_{0};
    std::atomic<uint64_t> peak_cli_streams_{0};
    std::atomic<uint64_t> queue_rejected_{0};
    std::atomic<uint64_t> idle_waits_{0};
};

#endif  // HNG_RUNTIME_ENGINE_HPP_
