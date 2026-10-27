/**
 * @file runtime_engine_component.hpp
 * @brief 运行时引擎组件的公共句柄、构造选项与观测类型。
 * @details 装配层经工厂构造并持有该句柄；流水线与分发实现仍在 src/。
 */

#ifndef HNG_RUNTIME_ENGINE_COMPONENT_HPP_
#define HNG_RUNTIME_ENGINE_COMPONENT_HPP_

#include <cstdint>
#include <memory>

#include "agent/runtime_engine/include/runtime_decision_sink.hpp"
#include "agent/runtime_engine/include/subscriber_reg_service.hpp"
#include "agent/util/include/component.hpp"

class ContextMaintainer;
class ProcessJoinService;
class ProcessUpdateService;
class RoleJoinService;
class RoleLookupService;

namespace hng {

template <class T>
class SPSC_Queue;

struct file_semantic_data;
struct syscall_semantic_data;

/** @brief 运行时引擎的观测快照 */
struct RuntimeEngineStats {
    /// 累计：归属未落定（roleID 或 contextID 为 0）的事件数，一条事件最多计一次
    uint64_t unsettled_events = 0;
    /// 峰值：CLI 订阅表同时存在的订阅流数
    uint64_t peak_cli_streams = 0;
    /// 累计：stop() 之后的订阅 / 注销命令入队被拒绝
    uint64_t queue_rejected   = 0;
};

/**
 * @brief 运行时引擎组件的构造选项。
 * @details 语义队列与控制平面服务均不拥有；队列为空表示该线未接线，维护器
 *          与服务须活到组件析构。
 */
struct RuntimeEngineOptions {
    /// 系统调用语义队列
    hng::SPSC_Queue<hng::syscall_semantic_data>* syscall_queue = nullptr;
    /// 文件语义队列
    hng::SPSC_Queue<hng::file_semantic_data>* file_queue       = nullptr;
    /// 上下文维护模块
    ContextMaintainer* ctx_maintainer                          = nullptr;
    /// 控制平面进程注册接口
    ProcessJoinService* process_join                           = nullptr;
    /// 控制平面进程镜像更新接口
    ProcessUpdateService* process_update                       = nullptr;
    /// 控制平面角色归属接口
    RoleJoinService* role_join                                 = nullptr;
    /// 控制平面角色查询接口
    RoleLookupService* role_lookup                             = nullptr;
};

/**
 * @brief 运行时引擎组件的公共句柄。
 * @details 转发订阅服务、系统 sink、统计与引擎线程；组件不持线程，线程由
 *          装配层创建并 join。
 * @note 构造后为 READY；run() 进入 RUNNING，stop() 置 STOPPED。在 STOPPED 上
 *       再次 run() 只落地已入队命令并清空订阅表，不进入 RUNNING；不支持并发
 *       的 run()。
 * @see hng::Component, RuntimeEngineOptions, RuntimeEngineFactory
 */
class RuntimeEngineComponent final : public hng::Component {
   public:
    ~RuntimeEngineComponent() override;

    RuntimeEngineComponent(const RuntimeEngineComponent&)            = delete;
    RuntimeEngineComponent& operator=(const RuntimeEngineComponent&) = delete;
    RuntimeEngineComponent(RuntimeEngineComponent&&)                 = delete;
    RuntimeEngineComponent& operator=(RuntimeEngineComponent&&)      = delete;

    /// @brief 订阅登记接口，供查询面使用
    SubscriberRegService& subscriber_service() noexcept;

    /// @brief 登记系统订阅者
    /// @param sink 空指针忽略；须存活到引擎停机
    /// @note 只可在 run() 之前调用；同一实现重复注册会收到重复投递
    void add_system_sink(RuntimeDecisionSink* sink);

    /// @brief 异常态观测快照；可从任意线程调用
    RuntimeEngineStats stats() const;

    /// @brief 当前生命周期状态
    /// @see hng::Component::state
    hng::ComponentState state() const override;

    /// @brief 组件线程入口
    /// @see hng::Component::run
    void run() override;

    /// @brief 停止组件
    /// @see hng::Component::stop
    void stop() override;

   private:
    struct Impl;

    explicit RuntimeEngineComponent(std::unique_ptr<Impl> impl);

    friend class RuntimeEngineFactory;

    std::unique_ptr<Impl> impl_;
};

}  // namespace hng

#endif  // HNG_RUNTIME_ENGINE_COMPONENT_HPP_
