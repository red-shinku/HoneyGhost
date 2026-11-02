/**
 * @file process_component.hpp
 * @brief 进程管理组件的公共句柄
 * @details 装配层经工厂构造并持有该句柄；具体 ProcessManager 仍在 src/。
 * @author red_shinku
 * @date 2026.10.25
 */

#ifndef HNG_PROCESS_COMPONENT_HPP_
#define HNG_PROCESS_COMPONENT_HPP_

#include <memory>

#include "agent/control_plane/include/process_lifecycle_sink.hpp"
#include "agent/control_plane/include/process_seed_service.hpp"
#include "agent/control_plane/include/process_service.hpp"
#include "agent/control_plane/include/process_stats.hpp"
#include "agent/control_plane/include/role_service.hpp"
#include "agent/util/include/component.hpp"

namespace hng {

class ControlPlaneFactory;

/**
 * @brief 进程管理组件
 * @details 提供进程查询、注册、更新与存活视图的服务接口，并转发组件的生命
 *          周期。组件自身不持线程。
 * @see hng::Component
 */
class ProcessComponent final : public hng::Component {
   public:
    ~ProcessComponent() override;

    ProcessComponent(const ProcessComponent&)            = delete;
    ProcessComponent& operator=(const ProcessComponent&) = delete;

    /// @brief 进程查询服务
    /// @see ProcessLookupService
    ProcessLookupService& lookup_service() noexcept;

    /// @brief 进程注册服务
    /// @see ProcessJoinService
    ProcessJoinService& join_service() noexcept;

    /// @brief 进程镜像更新服务
    /// @see ProcessUpdateService
    ProcessUpdateService& update_service() noexcept;

    /// @brief 进程存活视图
    /// @see ProcessLivenessService
    ProcessLivenessService& liveness_service() noexcept;

    /// @brief 进程树初始化写入服务
    /// @see ProcessSeedService
    ProcessSeedService& seed_service() noexcept;

    /// @brief 注册进程生命周期订阅者
    /// @param sink 空指针忽略；须存活到 run() 返回之后
    /// @note 只可在 run() 之前调用，此后不再变更
    void add_process_lifecycle_sink(ProcessLifecycleSink* sink);

    /// @brief 注入角色归属接口依赖（可空）
    void set_role_join_service(RoleJoinService* service);

    /// @brief 异常态观测快照
    /// @see ProcessManagerStats
    ProcessManagerStats stats() const;

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

    explicit ProcessComponent(std::unique_ptr<Impl> impl);

    friend class ControlPlaneFactory;

    std::unique_ptr<Impl> impl_;
};

}  // namespace hng

#endif  // HNG_PROCESS_COMPONENT_HPP_
