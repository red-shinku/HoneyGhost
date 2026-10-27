/**
 * @file role_component.hpp
 * @brief 角色管理组件的公共句柄
 * @details 装配层经工厂构造并持有该句柄；具体 RoleManager 仍在 src/。
 * @author red_shinku
 * @date 2026.10.25
 */

#ifndef HNG_ROLE_COMPONENT_HPP_
#define HNG_ROLE_COMPONENT_HPP_

#include <chrono>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "agent/control_plane/include/process_lifecycle_sink.hpp"
#include "agent/control_plane/include/role_lifecycle_sink.hpp"
#include "agent/control_plane/include/role_seed_service.hpp"
#include "agent/control_plane/include/role_service.hpp"
#include "agent/control_plane/include/role_stats.hpp"
#include "agent/role_discovery/include/role_event_sink.hpp"
#include "agent/util/include/component.hpp"

namespace hng {

class ControlPlaneFactory;

/**
 * @brief 角色组件的注入点
 * @details 留空的字段使用真实实现；单元测试可注入替身以免依赖 cgroup 与
 *          /proc。
 */
struct RoleComponentOptions {
    /// @brief 按 cgroup 路径枚举成员；留空时读真实 cgroup
    std::function<std::vector<hng::Process>(const std::string&)> read_members;
    /// @brief 进程存活视图；留空表示存活未知，对账按未知保留
    std::function<bool(hng::Process)> is_exited;
};

/**
 * @brief 角色管理组件
 * @details 提供角色查询、归属继承、监管名单与初始化对账服务，并转发组件的
 *          生命周期。组件自身不持线程。
 * @see hng::Component
 */
class RoleComponent final : public hng::Component {
   public:
    ~RoleComponent() override;

    RoleComponent(const RoleComponent&)            = delete;
    RoleComponent& operator=(const RoleComponent&) = delete;

    /// @brief 角色归属查询服务
    /// @see RoleLookupService
    RoleLookupService& lookup_service() noexcept;

    /// @brief 角色归属继承服务
    /// @see RoleJoinService
    RoleJoinService& join_service() noexcept;

    /// @brief 监管名单写入服务
    /// @see RoleSupervisionService
    RoleSupervisionService& supervision_service() noexcept;

    /// @brief 角色初始落地后的对账服务
    /// @see RoleSeedService
    RoleSeedService& seed_service() noexcept;

    /// @brief 同步取空已入队的角色事件并落地
    /// @note 只在 run() 之前调用
    /// @see RoleManager::drain
    void drain();

    /// @brief 等待此前入队的角色事件全部落地
    /// @return 屏障任务已落地为 true；未运行、入队被拒或超时为 false
    /// @see RoleManager::barrier
    bool barrier(std::chrono::milliseconds timeout);

    /// @brief 进程退出的下游接收方
    /// @note 供进程管理组件的装配者登记，须存活到 run() 返回之后
    ProcessLifecycleSink& lifecycle_sink() noexcept;

    /// @brief 角色事件的入口
    /// @note 供发现器在 run() 之前同步投递初始角色事件；事件仍只入队，落地
    ///       须经 drain() 或 run()
    hng::role::RoleEventSink& event_sink() noexcept;

    /// @brief 注册角色生命周期订阅者
    /// @param sink 空指针忽略；同一实现重复注册会收到重复通知
    /// @note 只可在 run() 之前调用，此后不再变更
    void add_lifecycle_sink(RoleLifecycleSink* sink);

    /// @brief 异常态观测快照
    /// @see RoleManagerStats
    RoleManagerStats stats() const;

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

    explicit RoleComponent(std::unique_ptr<Impl> impl);

    friend class ControlPlaneFactory;

    std::unique_ptr<Impl> impl_;
};

}  // namespace hng

#endif  // HNG_ROLE_COMPONENT_HPP_
