/**
 * @file role_discovery_component.hpp
 * @brief 角色发现组件的公共句柄与两种发现源的构造选项。
 * @details 装配层经工厂构造并持有该句柄；发现器实现仍在 src/。
 */

#ifndef HNG_ROLE_DISCOVERY_COMPONENT_HPP_
#define HNG_ROLE_DISCOVERY_COMPONENT_HPP_

#include <chrono>
#include <memory>
#include <string>

#include "agent/util/include/component.hpp"

namespace hng {

/// @brief systemd 发现源的构造选项
struct SystemdSourceOptions {
    /// @brief 周期快照间隔，0 表示不做
    /// @details 对账只在快照段结束时发生，周期快照给幽灵存活期设上界
    std::chrono::milliseconds snapshot_interval{600000};
};

/// @brief containerd 发现源的构造选项
struct ContainerdSourceOptions {
    /// @brief 翻译进程的 Unix socket 路径
    std::string socket_path = "/run/honeyghost/containerd-bridge.sock";
};

class RoleDiscoveryFactory;

/**
 * @brief 角色发现组件的公共句柄。
 * @details 包装一个发现源（systemd 或 containerd），转发其阻塞运行与停止，
 *          不感知源的种类；组件不持线程，线程由装配层创建并 join。
 * @note 构造后为 READY；run() 进入 RUNNING 并阻塞到源返回，返回后置 STOPPED。
 *       状态不是 READY 时 run() 立即返回；不支持并发的 run()。
 * @see hng::Component, RoleDiscoveryFactory
 */
class RoleDiscoveryComponent final : public hng::Component {
   public:
    ~RoleDiscoveryComponent() override;

    RoleDiscoveryComponent(const RoleDiscoveryComponent&)            = delete;
    RoleDiscoveryComponent& operator=(const RoleDiscoveryComponent&) = delete;
    RoleDiscoveryComponent(RoleDiscoveryComponent&&)                 = delete;
    RoleDiscoveryComponent& operator=(RoleDiscoveryComponent&&)      = delete;

    /// @brief 当前生命周期状态
    /// @see hng::Component::state
    hng::ComponentState state() const override;

    /// @brief 组件线程入口：阻塞到发现源返回
    /// @see hng::Component::run
    void run() override;

    /// @brief 请求发现源返回；幂等
    /// @see hng::Component::stop
    void stop() override;

   private:
    struct Impl;

    explicit RoleDiscoveryComponent(std::unique_ptr<Impl> impl);

    friend class RoleDiscoveryFactory;

    std::unique_ptr<Impl> impl_;
};

}  // namespace hng

#endif  // HNG_ROLE_DISCOVERY_COMPONENT_HPP_
