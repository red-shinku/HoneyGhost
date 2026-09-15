/**
 * @file role_discoverer.hpp
 * @brief 角色发现器的接口类
 * @author red_shinku
 * @date 2026.9.10
 */

#ifndef ROLE_DISCOVERER_HPP_
#define ROLE_DISCOVERER_HPP_

#include "agent/control_plane/role_discovery/include/role_event.hpp"

/**
 * @brief 角色发现器的接口类
 * 被所有监听在不同位置的角色发现器实现
 */
class RoleDiscoverer {
   public:
    virtual ~RoleDiscoverer()                               = default;

    /// @brief 发布角色的加入、退出、主进程更换事件
    /// @param event 本次跃迁的事件载荷
    /// @note 在发现器 run() 的调用栈上同步调用；run() 返回后不再调用。
    virtual void publish(const hng::role::RoleEvent& event) = 0;
};

#endif  // ROLE_DISCOVERER_HPP_