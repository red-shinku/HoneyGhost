/**
 * @file role_discoverer.hpp
 * @brief 角色发现器的接口类
 * @author red_shinku
 * @date 2026.9.10
 */

#ifndef ROLE_DISCOVERER_HPP_
#define ROLE_DISCOVERER_HPP_

/**
 * @brief 角色发现器的接口类
 * 被所有监听在不同位置的角色发现器实现
 */
class RoleDiscoverer {
   public:
    virtual ~RoleDiscoverer() = default;

    /// @brief 发布角色的加入、退出事件
    virtual void publish()    = 0;
};

#endif  // ROLE_DISCOVERER_HPP_