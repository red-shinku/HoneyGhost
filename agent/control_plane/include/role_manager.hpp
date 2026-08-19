/**
 * @file role_manager.hpp
 * @brief 控制平面的角色管理器组件
 * @author red_shinku
 * @date 2026.8.18
 */

#ifndef _CONTROL_PLANE_ROLEMANAGER_HPP
#define _CONTROL_PLANE_ROLEMANAGER_HPP

#include <cstdint>
#include <unordered_map>
#include <memory>

#include "role.hpp"

class RoleManager {
   public:
    RoleManager();
    ~RoleManager();

    void unregister_role();

   private:
    std::unordered_map<uint16_t, std::unique_ptr<Role>> role;

    void addrole();
    void deleterole();
};

#endif  //_CONTROL_PLANE_ROLEMANAGER_HPP