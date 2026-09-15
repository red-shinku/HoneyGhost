/**
 * @file role_manager.hpp
 * @brief 控制平面的角色管理器组件
 * @author red_shinku
 * @date 2026.8.18
 */

#ifndef _CONTROL_PLANE_ROLEMANAGER_HPP
#define _CONTROL_PLANE_ROLEMANAGER_HPP

#include <unordered_map>
#include <shared_mutex>

#include "agent/event_data/role.hpp"
#include "agent/event_data/process.hpp"

/// @brief 角色的主 Process 到其 roleID 的映射表
struct MainProcessToRoleMap {
    mutable std::shared_mutex smtx;

    std::unordered_map<hng::Process, uint16_t> roleID;
};

/// @brief 进程到其所属角色的主进程的映射表
struct ToMainProcessTable {
    mutable std::shared_mutex smtx;
    std::unordered_map<hng::Process, hng::Process> mainProcess;
};

/// @brief roleID 到 hng::Role 的映射表
struct RoleTable {
    mutable std::shared_mutex smtx;
    std::unordered_map<uint16_t, hng::Role> role;
};

class RoleManager {
   public:
    RoleManager();
    ~RoleManager();

    void unregister_role();

   private:
    ToMainProcessTable to_mainprocess;

    MainProcessToRoleMap roleID;

    RoleTable roletable;

    void addrole();
    void deleterole();
};

#endif  //_CONTROL_PLANE_ROLEMANAGER_HPP