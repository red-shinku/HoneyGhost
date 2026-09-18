/**
 * @file role_service.hpp
 * @brief 控制平面中角色相关的对外服务接口
 * @details 查询面供任意线程只读调用；两个写接口是通知写：入队即返回，落地在
 * RoleManager 的消费线程上。role_manager.hpp 中 RoleManager 实现了这三个接口。
 * @author red_shinku
 * @date 2026.9.17
 */

#ifndef HNG_ROLE_SERVICE_HPP_
#define HNG_ROLE_SERVICE_HPP_

#include <cstdint>
#include <optional>
#include <vector>

#include "agent/control_plane/role_discovery/include/role_event.hpp"
#include "agent/event_data/process.hpp"
#include "agent/event_data/role.hpp"

/// @brief 角色归属的查询接口
class RoleLookupService {
   protected:
    virtual ~RoleLookupService() = default;

   public:
    /// @brief 进程 → roleID；未归属、或归属的角色已退出时为空
    /// @note 事件路径上的高频入口
    virtual std::optional<uint32_t> lookup(hng::Process p) const = 0;

    /// @brief 角色的对外视图：roleID + roleLabel
    virtual std::optional<hng::Role> role(uint32_t roleID) const = 0;

    /// @brief 角色的身份：实例键、类型键、属性字典
    /// @note 供角色标签维护与日志打印
    virtual std::optional<hng::role::RoleIdentity> identity(
        uint32_t roleID) const                                       = 0;

    /// @brief 按 cgroup 实时重枚举该角色的当前进程（含主进程）
    /// @note 不是任何内部缓存；路径不可读时返回已收集结果，调用方不得把空结果
    ///       读成「没有成员」
    virtual std::vector<hng::Process> members(uint32_t roleID) const = 0;
};

/// @brief 进程结构事实 → 角色归属
class RoleJoinService {
   protected:
    virtual ~RoleJoinService() = default;

   public:
    /// @brief 子进程继承父进程的角色归属
    /// @note 父进程未归属时丢弃该次通知
    virtual void bind_to_role(hng::Process child, hng::Process parent) = 0;
};

/// @brief 归属数据的清理
class RoleClearService {
   protected:
    virtual ~RoleClearService() = default;

   public:
    /// @brief 进程被完全删除
    /// @note 只清理该进程的归属条目，不改变角色的存在性
    virtual void on_process_removed(hng::Process p) = 0;
};

#endif  // HNG_ROLE_SERVICE_HPP_
