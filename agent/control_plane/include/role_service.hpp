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

#include "agent/control_plane/include/role_stats.hpp"
#include "agent/role_discovery/include/role_event.hpp"
#include "agent/event_data/include/process.hpp"
#include "agent/event_data/include/role.hpp"

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

    /// @brief 角色的当前锚点；角色不存在或锚点已退出时为空
    virtual std::optional<hng::Process> main_process(
        uint32_t roleID) const = 0;

    /// @brief 全部角色的快照，按 roleID 升序
    virtual std::vector<hng::Role> roles() const = 0;

    /// @brief 当前被系统监管的角色快照，按 roleID 升序
    virtual std::vector<hng::Role> supervised_roles() const = 0;

    /// @brief 角色的身份：实例键、类型键、属性字典与来源
    /// @note 供角色标签维护与日志打印 TODO: 也许不该做这个接口
    virtual std::optional<hng::role::RoleIdentity> identity(
        uint32_t roleID) const                                       = 0;

    /// @brief 按 cgroup 实时重枚举该角色的当前进程
    /// @note 锚点见 main_process()；不是任何内部缓存；路径不可读时返回已收集
    ///       结果，调用方不得把空结果读成「没有成员」
    virtual std::vector<hng::Process> members(uint32_t roleID) const = 0;

    /// @brief 异常态观测快照
    virtual RoleManagerStats stats() const = 0;
};

/// @brief 监管名单的写入侧
/// @details 由用户态角色过滤模块在策略判定后调用；RoleManager 实现。
///          角色退出时 RoleManager 自动移除登记，调用方无需处理退出。
class RoleSupervisionService {
   protected:
    virtual ~RoleSupervisionService() = default;

   public:
    /// @brief 登记或移除一个系统监管角色
    /// @param roleID 目标角色；不存在时忽略
    /// @param supervised true 登记，false 移除
    virtual void set_supervised(uint32_t roleID, bool supervised) = 0;
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

#endif  // HNG_ROLE_SERVICE_HPP_
