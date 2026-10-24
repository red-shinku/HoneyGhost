/**
 * @file role_lifecycle_sink.hpp
 * @brief 角色生命周期的下行出口
 * 需要角色生命周期通知的模块，可实现该接口，决定如何接受角色管理组件的通知。
 * @details 通过 RoleManager::add_lifecycle_sink 注册。
 * 三个生命周期动作与角色事件的三类动作一一对应，但携带的是 RoleManager 分配的
 * hng::Role（roleID + roleLabel），不是转发。成员新增是独立于生命周期的通知，
 * 供订阅方增量维护自己的进程名单。
 * @author red_shinku
 * @date 2026.9.17
 */

#ifndef HNG_ROLE_LIFECYCLE_SINK_HPP_
#define HNG_ROLE_LIFECYCLE_SINK_HPP_

#include <vector>

#include "agent/event_data/include/process.hpp"
#include "agent/event_data/include/role.hpp"

/**
 * @brief 角色生命周期的下游接收方
 * @warning 接口的实现不可阻塞
 * @note 一个 RoleManager 上可注册多个实现，同一次跃迁按注册顺序通知到每个实现
 */
class RoleLifecycleSink {
   protected:
    /// @note 析构为 protected：下游自持其实现，RoleManager 不接管它的生命周期
    virtual ~RoleLifecycleSink() = default;

   public:
    /// @brief 角色加入；此刻起 lookup 可命中该 role.roleID
    virtual void on_role_joined(const hng::Role& role)               = 0;

    /// @brief 角色退出；此刻起该 role.roleID 一律失配
    virtual void on_role_left(const hng::Role& role)                 = 0;

    /// @brief 锚点更换；role.roleID 不变，roleLabel 可能被重算
    virtual void on_role_main_process_changed(const hng::Role& role) = 0;

    /**
     * @brief 角色成员集新增
     * @param[in] role 变化后的角色视图
     * @param[in] added 本次新归属该角色的进程，至少一个
     * @warning 接口的实现不可阻塞
     * @note 通知只表示成员集扩大；移除不在此通知，订阅方须按存活核对或角色
     *       退出自行收敛。
     * @note 角色加入或锚点更换的落地可能先产生对应的生命周期通知，再产生本通知。
     */
    virtual void on_role_members_changed(
        const hng::Role& role, const std::vector<hng::Process>& added) = 0;
};

#endif  // HNG_ROLE_LIFECYCLE_SINK_HPP_
