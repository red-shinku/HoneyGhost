/**
 * @file role_lifecycle_sink.hpp
 * @brief 角色生命周期的下行出口
 * 需要角色生命周期通知的模块，可实现该接口，决定如何接受角色管理组件的通知。
 * @details 通过 RoleManager::add_lifecycle_sink 注册。
 * 三个动作与角色事件的三类动作一一对应，但携带的是 RoleManager 分配的
 * roleID，不是转发。
 * @author red_shinku
 * @date 2026.9.17
 */

#ifndef HNG_ROLE_LIFECYCLE_SINK_HPP_
#define HNG_ROLE_LIFECYCLE_SINK_HPP_

#include <cstdint>

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
    /// @brief 角色加入；此刻起 lookup 可命中该 roleID
    virtual void on_role_joined(uint32_t roleID)               = 0;

    /// @brief 角色退出；此刻起该 roleID 一律失配
    virtual void on_role_left(uint32_t roleID)                 = 0;

    /// @brief 锚点更换；roleID 不变
    virtual void on_role_main_process_changed(uint32_t roleID) = 0;
};

#endif  // HNG_ROLE_LIFECYCLE_SINK_HPP_
