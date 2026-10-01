/**
 * @file role_event_sink.hpp
 * @brief 角色事件的下游接收接口。
 * 该接口由各发现器持有、角色管理器实现。
 * @author red_shinku
 * @date 2026.9.15
 */

#ifndef HNG_ROLE_EVENT_SINK_HPP_
#define HNG_ROLE_EVENT_SINK_HPP_

#include "agent/role_discovery/include/role_event.hpp"

namespace hng {
namespace role {

/**
 * @brief 角色事件的下游接收方
 * @details 由消费方实现。发现器只依赖本接口，不感知消费方的类型与数量。
 * 出口是推送：事件由发现器主动送出，没有实现方就构造不出发现器。
 */
class RoleEventSink {
   protected:
    /// @note 析构为 protected：消费方自持其实现，发现器不接管它的生命周期
    virtual ~RoleEventSink() = default;

   public:
    /// @brief 接收一个角色事件
    /// @param event 本次跃迁的载荷
    /// @note 由发现器在其 run() 的调用栈上同步调用，run() 返回后不再调用。
    /// 实现方必须尽快返回：本调用跑在发现器线程上（同步）
    virtual void on_role_event(const RoleEvent& event) = 0;
};

}  // namespace role
}  // namespace hng

#endif  // HNG_ROLE_EVENT_SINK_HPP_
