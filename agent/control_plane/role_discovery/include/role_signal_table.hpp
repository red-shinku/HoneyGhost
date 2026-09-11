/**
 * @file role_signal_table.hpp
 * @brief 角色存活状态表与跃迁判定
 * @details
 * 定义观察量为：hng::role::RoleObservation
 * 一切观察量先过本表，只在状态跃迁时产出事件：重复的、乱序的、源重连后重放的
 * 观察量都不产生多余事件。因此重连策略可以退化成「无条件重新快照并重新订阅」，
 * 不必存断点，也不必处理重复投递。
 * 定义锚点为：hng::Process，角色的锚点即该角色的主进程
 * 判定两类状态跃迁：存在性跃迁与锚点跃迁。前者是不存在→存在（产出 JOIN）、
 * 存在→不存在（产出 LEAVE），后者是实例仍存在但锚点变化（产出
 * MAIN_PROCESS_CHANGE）。
 * 本表只认识观察量，不认识任何源特有的消息类型。
 * @author red_shinku
 * @date 2026.9.11
 */

#ifndef HNG_ROLE_SIGNAL_TABLE_HPP_
#define HNG_ROLE_SIGNAL_TABLE_HPP_

#include <optional>
#include <string>
#include <unordered_map>

#include "agent/control_plane/role_discovery/include/role_observation.hpp"

namespace hng {
namespace role {

/**
 * @brief 角色存活状态表
 * @details 以实例键为键维护存活标记与已发布实例的载荷缓存。退出时源侧往往已经
 * 查不到属性了，退出事件的载荷必须回查缓存，不能实时向源索取。
 * 非线程安全，由持有它的发现器线程独占访问。
 */
class RoleSignalTable {
   public:
    /// 喂入观察量并判定跃迁
    /// @details 根据跃迁会增删 alive_
    /// @param observation 源侧一次观察的结果
    /// @return 发生跃迁时返回对应事件；重复观察与未知实例的离开观察返回空
    std::optional<RoleEvent> submit(const RoleObservation& observation);

    /// 该实例键当前是否存活
    bool is_alive(const std::string& instance_key) const;

    /// 取存活实例的载荷缓存
    /// @return 实例不存活时为空
    std::optional<RolePayload> lookup(const std::string& instance_key) const;

   private:
    std::unordered_map<std::string, RolePayload> alive_;  ///< 实例键 → 载荷
};

}  // namespace role
}  // namespace hng

#endif  // HNG_ROLE_SIGNAL_TABLE_HPP_
