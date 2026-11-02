/**
 * @file role_event.hpp
 * @brief 角色事件：跃迁的载荷与封装
 * @details 模块对外的可见面：消费方（角色事件出口的实现）只需认识本文件的类型。
 * @author red_shinku
 * @date 2026.9.15
 */

#ifndef HNG_ROLE_EVENT_HPP_
#define HNG_ROLE_EVENT_HPP_

#include <map>
#include <string>
#include <vector>

#include "agent/event_data/include/process.hpp"

namespace hng {
namespace role {

/**
 * @brief 角色来源
 * @details 决定下游由身份的哪个字段构造 roleLabel
 */
enum class RoleSource {
    UNSPECIFIED,  ///< 未声明来源
    SYSTEMD,      ///< systemd 单元
    CONTAINERD,   ///< containerd 容器
};

/**
 * @brief 角色身份
 * @details
 * 实例键是状态表去重所用的键，选择依据是「该键变化等价于换了一个实例」。
 * systemd 用 unit 名，容器用容器 ID。
 * 类型键供下游做聚合归类（如「nginx」）。
 * 其余身份信息全部落入属性字典：命名空间、标签、镜像引用、来源特有字段。
 */
struct RoleIdentity {
    std::string instance_key;                       ///< 实例键
    std::string type_key;                           ///< 类型键
    std::map<std::string, std::string> attributes;  ///< 属性字典
    RoleSource source = RoleSource::UNSPECIFIED;  ///< 来源：构造 roleLabel 的依据
};

/**
 * @brief 事件载荷
 * @details 角色身份 + 主进程锚点 + 进程补齐。锚点复用 hng::Process
 */
struct RolePayload {
    RoleIdentity identity;        ///< 角色身份
    hng::Process main_process{};  ///< 主进程锚点
    std::string cgroup_path;      ///< cgroup 路径，供下游重枚举补漏进程
    std::vector<hng::Process> member_processes;  ///< 加入瞬间 cgroup 内的全部进程
};

/**
 * @brief 状态表产出的动作
 * @details JOIN 与 LEAVE 是存在性跃迁，MAIN_PROCESS_CHANGE 是同一实例上的锚点
 * 跃迁。三者的语义互不合并
 */
enum class RoleAction {
    JOIN,                 ///< 不存在 → 存在
    LEAVE,                ///< 存在 → 不存在
    MAIN_PROCESS_CHANGE,  ///< 实例仍存在，主进程锚点发生变化
};

/**
 * @brief 状态表产出的事件
 * @details JOIN / MAIN_PROCESS_CHANGE 的载荷取自触发跃迁的观察量；LEAVE 的载荷
 * 取自状态表缓存，其 member_processes 为空——加入瞬间的成员列表在退出时刻已过期，
 * 下游若要重枚举应使用 cgroup_path。
 */
struct RoleEvent {
    RoleAction action;    ///< 本次跃迁的动作
    RolePayload payload;  ///< 该动作的事件载荷
};

}  // namespace role
}  // namespace hng

#endif  // HNG_ROLE_EVENT_HPP_
