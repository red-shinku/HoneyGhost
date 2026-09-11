/**
 * @file role_observation.hpp
 * @brief 角色身份、事件载荷、观察量与状态表产出的事件
 * @details 状态表的输入与输出的纯数据结构。
 * @author red_shinku
 * @date 2026.9.11
 */

#ifndef HNG_ROLE_OBSERVATION_HPP_
#define HNG_ROLE_OBSERVATION_HPP_

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "agent/event_data/process.hpp"

namespace hng {
namespace role {

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
 * @brief 观察量：状态表的输入
 * @details 源侧一次观察的结果。存在信号与当前锚点必须同时携带：前者判定存在性
 * 跃迁，后者判定锚点跃迁（实例仍存在，但主进程换了）。
 * 离开观察只需 identity.instance_key 有值——源侧在实例消失后往往已经查不到其余
 * 字段，退出事件的载荷由状态表回查本地缓存补齐。
 * @pre present 为 true 时 payload 的 identity.instance_key 非空
 */
struct RoleObservation {
    bool present = false;  ///< 存在信号：源侧此刻是否观察到该实例
    RolePayload payload;   ///< present 为 true 时有效
};

/**
 * @brief 状态表产出的动作
 * @details JOIN 与 LEAVE 是存在性跃迁，MAIN_PROCESS_CHANGE 是同一实例上的锚点
 * 跃迁。后者如何表达给下游（独立事件类型，或展开为「退出 + 加入」并带标记）由
 * 下游契约决定，展开动作在出口做，不影响本枚举。
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

/// 锚点比较：pid 与 pid_start_time 均相同才算同一进程
inline bool same_process(const hng::Process& a, const hng::Process& b)
{
    return a.pid == b.pid && a.pid_start_time == b.pid_start_time;
}

/// 构造进入观察量
inline RoleObservation observe_enter(RolePayload payload)
{
    RoleObservation observation;
    observation.present = true;
    observation.payload = std::move(payload);
    return observation;
}

/// 构造离开观察量：源侧此刻只知实例键，其余字段无意义
inline RoleObservation observe_leave(const std::string& instance_key)
{
    RoleObservation observation;
    observation.present                       = false;
    observation.payload.identity.instance_key = instance_key;
    return observation;
}

}  // namespace role
}  // namespace hng

#endif  // HNG_ROLE_OBSERVATION_HPP_
