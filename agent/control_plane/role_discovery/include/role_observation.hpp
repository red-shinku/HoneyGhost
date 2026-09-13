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
 * @brief 存在信号：源侧一次观察的结论
 * @details 三种信号。UNKNOWN 表示源侧取数失败或本次枚举未覆盖该实例：既不能读成
 * 存在，也不能读成不存在——把 取不到 压成 不存在 会让存活实例被判定退出，
 * 载荷缓存随之销毁，下游收到一对无法撤回的幻影退出/加入。
 * @note 未知的判定不做 errno 细分：/proc 读失败、解析失败、调用超时的后果
 * 都是 这一侧不知道 ，而 ENOENT 在 实例确已消失 与 这一侧的 /proc 不是
 * 宿主的 之间不可区分。
 */
enum class ObservationKind {
    PRESENT,  ///< 观察到实例存在
    ABSENT,   ///< 观察到实例不存在
    UNKNOWN,  ///< 取数失败或未被枚举覆盖，源侧无结论
};

/**
 * @brief 观察量：状态表的输入
 * @details 源侧一次观察的结果。存在观察必须携带当前锚点：既判定存在性跃迁，
 * 也判定锚点跃迁（实例仍存在，但主进程换了）。
 * 离开与未知观察只需 identity.instance_key 有值——源侧在实例消失后往往已经
 * 查不到其余字段，退出事件的载荷由状态表回查本地缓存补齐。
 * @pre kind 非 UNKNOWN 时 payload 的 identity.instance_key 非空
 */
struct RoleObservation {
    ObservationKind kind = ObservationKind::ABSENT;  ///< 存在信号
    /// 源内子范围标签
    /// @details 同一源的全部观察量按此标签分组，快照段的对账只清理落在本段
    /// 范围内的条目。容器源取 containerd namespace；systemd 源无子范围，留空。
    /// 离开与未知观察不参与分组，一律留空。
    std::string scope;
    RolePayload payload;  ///< kind 为 PRESENT 时有效
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
/// @param payload 实例身份、锚点与进程补齐
/// @param scope 该实例所属的源内子范围，见 RoleObservation::scope
inline RoleObservation observe_enter(RolePayload payload, std::string scope = {})
{
    RoleObservation observation;
    observation.kind    = ObservationKind::PRESENT;
    observation.scope   = std::move(scope);
    observation.payload = std::move(payload);
    return observation;
}

/// 构造离开观察量：源侧此刻只知实例键，其余字段无意义
inline RoleObservation observe_leave(const std::string& instance_key)
{
    RoleObservation observation;
    observation.kind                          = ObservationKind::ABSENT;
    observation.payload.identity.instance_key = instance_key;
    return observation;
}

/// 构造未知观察量：源侧对实例键无结论
inline RoleObservation observe_unknown(const std::string& instance_key)
{
    RoleObservation observation;
    observation.kind                          = ObservationKind::UNKNOWN;
    observation.payload.identity.instance_key = instance_key;
    return observation;
}

}  // namespace role
}  // namespace hng

#endif  // HNG_ROLE_OBSERVATION_HPP_
