/**
 * @file role_observation.hpp
 * @brief 观察量与状态表产出的事件
 * @details 状态表输入输出的纯数据结构。观察量是模块内部类型——它携带的
 * 三态存在信号（见 ObservationKind）只对状态表有意义，下游只认识事件，
 * 故事件一侧的类型单独放在 role_event.hpp。
 * @author red_shinku
 * @date 2026.9.11
 */

#ifndef HNG_ROLE_OBSERVATION_HPP_
#define HNG_ROLE_OBSERVATION_HPP_

#include <string>

#include "agent/role_discovery/include/role_event.hpp"
#include "agent/event_data/include/process.hpp"

namespace hng {
namespace role {

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
    /// 观察到的载荷，kind 为 PRESENT 时有效
    /// @note 与事件载荷是同一份数据：跃迁时原样成为事件的载荷
    RolePayload payload;
};

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
