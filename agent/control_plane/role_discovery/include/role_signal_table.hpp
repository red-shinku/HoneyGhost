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
 * 快照段（begin_snapshot / end_snapshot）是一次对账而非「喂一批观察量」：
 * 段内未再出现的存活项按退出处理。只喂不结算则断开期间退出的角色会永远留在
 * 表里成为幽灵角色——重连重放的快照覆盖不到退出方向。
 * 本表只认识观察量，不认识任何源特有的消息类型。
 * @author red_shinku
 * @date 2026.9.11
 */

#ifndef HNG_ROLE_SIGNAL_TABLE_HPP_
#define HNG_ROLE_SIGNAL_TABLE_HPP_

#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "agent/control_plane/role_discovery/include/role_observation.hpp"

namespace hng {
namespace role {

/**
 * @brief 角色存活状态表
 * @details 以实例键为键维护存活标记与已发布实例的载荷缓存。退出时源侧往往已经
 * 查不到属性了，退出事件的载荷必须回查缓存，不能实时向源索取。
 * 另记快照代际：快照段是一次对账，段内未再出现的存活项按退出处理。
 * 非线程安全，由持有它的发现器线程独占访问。
 */
class RoleSignalTable {
   public:
    /// 喂入观察量并判定跃迁
    /// @details 根据跃迁会增删条目。快照段内被命中的条目一律刷成当代际——
    /// 段内到达的流内观察比枚举结果新，让它与枚举项一样幸存、不被对账清掉。
    /// @param observation 源侧一次观察的结果
    /// @return
    /// 发生跃迁时返回对应事件；重复观察、未知观察与未知实例的离开观察返回空
    std::optional<RoleEvent> submit(const RoleObservation& observation);

    /// 该实例键当前是否存活
    bool is_alive(const std::string& instance_key) const;

    /// 取存活实例的载荷缓存
    /// @return 实例不存活时为空
    std::optional<RolePayload> lookup(const std::string& instance_key) const;

    /// 开启快照段
    /// @details 递增代际并记下本段范围。已有未结算段时调用即作废上一段：
    /// 上一段的枚举结果不再被信赖，不产出任何退出。
    /// @param scope 本段确实完整枚举的源内子范围；空表示表的整个域
    void begin_snapshot(const std::vector<std::string>& scope = {});

    /// 结算本段：把范围内未在本段出现的存活项按退出清除
    /// @details 范围外的条目不动——某个子范围没被本段枚举时，其条目既非
    /// 「已退出」也非「已确认」，只能等覆盖它的那一段。未开启快照段时无动作。
    /// @return 各退出事件，按实例键升序，顺序确定
    std::vector<RoleEvent> end_snapshot();

   private:
    /// 一个存活条目的全部状态
    struct Entry {
        RolePayload payload;  ///< 载荷缓存
        uint64_t generation;  ///< 最近一次命中它的快照段代际
        std::string scope;    ///< 入表时所属的源内子范围，此后不再改变
    };

    /// 条目是否落在本段范围内
    bool in_current_scope(const Entry& entry) const;

    std::unordered_map<std::string, Entry> alive_;  ///< 实例键 → 存活条目
    uint64_t generation_ = 0;                       ///< 当前代际
    bool snapshot_open_  = false;                   ///< 是否有未结算的段
    std::vector<std::string> scope_;                ///< 未结算段的范围
};

}  // namespace role
}  // namespace hng

#endif  // HNG_ROLE_SIGNAL_TABLE_HPP_
