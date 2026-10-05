/**
 * @file role_relation_store.hpp
 * @brief 角色关系表：进程归属、角色记录与实例索引
 * @details
 * 只做三张表的读写与落地规则。不持队列与线程、不做 IO，可独立单测；
 * 角色的进程成员集由调用方算好后喂入。
 * 写者只有消费线程，读者可多个：写入口取独占锁，查询入口取共享锁。
 * @author red_shinku
 * @date 2026.9.17
 */

#ifndef HNG_ROLE_RELATION_STORE_HPP_
#define HNG_ROLE_RELATION_STORE_HPP_

#include <cstdint>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "agent/role_discovery/include/role_event.hpp"
#include "agent/event_data/include/process.hpp"
#include "agent/event_data/include/role.hpp"

/**
 * @brief 一次落地产生的跃迁结果
 * @details 供调用方在 store 之外按下行出口通知，store 自身不通知。
 */
struct RoleTransition {
    enum class Kind {
        NONE,                 ///< 未产生跃迁：幂等重放、入口拒收、未知实例键
        JOINED,               ///< 角色新增
        LEFT,                 ///< 角色退出
        MAIN_PROCESS_CHANGED  ///< 同一 roleID 的锚点更换
    };

    Kind kind = Kind::NONE;
    hng::Role role;  ///< 跃迁后的对外视图，含重算过的 roleLabel；NONE 时无意义
};

/// @brief 异常态观测快照
/// @details 前三项为累计计数：单次读数说明不了问题，只在看增量时才有意义；
///          末项是当前值，两者读法不同，见各自说明。
struct RoleStoreStats {
    uint64_t rejected         = 0;  ///< 累计：入口拒收，缺实例键或锚点
    uint64_t unknown_instance = 0;  ///< 累计：LEAVE 或锚点更换遇未知实例键
    uint64_t owner_conflict   = 0;  ///< 累计：成员写入时已归属另一个角色
    /// 当前值非累计：锚点已被完全删除而角色未退出的角色数
    /// @note 锚点退出到 LEAVE 到达之间必然经过该状态，故它不为零不是错态；
    ///       持续为正、或增量长期不收敛才是。只按 on_process_removed 的到达
    ///       记账，锚点在角色建立前就已被删的情形无从得知
    uint64_t anchors_removed  = 0;
};

/// @brief 一个存活角色的全部记录
struct RoleRecord {
    hng::Role role;                    ///< 对外视图：roleID + roleLabel
    hng::role::RoleIdentity identity;  ///< 载荷原样保留，属性一旦丢弃不可恢复
    hng::Process main_process;         ///< 锚点：判重与判锚点更换
    std::string cgroup_path;           ///< 重枚举成员的凭据

    /// 归属表的反向索引，仅用于 LEAVE 时定向删除，不对外、不是角色成员集
    /// @invariant ⊇ 归属表中该 roleID 的全部键
    std::unordered_set<hng::Process> entries;

    /// 锚点已被完全删除而角色未退出，是 RoleStoreStats::anchors_removed
    /// 的记账依据
    /// @note 锚点更换时清除：此处说的是当时那个锚点
    bool anchor_removed = false;
};

class RoleRelationStore {
   public:
    RoleRelationStore() = default;

    /// @brief 角色加入
    /// @param payload 角色身份、锚点与 cgroup 路径
    /// @param members 成员集，调用方按 payload.member_processes ∪ cgroup 重读结果
    ///        ∪ {锚点} 算好后传入
    /// @return 新增角色为 JOINED；实例键已存在时归一：锚点相同为空操作、
    ///         锚点不同返回 MAIN_PROCESS_CHANGED
    /// @note 缺实例键或锚点时拒收，只计数
    RoleTransition join(const hng::role::RolePayload& payload,
                        const std::vector<hng::Process>& members);

    /// @brief 锚点更换：roleID 不变，记录字段被覆盖，成员并入不丢键
    /// @return 实例键未知或锚点未变时为空操作
    RoleTransition main_process_change(const hng::role::RolePayload& payload,
                                       const std::vector<hng::Process>& members);

    /// @brief 角色退出：按实例键取 roleID，再按反向索引定向删归属条目
    /// @return 实例键未知时为空操作
    RoleTransition leave(const std::string& instance_key);

    /// @brief 子进程继承父进程的角色归属
    /// @note 父进程未归属时丢弃；该事件不再补账，由后续 JOIN 的重读兜底
    void bind_to_role(hng::Process child, hng::Process parent);

    /// @brief 进程被完全删除：删其归属条目，不改变角色存在性
    /// @note 反向索引里的键留存，LEAVE 删时核对当前值即无副作用
    /// @note p 是该角色的锚点时把它计入 anchors_removed，
    ///       该角色退出或更换锚点后退出该计数
    void on_process_removed(hng::Process p);

    /// @brief 进程 → roleID；未归属时为空
    /// @note 归属条目与角色记录同生共死，命中即是在册角色
    std::optional<uint32_t> lookup(hng::Process p) const;

    /// @brief 角色的对外视图
    std::optional<hng::Role> role(uint32_t role_id) const;

    /// @brief 角色的身份：实例键、类型键、属性字典
    std::optional<hng::role::RoleIdentity> identity(uint32_t role_id) const;

    /// @brief 角色的 cgroup 路径；角色不存在时为空
    /// @note 供 RoleManager 重枚举成员用，不属于对外查询面
    std::optional<std::string> cgroup_path(uint32_t role_id) const;

    /// @brief 异常态观测快照
    RoleStoreStats stats() const;

   private:
    /// @brief 把 p 记为 role_id 的成员：写归属表并并进反向索引
    /// @note p 已归属别的角色时改判并计数（成员集是当下的枚举结果，比旧归属新）
    void adopt(uint32_t role_id, RoleRecord& record, hng::Process p);

    /// @brief 并入锚点与成员集
    /// @note 锚点无条件写入：成员集契约已含锚点，此处为「主进程自指」兜底
    void adopt_all(uint32_t role_id, RoleRecord& record, hng::Process anchor,
                   const std::vector<hng::Process>& members);

    /// @brief 锚点更换的落地，调用方须已持独占锁
    RoleTransition rebind_anchor(uint32_t role_id, RoleRecord& record,
                                 const hng::role::RolePayload& payload,
                                 const std::vector<hng::Process>& members);

    mutable std::shared_mutex mutex_;

    /// 归属索引，主进程自指
    std::unordered_map<hng::Process, uint32_t> process_to_role_;
    std::unordered_map<uint32_t, RoleRecord> role_table_;
    /// LEAVE 与锚点更换的入口
    std::unordered_map<std::string, uint32_t> instance_to_role_;

    /// roleID 从 1 起单调递增、永不复用；uint32_t 用尽不可达，不处理绕回
    uint32_t next_role_id_ = 1;

    RoleStoreStats stats_;
};

#endif  // HNG_ROLE_RELATION_STORE_HPP_
