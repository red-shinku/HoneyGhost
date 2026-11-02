/**
 * @file role_relation_store.hpp
 * @brief 角色关系表：进程归属、角色记录与实例索引
 * @details
 * 只做三张表的读写与落地规则。不持队列与线程、不做 IO，可独立单测；
 * 角色的进程成员集由调用方算好后喂入。另以等待表暂存先到的 fork 继承关系、
 * 以墓碑拒绝已退出进程的迟到写入；两张表与三张表同锁保护。
 * 写者只有消费线程，读者可多个：写入口取独占锁，查询入口取共享锁。
 * @author red_shinku
 * @date 2026.9.17
 */

#ifndef HNG_ROLE_RELATION_STORE_HPP_
#define HNG_ROLE_RELATION_STORE_HPP_

#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <variant>
#include <vector>

#include "agent/control_plane/include/role_stats.hpp"
#include "agent/role_discovery/include/role_event.hpp"
#include "agent/event_data/include/process.hpp"
#include "agent/event_data/include/role.hpp"
#include "agent/util/include/deferred_relation_table.hpp"
#include "agent/util/include/tombstone_table.hpp"

/**
 * @brief 一次落地新增的成员归属，按角色分组
 * @details 供调用方在 store 之外对每个角色通知新增成员，store 自身不通知。
 */
struct RoleMemberChanges {
    struct Entry {
        uint32_t role_id = 0;               ///< 成员所属角色
        std::vector<hng::Process> members;  ///< 新归属该角色的进程
    };

    std::vector<Entry> entries;  ///< 同一角色至多一项

    /// @brief 记录 p 新归属 role_id；该角色无记录时新建一项
    void add(uint32_t role_id, hng::Process p);
};

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
    /// 本次落地新增的成员归属；与 kind 无关，无新增时为空
    RoleMemberChanges members;
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

    /// 锚点已退出而角色未退出，是 RoleStoreStats::anchors_removed
    /// 的记账依据
    /// @note 锚点更换时清除：此处说的是当时那个锚点
    bool anchor_removed = false;
};

/// @brief 角色关系表接收的关系修复配置
/// @details 默认值可直接运行；测试通过覆盖参数注入假时钟与小容量、短寿命。
struct RoleRelationOptions {
    hng::DeferredRelationOptions bind_pending;  ///< fork 继承的等待表
    hng::TombstoneOptions tombstones;           ///< 已退出进程墓碑表
    /// 当前时间来源，必须是单调时钟
    std::function<hng::RelationTimePoint()> now = [] {
        return std::chrono::steady_clock::now();
    };
};

class RoleRelationStore {
   public:
    /// @param options 等待表、墓碑表与时钟
    explicit RoleRelationStore(RoleRelationOptions options = {});

    /// @brief 角色加入
    /// @param payload 角色身份、锚点与 cgroup 路径
    /// @param members 成员集，调用方按 payload.member_processes ∪ cgroup 重读结果
    ///        ∪ {锚点} 算好后传入
    /// @return 新增角色为 JOINED；实例键已存在时归一：锚点相同仍按本次成员集
    ///         修正归属并返回 NONE，锚点不同返回 MAIN_PROCESS_CHANGED
    /// @note 缺实例键或锚点时拒收，只计数
    RoleTransition join(const hng::role::RolePayload& payload,
                        const std::vector<hng::Process>& members);

    /// @brief 锚点更换：roleID 不变，记录字段被覆盖，成员并入不丢键
    /// @return 实例键未知时为空操作；锚点未变时按本次成员集修正归属并返回 NONE
    RoleTransition main_process_change(const hng::role::RolePayload& payload,
                                       const std::vector<hng::Process>& members);

    /// @brief 角色退出：按实例键取 roleID，再按反向索引定向删归属条目
    /// @return 实例键未知时为空操作
    /// @note 释放的进程会取消其等待项并丢弃以其为锚点的等待子树
    RoleTransition leave(const std::string& instance_key);

    /// @brief 子进程继承父进程的角色归属
    /// @param child 等待归属的进程
    /// @param parent 其父进程
    /// @return 本次落地新增的成员归属；暂存或丢弃时为空
    /// @note 父进程尚未归属时暂存，待父所属角色落地后应用；子进程已有归属
    ///       或已有墓碑时丢弃本次 bind
    RoleMemberChanges bind_to_role(hng::Process child, hng::Process parent);

    /// @brief 初始化期的子进程继承：父已有归属时直接 adopt，否则丢弃
    /// @param child 待归属的进程
    /// @param parent 其父进程
    /// @return 本次新增的成员归属；父未归属、子已有归属或已有墓碑时为空
    /// @note 不写等待表、不动运行期 bind_* 计数：初始化结束后不会再有父角色
    ///       事件补做，暂存只会留下永不应用的等待项
    /// @see bind_to_role
    RoleMemberChanges bind_to_role_initial(hng::Process child,
                                           hng::Process parent);

    /// @brief 按当下的枚举结果改写角色的成员归属
    /// @param role_id 目标角色
    /// @param members 本次枚举到的进程
    /// @return 本次新增的成员归属；角色不存在时为空
    /// @note 墓碑命中的进程跳过；已归属同一角色无变化；已归属别的角色按
    ///       adopt 的规则改判
    /// @note 不写等待表、不清理过期项
    RoleMemberChanges adopt_members(uint32_t role_id,
                                    const std::vector<hng::Process>& members);

    /// @brief 进程已退出：写墓碑，丢弃相关等待项，删其归属条目
    /// @note 不改变角色存在性；反向索引里的键留存，LEAVE 删时核对当前值即无副作用
    /// @note p 是该角色的锚点时把它计入 anchors_removed，
    ///       该角色退出或更换锚点后退出该计数
    void on_process_exited(hng::Process p);

    /// @brief 清理超过寿命的等待项与墓碑
    /// @note 过期的等待项直接丢弃，不应用；由 RoleManager 在每次落地后调用
    void expire();

    /// @brief 该身份是否已有未过期的墓碑
    /// @note 命中但已过期的墓碑会被就地清除
    bool is_dead(hng::Process p);

    /// @brief 进程 → roleID；未归属时为空
    /// @note 归属条目与角色记录同生共死，命中即是在册角色
    std::optional<uint32_t> lookup(hng::Process p) const;

    /// @brief 归属表的全部键，顺序不限
    /// @note 供初始化对账遍历归属条目用，不属于对外查询面
    std::vector<hng::Process> ownership_processes() const;

    /// @brief 该角色当前归属的进程，按 pid 升序
    /// @details 遍历记录的反向索引，并以归属表的当前值核对：反向索引是超集，
    ///          留存已退出或已改判的键，故不能直接当成员集
    /// @return 角色不存在时为空
    std::vector<hng::Process> members(uint32_t role_id) const;

    /// @brief 角色的对外视图
    std::optional<hng::Role> role(uint32_t role_id) const;

    /// @brief 角色的当前锚点；角色不存在或锚点已退出时为空
    std::optional<hng::Process> main_process(uint32_t role_id) const;

    /// @brief 全部角色的对外视图，按 roleID 升序
    std::vector<hng::Role> roles() const;

    /// @brief 登记或移除监管角色；roleID 不存在时忽略
    void set_supervised(uint32_t role_id, bool supervised);

    /// @brief 当前被监管角色的对外视图，按 roleID 升序
    std::vector<hng::Role> supervised_roles() const;

    /// @brief 角色的身份：实例键、类型键、属性字典
    std::optional<hng::role::RoleIdentity> identity(uint32_t role_id) const;

    /// @brief 角色的 cgroup 路径；角色不存在时为空
    /// @note 供 RoleManager 重枚举成员用，不属于对外查询面
    std::optional<std::string> cgroup_path(uint32_t role_id) const;

    /// @brief 异常态观测快照
    RoleStoreStats stats() const;

   private:
    /// @brief 等待子树的最大递归深度
    static constexpr int kMaxDrainDepth = 32;

    /// @brief 单条成员写入的结果
    enum class AdoptResult {
        ADDED,    ///< 原本不归属该角色，本次写入
        PRESENT,  ///< 已归属该角色，无变化
        REJECTED  ///< 该身份已有墓碑，未写入
    };

    /// @brief 把 p 记为 role_id 的成员：写归属表并并进反向索引
    /// @param now 查墓碑用的当前时间
    /// @note p 已归属别的角色时改判并计数（成员集是当下的枚举结果，比旧归属新）
    AdoptResult adopt(uint32_t role_id, RoleRecord& record, hng::Process p,
                      hng::RelationTimePoint now);

    /// @brief 并入锚点与成员集
    /// @param changes 本次新增的归属汇总
    /// @param now 查墓碑用的当前时间
    /// @note 锚点无条件尝试写入：成员集契约已含锚点，此处为「主进程自指」兜底
    /// @note 每条被墓碑拒绝的写入计入 late_adopt_rejected
    void adopt_all(uint32_t role_id, RoleRecord& record, hng::Process anchor,
                   const std::vector<hng::Process>& members,
                   hng::RelationTimePoint now, RoleMemberChanges& changes);

    /// @brief 应用以 anchor 为锚点的等待项，并递归收敛子的等待者
    /// @param now 查墓碑与递归共用的当前时间
    /// @param depth 当前递归深度
    /// @param changes 本次新增的归属汇总
    /// @note 调用方须已持独占锁；anchor 无归属或其角色记录缺失时不做任何事
    void drain_anchor(hng::Process anchor, hng::RelationTimePoint now, int depth,
                      RoleMemberChanges& changes);

    /// @brief 丢弃以 anchor 为锚点的等待子树
    /// @param depth 当前递归深度
    /// @note 调用方须已持独占锁；每条被丢弃的等待项计入 bind_rejected
    void fail_anchor(hng::Process anchor, int depth);

    /// @brief 锚点更换的落地，调用方须已持独占锁
    /// @param changes 本次新增的归属汇总
    RoleTransition rebind_anchor(uint32_t role_id, RoleRecord& record,
                                 const hng::role::RolePayload& payload,
                                 const std::vector<hng::Process>& members,
                                 hng::RelationTimePoint now,
                                 RoleMemberChanges& changes);

    mutable std::shared_mutex mutex_;

    RoleRelationOptions options_;

    /// 归属索引，主进程自指
    std::unordered_map<hng::Process, uint32_t> process_to_role_;
    std::unordered_map<uint32_t, RoleRecord> role_table_;
    /// LEAVE 与锚点更换的入口
    std::unordered_map<std::string, uint32_t> instance_to_role_;
    /// 监管名单；LEAVE 时随角色记录一并删除
    std::unordered_set<uint32_t> supervised_;

    /// fork 继承的等待项，按父进程为锚点暂存
    hng::DeferredRelationTable<hng::Process, hng::Process, std::monostate>
        bind_pending_;
    /// 已退出进程的墓碑
    hng::TombstoneTable<hng::Process, std::monostate> tombstones_;

    /// roleID 从 1 起单调递增、永不复用；uint32_t 用尽不可达，不处理绕回
    uint32_t next_role_id_ = 1;

    RoleStoreStats stats_;
};

#endif  // HNG_ROLE_RELATION_STORE_HPP_
