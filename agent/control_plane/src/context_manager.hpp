/**
 * @file context_manager.hpp
 * @brief 控制平面的上下文管理器组件
 * @author red_shinku
 * @date 2026.8.18
 */

#ifndef _CONTROL_PLANE_CONTEXTMANAGER_HPP
#define _CONTROL_PLANE_CONTEXTMANAGER_HPP

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>
#include <shared_mutex>
#include <unordered_map>
#include <unordered_set>
#include <variant>

#include "agent/util/include/deferred_relation_table.hpp"
#include "agent/util/include/tombstone_table.hpp"
#include "agent/util/include/notification_queue.hpp"
#include "agent/control_plane/include/context_stats.hpp"
#include "agent/control_plane/include/context_service.hpp"
#include "agent/control_plane/include/process_lifecycle_sink.hpp"

/**
 * @brief 控制平面记录的一个 context 的消息
 * @details contextID 由工作平面的 context maintainer 生成并注册
 * Context 分为两种：一般 Context 与附属 Context。
 * 附属 Context 依附于某个属性为 NORMAL 的 一般 Context，
 * 代表 PID 与所依附的 Context 一致，而且没有中间状态（UNKNOWN）
 */
struct ContextMessage {
    uint32_t contextID;
    hng::contextattr attr;
    bool has_extra;  ///< 是否有附属 context
};

/**
 * @brief context 的键，内部为该 context 的根进程
 * @details
 * 一个 context 以其代表根进程的 (pid, start_time) 为键
 */
struct ContextKey {
    uint32_t pid;
    uint64_t start_time;

    bool operator==(const ContextKey& other) const
    {
        return other.pid == pid && other.start_time == start_time;
    }
};

/**
 * @brief contexts 映射的包装结构，使用读写锁保护
 * @details 键为 (pid, start_time) 复合键，值为该 context 的消息
 */
struct ContextTable {
    struct KeyHash {
        std::size_t operator()(const ContextKey& k) const
        {
            return std::hash<uint32_t>{}(k.pid) ^
                   (std::hash<uint64_t>{}(k.start_time) << 1);
        }
    };
    // mutable，在 const 函数中锁变量允许修改
    mutable std::shared_mutex smtx;
    std::unordered_map<ContextKey, ContextMessage, KeyHash> map;
    /// 属性 → contextID 集合；与 map 同锁维护
    std::unordered_map<hng::contextattr, std::unordered_set<uint32_t>> by_attr;
    /// contextID → 根键；与 map 同锁维护
    std::unordered_map<uint32_t, ContextKey> id_to_key;
};

/**
 * @brief parent 映射的包装结构，使用读写锁保护
 * @details 维护 contextID 到其父 contextID 的树状关系
 */
struct ParentTable {
    mutable std::shared_mutex smtx;
    std::unordered_map<uint32_t, uint32_t>
        map;  ///< contextID -> parent contextID
};

/**
 * @brief 进程 → 所属 context 的根进程 的映射包装结构，使用读写锁保护
 * @details
 * 内部 map 为 hng::Process -> ContextKey。
 * 其中 context 根进程自指。任意进程可直接 O(1) 得到其所属 context 的根进程
 * processes_by_root 是其反向索引，供按 context 枚举成员。
 *
 * 写点只有三类事件：
 *   1) 某进程的 context 归属落定 —— bind_to_ctxroot()
 *   2) 进程退出 —— on_process_exited() 清理该进程条目。
 *   3) context 根注册 —— addContextID() 写入根进程自指。
 * 进程的归属在落定后不再改写（不可变），故本表也无需修改
 */
struct ToContextRootTable {
    mutable std::shared_mutex smtx;
    std::unordered_map<hng::Process, ContextKey>
        map;  ///< 进程(hng::Process) -> 所属主context根进程(ContextKey)
    /// 根键 → 成员进程；map 的反向索引，与 map 同锁维护
    std::unordered_map<ContextKey, std::unordered_set<hng::Process>,
                       ContextTable::KeyHash>
        processes_by_root;
};

/**
 * @brief 上下文管理器接收的关系修复配置
 * @details 三个表的容量与寿命默认值可直接运行；测试通过覆盖参数注入假时钟与
 *          小容量、短寿命。
 */
struct ContextManagerOptions {
    hng::DeferredRelationOptions link_pending;  ///< 父链接等待表
    hng::DeferredRelationOptions bind_pending;  ///< KEEP 挂靠等待表
    hng::TombstoneOptions tombstones;           ///< 已退出进程墓碑表
    /// 当前时间来源，必须是单调时钟
    std::function<hng::RelationTimePoint()> now = [] {
        return std::chrono::steady_clock::now();
    };
};

/// @brief 父链接等待项：子进程已注册主 context，等待父 contextID
struct LinkAction {
    hng::Process child;  ///< 等待父链接的子进程
    uint32_t contextID;  ///< 子进程自己的主 contextID
};

/// @brief 已退出进程的墓碑信息
struct ContextTombstone {
    std::optional<ContextKey> last_root;  ///< 退出时所属 context 的根键
    uint32_t context_id = 0;              ///< last_root 的 contextID
};

/**
 * @brief 上下文管理器
 * @details
 * 上下文管理器负责 context 结构关系的管理，是单例的
 * 其中记录的 contextID 由工作平面的 context maintainer 模块生成并注册。
 * 具体 Context结构 维护在工作平面本地，形式是 contextID -> Context。
 * 工作平面本地也会维护每个角色的 Context 树关系，并且是第一手的。
 * 控制平面这里则是权威的，所有离散无状态事件的归属标准。
 *
 * 六个写接口都是通知写：入队即返回，落地在 run() 的消费线程上。故入队之后
 * 不得立即依赖查询结果，见 docs/red_shinku_logs/控制平面context归属重构.md §3.3。
 *
 * 父链接与 KEEP 挂靠可先于父进程落地；此时关系暂存在消费线程私有的延迟表中，
 * 父落地时收敛，父退出或超时后降级。已退出进程的墓碑用于拒绝迟到的注册与挂靠。
 * 查询面不读取延迟表或墓碑。
 */
class ContextManager : public ContextLookupService,
                       public ContextJoinService,
                       public ContextUpdateService,
                       public ProcessLifecycleSink {
   public:
    /// @brief 构造管理器
    /// @param options 延迟表、墓碑表的参数与时间来源
    explicit ContextManager(ContextManagerOptions options = {});
    ~ContextManager();

    /// @brief 查询进程所属主 context 的 ID。
    /// 会先查询该进程所属 context 的根进程，其结果作为
    /// ContextKey 查 contexts 表
    std::optional<uint32_t> lookup(hng::Process p) const override;

    /// @brief 查询进程所属 附属 Context 的 ID（任意进程，经 process→根 映射解析）
    /// 会先查询该进程所属 context 的根进程，其结果作为
    /// ContextKey 查 extras 表
    std::optional<uint32_t> lookup_extra(hng::Process p) const override;

    /// @brief 指定属性的 contextID 集合，按 ID 升序
    std::vector<uint32_t> contexts_by_attr(hng::contextattr attr) const override;

    /// @brief 按 contextID 取根进程与成员集；未知 ID 返回空
    std::optional<ContextProcessSet> members(uint32_t contextID) const override;

    /// @brief 注册新的主 contextID（通知写）
    /// @param p context 代表进程
    /// @param newcontext 新 context 信息；kind 须为 DERIVE
    /// @param parent 父进程引用；落地时解析其 contextID
    /// @see ContextParentRef
    void register_context(hng::Process p, ContextDeriveDecision newcontext,
                          ContextParentRef parent) override;

    /// @brief 注册附属 context（通知写）
    /// @param p context 代表进程；须已有主 context
    /// @param contextID 附属 contextID
    /// @param attr 附属 context 属性
    void register_extra_context(hng::Process p, uint32_t contextID,
                                hng::contextattr attr) override;

    /// @brief 注销 contextID（通知写）
    /// 生成并将实际写操作 加入任务队列
    void unregister_context(hng::Process p) override;

    /// @brief 修改 context 属性（通知写）
    void set_attr(hng::Process p, uint32_t contextID,
                  hng::contextattr attr) override;

    /// @brief 归属落定：KEEP 子进程挂靠到父进程所属的 context（通知写）
    /// @param p 子进程
    /// @param parent 父进程引用；expected 为 true 且父未落定时暂存挂靠，
    ///        expected 为 false 时直接降级并保持未归属
    /// @see ContextParentRef
    void bind_to_ctxroot(hng::Process p, ContextParentRef parent) override;

    /// @brief 进程已退出（通知写）
    /// @details 从归属索引与成员集中移除该进程；成员集清空时删除整个 context。
    ///          根进程退出而其他成员仍在时，context 保留，键仍指向已退出的根
    void on_process_exited(hng::Process p) override;

    /// @brief 消费线程入口：取队列、按到达顺序串行落地，阻塞直到 stop()
    /// @note 不持线程，线程由装配方创建；析构前须已返回
    void run();

    /// @brief 停止消费；幂等，可从任意线程调用
    /// @note 已入队的任务仍会被落地，队列取空后 run() 返回；此后的入队被拒绝
    void stop();

    /// @brief 异常态观测快照
    ContextManagerStats stats() const override;

   private:
    /// @brief 入队任务：注册一个主 context
    struct AddTask {
        hng::Process process;
        uint32_t contextID;       ///< 新 context 的 ID，由工作面生成
        hng::contextattr attr;    ///< 新 context 的属性
        ContextParentRef parent;  ///< 父进程引用；落地时解析其 contextID
    };

    /// @brief 入队任务：注册一个附属 context
    struct ExtraTask {
        hng::Process process;
        uint32_t contextID;
        hng::contextattr attr;
    };

    /// @brief 入队任务：注销某个根进程的 context
    struct DelTask {
        hng::Process process;
    };

    /// @brief 入队任务：修改 context 属性
    struct SetAttrTask {
        hng::Process process;
        uint32_t contextID;
        hng::contextattr attr;
    };

    /// @brief 入队任务：把进程挂靠到父进程所属的 context
    struct BindTask {
        hng::Process process;
        ContextParentRef parent;
    };

    /// @brief 入队任务：进程已退出
    struct ExitedTask {
        hng::Process process;
    };

    /// 六个写接口共用一条队列：多生产者、无界，按到达顺序串行落地
    using Task = std::variant<AddTask, ExtraTask, DelTask, SetAttrTask, BindTask,
                              ExitedTask>;
    hng::NotificationQueue<Task> task;

    ContextManagerOptions options_;
    /// 子进程等待父进程 contextID 的延迟表；只在消费线程访问
    hng::DeferredRelationTable<hng::Process, hng::Process, LinkAction>
        link_pending_;
    /// 子进程等待父进程归属的延迟表；只在消费线程访问
    hng::DeferredRelationTable<hng::Process, hng::Process, std::monostate>
        bind_pending_;
    /// 已退出进程的墓碑；只在消费线程访问
    hng::TombstoneTable<hng::Process, ContextTombstone> tombstones_;

    /// 消费线程写、任意线程读，故为原子
    std::atomic<uint64_t> pending_deferred_{0};
    std::atomic<uint64_t> pending_resolved_{0};
    std::atomic<uint64_t> pending_rejected_{0};
    std::atomic<uint64_t> pending_expired_{0};
    std::atomic<uint64_t> pending_cancelled_{0};
    std::atomic<uint64_t> pending_depth_{0};
    std::atomic<uint64_t> bind_orphaned_{0};
    std::atomic<uint64_t> extra_orphaned_{0};
    std::atomic<uint64_t> parent_missing_{0};
    std::atomic<uint64_t> late_register_{0};
    std::atomic<uint64_t> late_bind_{0};
    std::atomic<uint64_t> duplicate_context_{0};
    std::atomic<uint64_t> ownership_conflict_{0};
    std::atomic<uint64_t> tombstone_hits_{0};
    std::atomic<uint64_t> tombstone_depth_{0};
    std::atomic<uint64_t> ctxroot_parent_unsettled_{0};
    std::atomic<uint64_t> unknown_unregister_{0};

    // 进程 → 所属 context 根进程 的映射（归属索引）
    // lookup/lookup_extra/bind_to_ctxroot/on_process_exited 均经该表解析。
    ToContextRootTable to_context_root;

    // context 根进程 到主 context 的映射
    ContextTable contexts;

    // context 根进程 到附属 context 的映射
    // 附属 context 与主 context 共用代表进程，
    // 即 EXTRA_ATTACK 依附于某个 NORMAL context 的情形
    // 每个主 context 至多一个附属 context，由 has_extra 标记
    // 主 context 删除时一并清理
    ContextTable extras;

    // 维护 context 树状关系，
    // 一个 contextID 映射到它的上一个父级 ID
    ParentTable parent;

    /// @brief 查找墓碑；命中时累计 tombstone_hits
    /// @param p 进程身份
    /// @param now 当前时间，用于判断墓碑是否过期
    std::optional<ContextTombstone> find_tombstone(hng::Process p,
                                                   hng::RelationTimePoint now);

    /// @brief 解析锚点当前所属 context 的根键
    /// @details
    /// 依次尝试：归属索引（根键须仍有 context 记录）、锚点自身仍是存活 context
    /// 的根键、墓碑记录的 last_root 或 context_id。均未命中时返回空；不回退到
    /// 祖先 context。显式注销不清理归属索引，故归属索引单独校验 context
    /// 是否存在。
    /// @param anchor 锚点进程
    /// @param now 当前时间，用于判断墓碑是否过期
    std::optional<ContextKey> resolve_root_of(hng::Process anchor,
                                              hng::RelationTimePoint now);

    /// @brief 解析锚点当前所属主 context 的 ID
    /// @param anchor 锚点进程
    /// @param now 当前时间，用于判断墓碑是否过期
    /// @return 解析到存活 context 时为它的 ID；否则为空
    std::optional<uint32_t> resolve_context_id_of(hng::Process anchor,
                                                  hng::RelationTimePoint now);

    /// @brief 查询根键对应的 contextID
    /// @param key context 根键
    /// @return context 存活时为它的 ID；否则为空
    std::optional<uint32_t> context_id_of(const ContextKey& key);

    /// @brief 查询根键对应的主 context 是否存在
    bool context_exists(const ContextKey& key) const;

    /// @brief 实际插入主 context
    /// @details 主 context 键唯一：同键已存在时保留首条并计数。父 contextID
    ///          解析不到且允许等待时先暂存父链接，主 context 立即插入。
    /// @param p context代表进程的唯一性表示
    /// @param contextID 新的contextID，由工作面生成
    /// @param attr 新 context 的属性
    /// @param parent 父进程引用
    /// @param now 当前时间
    void addContextID(hng::Process p, uint32_t contextID, hng::contextattr attr,
                      ContextParentRef parent_ref, hng::RelationTimePoint now);

    /// @brief 实际插入附属 context
    /// @details 要求该键已有主 context；进程命中墓碑、主 context 不存在或已有
    ///          附属 context 时丢弃，前两者计入 extra_orphaned。
    /// @param p context代表进程的唯一性表示
    /// @param contextID 附属 contextID
    /// @param attr 附属 context 的属性
    /// @param now 当前时间
    void addExtraContext(hng::Process p, uint32_t contextID,
                         hng::contextattr attr, hng::RelationTimePoint now);

    /// @brief 实际删除 contextID
    /// @details 删除主 context 时一并删除同键的附属 context 及其 parent 记录；
    ///          以 p 为锚点的等待项按目标消失处理，p 作为等待方的条目被取消。
    ///          显式注销不写墓碑。
    /// @param p context代表进程的唯一性表示
    /// @param now 当前时间
    void delContextID(hng::Process p, hng::RelationTimePoint now);

    /// @brief 设置 context 属性
    /// @details
    /// 只允许 UNKNOWN 向其他属性的变更
    /// 由于附属 Context 没有中间状态(UNKNOWN)，目标 context 正常情况都在主 map
    /// 中。在 ATTACK/EXTRA_ATTACK 属性上预留钩子，会触发向
    /// eBPF map 的注册行为
    void set_attr_(hng::Process p, uint32_t contextID, hng::contextattr attr);

    /// @brief 新进程没有派生 context 时，需与 context 根进程绑定
    /// @details 解析不了父归属且允许等待时暂存挂靠；否则保持未归属并计数。
    /// @param p 子进程
    /// @param parent 父进程引用
    /// @param now 当前时间
    void bind_to_ctxroot_(hng::Process p, ContextParentRef parent,
                          hng::RelationTimePoint now);

    /// @brief 把子进程写入指定 context 根，并递归收敛其等待者
    /// @param child 子进程
    /// @param root context 根键
    /// @param now 当前时间
    /// @param depth 递归深度
    /// @return 写入成功或已归属同一根时为 true；墓碑拒绝或归属冲突时为 false
    /// @note 归属落定后不可改绑
    bool bind_child(hng::Process child, const ContextKey& root,
                    hng::RelationTimePoint now, uint32_t depth);

    /// @brief 应用以 anchor 为锚点的等待项
    /// @param anchor 已落定的锚点进程
    /// @param now 当前时间
    /// @param depth 递归深度
    void drain_waiters(hng::Process anchor, hng::RelationTimePoint now,
                       uint32_t depth);

    /// @brief 按目标消失处理以 anchor 为锚点的等待项
    /// @details 链接等待者父链接置 0；挂靠等待者丢弃并级联失败其子等待者。
    ///          不挂祖先 context，也不新建 context。
    /// @param anchor 消失的锚点进程
    /// @param depth 递归深度
    void fail_waiters(hng::Process anchor, uint32_t depth);

    /// @brief 清理过期的延迟关系与墓碑，并累计对应降级计数
    /// @param now 当前时间
    void expire_pending(hng::RelationTimePoint now);

    /// @brief 刷新 pending_depth 与 tombstone_depth 两个观测值
    void refresh_depths();

    /// @brief 进程退出时清理归属条目；成员集清空则删除整个 context
    void on_process_exited_(hng::Process p, hng::RelationTimePoint now);

    /// @brief 落地一条队列任务
    void land(Task& task);
};

#endif  //_CONTROL_PLANE_CONTEXTMANAGER_HPP
