/**
 * @file context_manager.hpp
 * @brief 控制平面的上下文管理器组件
 * @author red_shinku
 * @date 2026.8.18
 */

#ifndef _CONTROL_PLANE_CONTEXTMANAGER_HPP
#define _CONTROL_PLANE_CONTEXTMANAGER_HPP

#include <cstdint>
#include <functional>
#include <shared_mutex>
#include <unordered_map>

#include "agent/util/include/spsc_queue.hpp"
#include "context_service.hpp"

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
 * 该表也隐含地表示了不同 context 的进程集
 *
 * 写点只有两类事件：
 *   1) 某进程的 context 归属落定 —— bind_to_ctxroot()
 *   2) 进程被完全删除 —— on_process_removed() 清理该进程条目。
 * 进程的归属在落定后不再改写（不可变），故本表也无需修改
 */
struct ToContextRootTable {
    struct ProcessEq {
        bool operator()(const hng::Process& a, const hng::Process& b) const
        {
            return a.pid == b.pid && a.pid_start_time == b.pid_start_time;
        }
    };
    struct ProcessHash {
        std::size_t operator()(const hng::Process& k) const
        {
            return std::hash<uint32_t>{}(k.pid) ^
                   (std::hash<uint64_t>{}(k.pid_start_time) << 1);
        }
    };
    mutable std::shared_mutex smtx;
    std::unordered_map<hng::Process, ContextKey, ProcessHash, ProcessEq>
        map;  ///< 进程(hng::Process) -> 所属主context根进程(ContextKey)
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
 * 负责：
 * 1) 回答任意进程属于哪个 context
 */
class ContextManager : public ContextService {
   public:
    ContextManager(/* args */);
    ~ContextManager();

    /// @brief 查询进程所属主 context 的 ID。
    /// 会先查询该进程所属 context 的根进程，其结果作为
    /// ContextKey 查 contexts 表
    std::optional<uint32_t> lookup(hng::Process p) const override;

    /// @brief 查询进程所属 附属 Context 的 ID（任意进程，经 process→根 映射解析）
    /// 会先查询该进程所属 context 的根进程，其结果作为
    /// ContextKey 查 extras 表
    std::optional<uint32_t> lookup_extra(hng::Process p) const override;

    /// @brief 注册新的 contextID（通知写）
    /// 生成并将实际写操作 加入任务队列
    void register_contextID(hng::Process p, ContextDeriveDecision newcontext,
                            uint32_t pcontextID) override;

    /// @brief 注销 contextID（通知写）
    /// 生成并将实际写操作 加入任务队列
    void unregister_contextID(hng::Process p) override;

    /// @brief 修改 context 属性（通知写）
    void set_attr(hng::Process p, uint32_t contextID,
                  hng::contextattr attr) override;

    /// @brief 归属落定：KEEP 子进程挂靠到父进程所属的 context（通知写）
    /// @details 派生决策为 KEEP 时由工作平面调用；实际落地在私有挂靠逻辑，
    /// 父进程尚未落定时为空操作（登记竞态，归属保持待定）
    void bind_to_ctxroot(hng::Process p, hng::Process parent) override;

    /// @brief 上报进程被完全删除（通知写）
    /// @details 供 ProcessManager 在进程（实进程/虚拟根）被完全删除时调用；
    /// 实际清理逻辑（归属条目，若为 context 根则连同 context）在私有方法中执行
    void on_process_removed(hng::Process p) override;

   private:
    // 通知写任务的队列。所有对内部数据的修改都经公共接口入队、由消费者串行执行，
    // 避免把写操作外泄到调用方线程（ProcessManager 同款写法）。
    // TODO: 当前为 SPSC 占位：消费线程 / 生产者汇聚（含 ProcessManager 线程与
    // 工作面线程两类来源）的确定是后续任务。
    static constexpr size_t kTaskQueueCapacity = 4096;
    hng::SPSC_Queue<std::function<void()>> task;

    // 进程 → 所属 context 根进程 的映射（归属索引）
    // lookup/lookup_extra/bind_to_ctxroot/on_process_removed 均经该表解析。
    ToContextRootTable to_context_root;

    // context 根进程 到主 context 的映射
    ContextTable contexts;

    // context 根进程 到附属 context 的映射
    // 附属 context 与主 context 共用代表进程，
    // 即 EXTRA_ATTACK 依附于某个 NORMAL context 的情形
    // 每个主 context 至多一个附属 context，由 has_extra 标记
    // TODO: 附属 context 如何清理？
    ContextTable extras;

    // 维护 context 树状关系，
    // 一个 contextID 映射到它的上一个父级 ID
    ParentTable parent;

    /// @brief 实际插入新 contextID
    /// 插入的新 context 默认属性为 UNKNOWN
    /// @details
    /// 若 Process 尚无主 context，则作为主 context 插入主 map；
    /// 否则作为附属 context 插入附属 map（对应 EXTRA_ATTACK）。
    ///
    /// 关于 context
    /// 泄漏（孤儿context、附属context意外作为主context插入到主表中），这个问题在
    /// FIFO 任务队列以及单线程跑 context_manager 的情况下是安全的
    ///
    /// @param p context代表进程的唯一性表示
    /// @param contextID 新的contextID，由工作面生成
    /// @param attr 新 context 的属性
    /// @param pcontextID 父 context ID
    void addContextID(hng::Process p, uint32_t contextID, hng::contextattr attr,
                      uint32_t pcontextID);

    /// @brief 实际删除 contextID
    /// @details 删除主 context 时一并删除同键的附属 context 及其 parent 记录
    /// @param p context代表进程的唯一性表示
    void delContextID(hng::Process p);

    /// @brief 设置 context 属性
    /// @details
    /// 只允许 UNKNOWN 向其他属性的变更
    /// 由于附属 Context 没有中间状态(UNKNOWN)，目标 context 正常情况都在主 map
    /// 中。在 ATTACK/EXTRA_ATTACK 属性上预留钩子，会触发向
    /// eBPF map 的注册行为
    void set_attr_(hng::Process p, uint32_t contextID, hng::contextattr attr);

    /// @brief 新进程没有派生 context 时，需与 context 根进程绑定
    void bind_to_ctxroot_(hng::Process p, hng::Process parent);

    /// @brief 进程被完全删除时，尝试清理相关 context 与 to_context_root 记录
    /// 若为 context 根则连同 context 清除
    void on_process_removed_(hng::Process p);

    // 任务队列消费循环（装配期启动线程运行）
    void work();
};

#endif  //_CONTROL_PLANE_CONTEXTMANAGER_HPP
