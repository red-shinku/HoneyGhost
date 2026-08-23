/**
 * @file context_manager.hpp
 * @brief 控制平面的上下文管理器组件
 * @author red_shinku
 * @date 2026.8.18
 */

#ifndef _CONTROL_PLANE_CONTEXTMANAGER_HPP
#define _CONTROL_PLANE_CONTEXTMANAGER_HPP

#include <cstdint>
#include <optional>
#include <shared_mutex>
#include <unordered_map>

#include "agent/event_data/context.hpp"

/**
 * @brief 控制平面记录的一个 context 的消息
 * @details contextID 由工作平面的 context maintainer 生成并注册
 */
struct ContextMessage {
    uint32_t contextID;
    hng::contextattr attr;
    bool has_extra;  ///< 是否有附属 context
};

/**
 * @brief context 记录的复合键
 * @details pid 与 start_time 唯一标识一个代表进程实例，
 * 一个 context 以其代表进程的 (pid, start_time) 为键
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
 * @brief 上下文管理器
 * @details
 * 上下文管理器负责 context 结构关系的管理，是单例的
 * 其中记录的 contextID 由工作平面的 context maintainer 模块生成并注册。
 * 具体 Context结构 维护在工作平面本地，形式是 contextID -> Context。
 * 工作平面本地也会维护每个角色的 Context 树关系，并且是第一手的。
 * 控制平面这里则是权威的，所有离散无状态事件的归属标准。
 *
 * 回答某个 PID 属于哪个 context
 */
class ContextManager {
   public:
    ContextManager(/* args */);
    ~ContextManager();

    /**
     * @brief 按代表进程查询其所属的 contextID
     * @param pid 代表进程的 pid
     * @param start_time 代表进程的时间标识
     * @return 命中的 contextID；进程未归属任何 context 时返回 std::nullopt
     */
    std::optional<uint32_t> lookup(uint32_t pid, uint64_t start_time) const;

    /**
     * @brief 其他组件通知注册新的 contextID
     * @param pid 新 context 的代表进程的 pid
     * @param start_time 代表进程的时间标识
     * @param contextID 新的 contextID，由工作平面生成
     * @param pcontextID 父 context ID
     */
    void register_contextID(uint32_t pid, uint64_t start_time, uint32_t contextID,
                            uint32_t pcontextID);

    /**
     * @brief 其他组件通知注销 contextID
     * @param pid 代表进程的 pid
     * @param start_time 代表进程的时间标识
     */
    void unregister_contextID(uint32_t pid, uint64_t start_time);

    /**
     * @brief 通知修改 context 属性
     * @param pid 代表进程的 pid
     * @param start_time 代表进程的时间标识
     * @param contextID 目标 context 的 ID，用于区分主/附属 context
     * @param attr 目标属性
     */
    void set_attr(uint32_t pid, uint64_t start_time, uint32_t contextID,
                  hng::contextattr attr);

   private:
    // TODO: 任务队列

    // 维护 (pid, start_time) 到主 context 消息的映射
    // 该 map 中只记录每个 context 的根 PID
    // 通常 Process 结构（对应一个PID）中会有其所属 contextID 的缓存
    // 通过其他控制面组件中维护的 PID 树向上查询可以获得该缓存
    ContextTable contexts;

    // 维护 (pid, start_time) 到附属 context 消息的映射
    // 附属 context 与主 context 共用代表进程 (pid, start_time)，
    // 即 EXTRA_ATTACK 依附于某个 NORMAL context 的情形
    // 每个主 context 至多一个附属 context，由 has_extra 标记
    ContextTable extras;

    // 维护 context 树状关系，
    // 一个 contextID 映射到它的上一个父级 ID
    ParentTable parent;

    /// @brief 实际插入新 contextID
    /// 插入的新 context 默认属性为 UNKNOWN
    /// @details
    /// 若 (pid, start_time) 尚无主 context，则作为主 context 插入主 map；
    /// 否则作为附属 context 插入附属 map（对应 EXTRA_ATTACK）
    /// @param pid 新 context 的代表进程的 pid
    /// @param start_time pid 的时间标识
    /// @param contextID 新的contextID，由工作面生成
    /// @param pcontextID 父 context ID
    void addContextID(uint32_t pid, uint64_t start_time, uint32_t contextID,
                      uint32_t pcontextID);

    /// @brief 实际删除 contextID
    /// @details 删除主 context 时一并删除同键的附属 context 及其 parent 记录
    /// @param pid 代表进程的 pid
    /// @param start_time pid 的时间标识
    void delContextID(uint32_t pid, uint64_t start_time);

    /// @brief 设置 context 属性
    /// @details
    /// 目标 context 可能在主 map 或附属 map 中，需要 contextID 定位
    /// 只允许 UNKNOWN 向其他属性的变更
    /// 在 ATTACK/EXTRA_ATTACK 属性上预留钩子，会触发向 eBPF map 的注册行为
    void set_attr_(uint32_t pid, uint64_t start_time, uint32_t contextID,
                   hng::contextattr attr);
};

#endif  //_CONTROL_PLANE_CONTEXTMANAGER_HPP
