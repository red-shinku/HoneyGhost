/**
 * @file pending_table.hpp
 * @brief 待决策进程（fork 产生、尚未完成派生决策）的登记与窗口推进
 * @details
 * 包含线程不安全的待决策进程表。登记键为子进程 Process(child)；
 * 仅登记 fork 产生的新线程组子进程（子 tgid ≠ 父 tgid），线程不登记。
 * 决策只有两个出口，也是仅有的两个清理时机：
 *   1) exec 事件到达 → 立即按 decide_exec 判定；
 *   2) 事件配额耗尽（窗口内无 exec）→ 强制派生 NO_EXEC_WINDOW。
 * 以及进程退出时清理（决策尚未完成即退出）。
 * @author red_shinku
 * @date 2026.9.5
 */

#ifndef HNG_RULE_PENDING_TABLE_HPP_
#define HNG_RULE_PENDING_TABLE_HPP_

#include <cstdint>
#include <functional>
#include <optional>
#include <unordered_map>

#include "agent/event_data/include/process.hpp"
#include "agent/context_maintainer/src/rule/derive_types.hpp"

namespace hng {
namespace detail {

/// 窗口期内一个待决策进程的登记信息
struct PendingEntry {
    hng::Process parent;                 ///< 父进程
    bool parent_context_is_interpreter;  ///< 父 context 是否解释器上下文
    uint32_t window_left;                ///< 剩余非 exec 事件配额
};

/**
 * @brief 待决策进程窗口表
 * @details 对外提供 fork 登记、exec/事件/退出三路推进入口。返回值为空表示
 * 无派生动作（仍待决策、KEEP、或非待决策进程）；非空表示本次触发了 DERIVE，
 * 调用方应据 verdict 为新进程创建 context。
 */
class PendingTable {
   public:
    /// fork 产生新线程组子进程时登记；同 child 重复登记忽略
    /// @param child 子进程（决策对象，登记键）
    /// @param parent 父进程
    /// @param parent_context_is_interpreter fork 时由上层提供
    /// @param window_size 事件配额，须大于 0（<=0 时按 1 处理）
    void on_fork(hng::Process child, hng::Process parent,
                 bool parent_context_is_interpreter, uint32_t window_size);

    /// 待决策子进程的 exec：立即判定并移除
    /// @details 非待决策进程的 exec 视为既有进程原地重 exec（同一执行实体），
    /// 不做派生决策，返回空。
    /// @param p 执行 exec 的进程
    /// @param normalized_filename 归一后的 exec 目标路径
    /// @return 触发 DERIVE 时非空；KEEP / 非待决策 时为空
    std::optional<DeriveVerdict> on_exec(hng::Process p,
                                         const std::string& normalized_filename);

    /// 待决策子进程的非 exec 事件：消耗配额；耗尽触发 NO_EXEC_WINDOW 派生
    /// @return 触发 DERIVE 时非空；仍待决策 / 非待决策 时为空
    std::optional<DeriveVerdict> on_event(hng::Process p);

    /// 进程退出：若待决策则清理（决策未完成即退出的情形）
    void on_exit(hng::Process p);

    bool is_pending(hng::Process p) const;
    std::optional<PendingEntry> lookup(hng::Process p) const;

   private:
    /// 以进程身份为键的包装结构，比较与哈希沿用 hng::Process 的定义
    struct ProcessKey {
        hng::Process p;
        bool operator==(const ProcessKey& o) const { return p == o.p; }
    };
    struct KeyHash {
        std::size_t operator()(const ProcessKey& k) const
        {
            return std::hash<hng::Process>{}(k.p);
        }
    };

    std::unordered_map<ProcessKey, PendingEntry, KeyHash> table_;
};

}  // namespace detail
}  // namespace hng

#endif  // HNG_RULE_PENDING_TABLE_HPP_
