/**
 * @file pending_table.cc
 * @brief 待决策进程窗口表的登记与推进实现
 * @author red_shinku
 * @date 2026.9.5
 */

#include "./include/pending_table.hpp"

namespace hng {
namespace rule {

void PendingTable::on_fork(hng::Process child, hng::Process parent,
                           bool parent_context_is_interpreter,
                           uint32_t window_size)
{
    if (window_size == 0) {
        window_size = 1;
    }
    ProcessKey key{child};
    // 同 child 已在窗口期（fork 事件重复等），保留原记录
    if (table_.find(key) != table_.end()) {
        return;
    }
    table_.emplace(
        key, PendingEntry{parent, parent_context_is_interpreter, window_size});
}

std::optional<DeriveVerdict> PendingTable::on_exec(
    hng::Process p, const std::string& normalized_filename)
{
    auto it = table_.find(ProcessKey{p});
    if (it == table_.end()) {
        // 非待决策进程：既有进程原地重 exec，不产生派生决策
        return std::nullopt;
    }
    const PendingEntry entry = it->second;  // 拷贝后擦除，避免悬垂引用
    table_.erase(it);

    DeriveVerdict v =
        decide_exec(p, entry.parent, entry.parent_context_is_interpreter,
                    normalized_filename);
    if (v.derive) {
        return v;
    }
    // KEEP：留在父 context，无派生动作
    return std::nullopt;
}

std::optional<DeriveVerdict> PendingTable::on_event(hng::Process p)
{
    auto it = table_.find(ProcessKey{p});
    if (it == table_.end()) {
        return std::nullopt;
    }
    if (it->second.window_left > 0) {
        it->second.window_left -= 1;
    }
    if (it->second.window_left > 0) {
        return std::nullopt;  // 仍待决策，事件继续归属父 context
    }

    const hng::Process parent = it->second.parent;
    table_.erase(it);

    DeriveVerdict v;  // 窗口内无 exec，事件配额耗尽 → 强制派生
    v.derive = true;
    v.reason = DeriveReason::NO_EXEC_WINDOW;
    v.child  = p;
    v.parent = parent;
    return v;
}

void PendingTable::on_exit(hng::Process p) { table_.erase(ProcessKey{p}); }

bool PendingTable::is_pending(hng::Process p) const
{
    return table_.find(ProcessKey{p}) != table_.end();
}

std::optional<PendingEntry> PendingTable::lookup(hng::Process p) const
{
    auto it = table_.find(ProcessKey{p});
    if (it == table_.end()) {
        return std::nullopt;
    }
    return it->second;
}

}  // namespace rule
}  // namespace hng
