#include "agent/control_plane/src/context_store.hpp"

#include <algorithm>
#include <mutex>
#include <utility>

// 上下文关系存储

namespace {

/// 等待者收敛的递归深度上限
constexpr uint32_t kMaxWaitDepth = 32;

using AttrIndex =
    std::unordered_map<hng::contextattr, std::unordered_set<uint32_t>>;

/// 从属性索引中移除一个 contextID；调用方须已持该表的锁
void erase_from_attr_index(AttrIndex& index, hng::contextattr attr,
                           uint32_t context_id)
{
    auto it = index.find(attr);
    if (it == index.end()) {
        return;
    }
    it->second.erase(context_id);
    if (it->second.empty()) {
        index.erase(it);
    }
}

/// 查询某进程所属 context 的根进程；未落定返回空
std::optional<ContextKey> root_of(const ToContextRootTable& table, hng::Process p)
{
    std::shared_lock lock(table.smtx);
    auto it = table.map.find(p);
    if (it == table.map.end()) {
        return std::nullopt;
    }
    return it->second;
}

/// @brief 按根键组装成员集；取 roots 的共享锁
/// @note 成员集只含仍为实进程的成员；已退出的根不补回
ContextProcessSet process_set_of(const ContextKey& key,
                                 const ToContextRootTable& roots)
{
    ContextProcessSet result;
    result.root = hng::Process{key.pid, key.start_time};

    {
        std::shared_lock lock(roots.smtx);
        auto it = roots.processes_by_root.find(key);
        if (it != roots.processes_by_root.end()) {
            result.members.assign(it->second.begin(), it->second.end());
        }
    }

    std::sort(result.members.begin(), result.members.end(),
              [](const hng::Process& lhs, const hng::Process& rhs) {
                  if (lhs.pid != rhs.pid) {
                      return lhs.pid < rhs.pid;
                  }
                  return lhs.pid_start_time < rhs.pid_start_time;
              });
    return result;
}

}  // namespace

ContextStore::ContextStore(ContextStoreOptions options)
    : options_(std::move(options)),
      link_pending_(options_.link_pending),
      bind_pending_(options_.bind_pending),
      tombstones_(options_.tombstones)
{
}

std::optional<uint32_t> ContextStore::lookup(hng::Process p) const
{
    auto root = root_of(to_context_root, p);
    if (!root) {
        return std::nullopt;  // 进程尚未落定归属（含仍处派生观察窗口的进程）
    }
    std::shared_lock lock(contexts.smtx);
    auto it = contexts.map.find(*root);
    if (it == contexts.map.end()) {
        // 容错：根记录已被清理、其残留成员条目仍在索引中的良性滞后情形
        return std::nullopt;
    }
    return it->second.contextID;
}

std::optional<uint32_t> ContextStore::lookup_extra(hng::Process p) const
{
    auto root = root_of(to_context_root, p);
    if (!root) {
        return std::nullopt;
    }
    std::shared_lock lock(extras.smtx);
    auto it = extras.map.find(*root);
    if (it == extras.map.end()) {
        return std::nullopt;  // 该 context 无附属 context
    }
    return it->second.contextID;
}

std::vector<uint32_t> ContextStore::contexts_by_attr(hng::contextattr attr) const
{
    std::vector<uint32_t> result;
    {
        std::shared_lock lock(contexts.smtx);
        auto it = contexts.by_attr.find(attr);
        if (it != contexts.by_attr.end()) {
            result.assign(it->second.begin(), it->second.end());
        }
    }
    {
        std::shared_lock lock(extras.smtx);
        auto it = extras.by_attr.find(attr);
        if (it != extras.by_attr.end()) {
            result.insert(result.end(), it->second.begin(), it->second.end());
        }
    }
    std::sort(result.begin(), result.end());
    return result;
}

std::optional<ContextProcessSet> ContextStore::members(uint32_t contextID) const
{
    {
        std::shared_lock lock(contexts.smtx);
        auto it = contexts.id_to_key.find(contextID);
        if (it != contexts.id_to_key.end()) {
            return process_set_of(it->second, to_context_root);
        }
    }
    {
        std::shared_lock lock(extras.smtx);
        auto it = extras.id_to_key.find(contextID);
        if (it != extras.id_to_key.end()) {
            return process_set_of(it->second, to_context_root);
        }
    }
    return std::nullopt;
}

ContextManagerStats ContextStore::stats() const
{
    ContextManagerStats snapshot;
    snapshot.pending_deferred = pending_deferred_.load(std::memory_order_relaxed);
    snapshot.pending_resolved = pending_resolved_.load(std::memory_order_relaxed);
    snapshot.pending_rejected = pending_rejected_.load(std::memory_order_relaxed);
    snapshot.pending_expired  = pending_expired_.load(std::memory_order_relaxed);
    snapshot.pending_cancelled =
        pending_cancelled_.load(std::memory_order_relaxed);
    snapshot.pending_depth  = pending_depth_.load(std::memory_order_relaxed);
    snapshot.bind_orphaned  = bind_orphaned_.load(std::memory_order_relaxed);
    snapshot.extra_orphaned = extra_orphaned_.load(std::memory_order_relaxed);
    snapshot.parent_missing = parent_missing_.load(std::memory_order_relaxed);
    snapshot.late_register  = late_register_.load(std::memory_order_relaxed);
    snapshot.late_bind      = late_bind_.load(std::memory_order_relaxed);
    snapshot.duplicate_context =
        duplicate_context_.load(std::memory_order_relaxed);
    snapshot.ownership_conflict =
        ownership_conflict_.load(std::memory_order_relaxed);
    snapshot.tombstone_hits  = tombstone_hits_.load(std::memory_order_relaxed);
    snapshot.tombstone_depth = tombstone_depth_.load(std::memory_order_relaxed);
    snapshot.ctxroot_parent_unsettled =
        ctxroot_parent_unsettled_.load(std::memory_order_relaxed);
    snapshot.unknown_unregister =
        unknown_unregister_.load(std::memory_order_relaxed);
    return snapshot;
}

ContextSeedReport ContextStore::seed(const ContextSeedPlan& plan)
{
    ContextSeedReport report;
    for (const ContextSeedEntry& entry : plan.entries) {
        const hng::Process process        = entry.process;
        const hng::Process parent_process = entry.parent;

        // 身份非法或父与自身相同：整条丢弃
        if (process.pid == 0 || process.pid_start_time == 0 ||
            parent_process == process) {
            ++report.rejected_invalid;
            continue;
        }

        if (entry.kind == ContextSeedKind::DERIVE) {
            if (entry.contextID == 0) {
                ++report.rejected_invalid;
                continue;
            }

            const ContextKey key{process.pid, process.pid_start_time};
            bool duplicate = false;
            bool id_taken  = false;
            {
                std::shared_lock lock(contexts.smtx);
                duplicate     = contexts.map.find(key) != contexts.map.end();
                const auto it = contexts.id_to_key.find(entry.contextID);
                id_taken = it != contexts.id_to_key.end() && !(it->second == key);
            }
            if (duplicate) {
                ++report.duplicate;  // 同键保留首条
                continue;
            }
            if (id_taken) {
                ++report.rejected_invalid;  // contextID 已被别的根占用
                continue;
            }

            // 父 contextID 由父进程已落地的归属解析；解析不到说明计划乱序
            uint32_t parent_context = 0;
            if (parent_process.pid != 0) {
                const auto root = root_of(to_context_root, parent_process);
                const auto id =
                    root.has_value() ? context_id_of(*root) : std::nullopt;
                if (!id.has_value()) {
                    ++report.rejected_out_of_order;
                    continue;
                }
                parent_context = *id;
            }

            // 主 context 与归属索引同锁写入；锁序沿用 addContextID
            {
                std::unique_lock lock(contexts.smtx);
                contexts.map.emplace(
                    key, ContextMessage{entry.contextID,
                                        hng::contextattr::UNKNOWN, false});
                contexts.by_attr[hng::contextattr::UNKNOWN].insert(
                    entry.contextID);
                contexts.id_to_key[entry.contextID] = key;
                std::unique_lock tlock(to_context_root.smtx);
                to_context_root.map[process] = key;
                to_context_root.processes_by_root[key].insert(process);
            }
            if (parent_context != 0) {
                std::unique_lock lock(parent.smtx);
                parent.map.emplace(entry.contextID, parent_context);
            }
            ++report.inserted;
            continue;
        }

        // BIND：并入父进程所属 context 的成员集，不新建 context
        if (entry.contextID != 0 || parent_process.pid == 0) {
            ++report.rejected_invalid;
            continue;
        }
        const auto root = root_of(to_context_root, parent_process);
        if (!root.has_value()) {
            ++report.rejected_out_of_order;  // 父尚未落地
            continue;
        }
        {
            std::unique_lock lock(to_context_root.smtx);
            if (to_context_root.map.find(process) != to_context_root.map.end()) {
                ++report.duplicate;  // 已归属，保留首条
                continue;
            }
            to_context_root.map[process] = *root;
            to_context_root.processes_by_root[*root].insert(process);
        }
        ++report.bound;
    }
    return report;
}

void ContextStore::add_context(hng::Process p, uint32_t contextID,
                               hng::contextattr attr, ContextParentRef parent)
{
    const hng::RelationTimePoint now = options_.now();
    addContextID(p, contextID, attr, parent, now);
    expire_pending(now);
    refresh_depths();
}

void ContextStore::add_extra_context(hng::Process p, uint32_t contextID,
                                     hng::contextattr attr)
{
    const hng::RelationTimePoint now = options_.now();
    addExtraContext(p, contextID, attr, now);
    expire_pending(now);
    refresh_depths();
}

void ContextStore::remove_context(hng::Process p)
{
    const hng::RelationTimePoint now = options_.now();
    delContextID(p, now);
    expire_pending(now);
    refresh_depths();
}

std::optional<hng::contextattr> ContextStore::set_attr(hng::Process p,
                                                       uint32_t contextID,
                                                       hng::contextattr attr)
{
    const hng::RelationTimePoint now = options_.now();
    const auto changed               = set_attr_(p, contextID, attr);
    expire_pending(now);
    refresh_depths();
    return changed;
}

void ContextStore::bind_to_root(hng::Process p, ContextParentRef parent)
{
    const hng::RelationTimePoint now = options_.now();
    bind_to_ctxroot_(p, parent, now);
    expire_pending(now);
    refresh_depths();
}

void ContextStore::on_process_exited(hng::Process p)
{
    const hng::RelationTimePoint now = options_.now();
    on_process_exited_(p, now);
    expire_pending(now);
    refresh_depths();
}

std::optional<ContextTombstone> ContextStore::find_tombstone(
    hng::Process p, hng::RelationTimePoint now)
{
    auto tombstone = tombstones_.find(p, now);
    if (tombstone.has_value()) {
        ++tombstone_hits_;
    }
    return tombstone;
}

std::optional<ContextKey> ContextStore::resolve_root_of(
    hng::Process anchor, hng::RelationTimePoint now)
{
    std::optional<ContextKey> owned;
    {
        std::shared_lock lock(to_context_root.smtx);
        auto it = to_context_root.map.find(anchor);
        if (it != to_context_root.map.end()) {
            owned = it->second;
        }
    }
    // 显式注销不清归属索引，故须确认该根键仍有 context 记录
    if (owned.has_value() && context_exists(*owned)) {
        return owned;
    }

    const ContextKey self{anchor.pid, anchor.pid_start_time};
    {
        std::shared_lock lock(contexts.smtx);
        if (contexts.map.find(self) != contexts.map.end()) {
            return self;
        }
    }

    auto tombstone = find_tombstone(anchor, now);
    if (!tombstone.has_value()) {
        return std::nullopt;
    }
    if (tombstone->last_root.has_value()) {
        std::shared_lock lock(contexts.smtx);
        if (contexts.map.find(*tombstone->last_root) != contexts.map.end()) {
            return tombstone->last_root;
        }
    }
    if (tombstone->context_id != 0) {
        std::shared_lock lock(contexts.smtx);
        auto it = contexts.id_to_key.find(tombstone->context_id);
        if (it != contexts.id_to_key.end()) {
            return it->second;
        }
    }
    return std::nullopt;
}

std::optional<uint32_t> ContextStore::resolve_context_id_of(
    hng::Process anchor, hng::RelationTimePoint now)
{
    auto root = resolve_root_of(anchor, now);
    if (!root.has_value()) {
        return std::nullopt;
    }
    return context_id_of(*root);
}

std::optional<uint32_t> ContextStore::context_id_of(const ContextKey& key)
{
    std::shared_lock lock(contexts.smtx);
    auto it = contexts.map.find(key);
    if (it == contexts.map.end()) {
        return std::nullopt;
    }
    return it->second.contextID;
}

bool ContextStore::context_exists(const ContextKey& key) const
{
    std::shared_lock lock(contexts.smtx);
    return contexts.map.find(key) != contexts.map.end();
}

void ContextStore::addContextID(hng::Process p, uint32_t contextID,
                                hng::contextattr attr,
                                ContextParentRef parent_ref,
                                hng::RelationTimePoint now)
{
    if (find_tombstone(p, now).has_value()) {
        ++late_register_;
        return;
    }

    const ContextKey key{p.pid, p.pid_start_time};
    bool duplicate = false;
    {
        std::shared_lock lock(contexts.smtx);
        duplicate = contexts.map.find(key) != contexts.map.end();
    }
    if (duplicate) {
        ++duplicate_context_;  // 同键重复注册：保留首条
        drain_waiters(p, now, 0);
        return;
    }

    // 该进程已有自己的 context（含决策翻转）：不再需要继承父 context
    if (bind_pending_.cancel(p).has_value()) {
        ++pending_cancelled_;
    }

    uint32_t pcontextID = 0;
    if (parent_ref.process.pid != 0 && !(parent_ref.process == p)) {
        if (auto id = resolve_context_id_of(parent_ref.process, now)) {
            pcontextID = *id;
        }
        else {
            const bool parent_dead =
                find_tombstone(parent_ref.process, now).has_value();
            if (parent_ref.expected && !parent_dead) {
                const auto result = link_pending_.defer(
                    parent_ref.process, p, LinkAction{p, contextID}, now);
                if (result == decltype(link_pending_)::Result::DEFERRED) {
                    ++pending_deferred_;
                    ++ctxroot_parent_unsettled_;
                }
                else {
                    ++pending_rejected_;
                    ++parent_missing_;
                }
            }
            else {
                ++parent_missing_;
            }
        }
    }

    {
        std::unique_lock lock(contexts.smtx);
        contexts.map.emplace(key, ContextMessage{contextID, attr, false});
        contexts.by_attr[attr].insert(contextID);
        contexts.id_to_key[contextID] = key;
        // 根进程也是其 context 的一员：登记 进程→自身根，使 lookup/挂靠可用
        std::unique_lock tlock(to_context_root.smtx);
        to_context_root.map[p] = key;
        to_context_root.processes_by_root[key].insert(p);
    }

    if (pcontextID != 0) {
        std::unique_lock lock(parent.smtx);
        parent.map.emplace(contextID, pcontextID);
    }

    drain_waiters(p, now, 0);
}

void ContextStore::addExtraContext(hng::Process p, uint32_t contextID,
                                   hng::contextattr attr,
                                   hng::RelationTimePoint now)
{
    if (find_tombstone(p, now).has_value()) {
        ++extra_orphaned_;
        return;
    }

    const ContextKey key{p.pid, p.pid_start_time};
    uint32_t primaryID = 0;

    {
        std::unique_lock lock(contexts.smtx);

        auto it = contexts.map.find(key);
        if (it == contexts.map.end()) {
            ++extra_orphaned_;
            return;  // 无主 context：不能登记附属 context
        }
        primaryID = it->second.contextID;

        std::unique_lock xlock(extras.smtx);
        if (extras.map.find(key) != extras.map.end()) {
            return;  // 已有附属 context：保留首个
        }

        extras.map.emplace(key, ContextMessage{contextID, attr, false});
        extras.by_attr[attr].insert(contextID);
        extras.id_to_key[contextID] = key;
        it->second.has_extra        = true;
    }  // 释放 contexts/extras 锁后再记录 parent 关系

    std::unique_lock lock(parent.smtx);
    parent.map.emplace(contextID, primaryID);
}

void ContextStore::delContextID(hng::Process p, hng::RelationTimePoint now)
{
    const ContextKey key{p.pid, p.pid_start_time};
    if (find_tombstone(p, now).has_value() && !context_exists(key)) {
        return;  // 对已退出进程的幂等注销
    }

    std::optional<uint32_t> primaryID;
    std::optional<uint32_t> attachedID;

    {
        std::unique_lock lock(contexts.smtx);

        auto it = contexts.map.find(key);
        if (it == contexts.map.end()) {
            ++unknown_unregister_;
            return;
        }
        const uint32_t primary_id = it->second.contextID;
        primaryID                 = primary_id;
        erase_from_attr_index(contexts.by_attr, it->second.attr, primary_id);
        contexts.id_to_key.erase(primary_id);
        contexts.map.erase(it);
    }  // 释放 contexts 锁后再更新 extras,避免持锁顺序问题

    {
        std::unique_lock lock(extras.smtx);

        auto eit = extras.map.find(key);
        if (eit != extras.map.end()) {
            const uint32_t attached_id = eit->second.contextID;
            attachedID                 = attached_id;
            erase_from_attr_index(extras.by_attr, eit->second.attr, attached_id);
            extras.id_to_key.erase(attached_id);
            extras.map.erase(eit);
        }
    }

    {
        std::unique_lock lock(parent.smtx);
        if (primaryID.has_value()) {
            parent.map.erase(*primaryID);
        }
        if (attachedID.has_value()) {
            parent.map.erase(*attachedID);
        }
    }

    fail_waiters(p, 0);

    if (link_pending_.cancel(p).has_value()) {
        ++pending_cancelled_;
    }
    if (bind_pending_.cancel(p).has_value()) {
        ++pending_cancelled_;
    }
}

std::optional<hng::contextattr> ContextStore::set_attr_(hng::Process p,
                                                        uint32_t contextID,
                                                        hng::contextattr attr)
{
    bool changed = false;
    {
        std::unique_lock lock(contexts.smtx);

        auto it = contexts.map.find(ContextKey{p.pid, p.pid_start_time});
        if (it == contexts.map.end()) {
            return std::nullopt;
        }

        if (it->second.contextID == contextID) {
            // 目标在主 context
            if (it->second.attr == hng::contextattr::UNKNOWN) {
                erase_from_attr_index(contexts.by_attr, it->second.attr,
                                      contextID);
                it->second.attr = attr;
                contexts.by_attr[attr].insert(contextID);
                changed = true;
            }
        }
        else if (it->second.has_extra) {
            // TODO: 这里也许应该删除，附属 context 设计无属性变更
            // 目标不在主 context,查附属 context
            std::unique_lock xlock(extras.smtx);
            auto eit = extras.map.find(ContextKey{p.pid, p.pid_start_time});
            if (eit != extras.map.end() && eit->second.contextID == contextID) {
                if (eit->second.attr == hng::contextattr::UNKNOWN) {
                    erase_from_attr_index(extras.by_attr, eit->second.attr,
                                          contextID);
                    eit->second.attr = attr;
                    extras.by_attr[attr].insert(contextID);
                    changed = true;
                }
            }
        }
    }

    if (!changed) {
        return std::nullopt;
    }
    return attr;
}

void ContextStore::bind_to_ctxroot_(hng::Process p, ContextParentRef parent,
                                    hng::RelationTimePoint now)
{
    if (find_tombstone(p, now).has_value()) {
        ++late_bind_;
        return;
    }

    std::optional<ContextKey> existing;
    {
        std::shared_lock lock(to_context_root.smtx);
        auto it = to_context_root.map.find(p);
        if (it != to_context_root.map.end()) {
            existing = it->second;
        }
    }
    if (existing.has_value()) {
        const bool resolvable =
            parent.process.pid != 0 && parent.expected && !(parent.process == p);
        const std::optional<ContextKey> target =
            resolvable ? resolve_root_of(parent.process, now) : std::nullopt;
        if (target.has_value() && !(*target == *existing)) {
            ++ownership_conflict_;
            return;  // 归属不可变，保留首条
        }
        drain_waiters(p, now, 0);
        return;
    }

    if (parent.process.pid == 0 || !parent.expected || parent.process == p) {
        ++bind_orphaned_;
        return;
    }

    if (auto root = resolve_root_of(parent.process, now)) {
        bind_child(p, *root, now, 0);
        return;
    }

    if (find_tombstone(parent.process, now).has_value()) {
        ++bind_orphaned_;
        return;
    }

    const auto result =
        bind_pending_.defer(parent.process, p, std::monostate{}, now);
    if (result == decltype(bind_pending_)::Result::DEFERRED) {
        ++pending_deferred_;
        ++ctxroot_parent_unsettled_;
    }
    else {
        ++pending_rejected_;
        ++bind_orphaned_;
    }
}

bool ContextStore::bind_child(hng::Process child, const ContextKey& root,
                              hng::RelationTimePoint now, uint32_t depth)
{
    if (find_tombstone(child, now).has_value()) {
        return false;
    }

    bool applied = false;
    {
        std::unique_lock lock(to_context_root.smtx);
        auto it = to_context_root.map.find(child);
        if (it == to_context_root.map.end()) {
            to_context_root.map.emplace(child, root);
            to_context_root.processes_by_root[root].insert(child);
            applied = true;
        }
        else if (it->second == root) {
            applied = true;  // 同根重复挂靠：幂等
        }
        else {
            applied = false;  // 归属不可变，保留首条
        }
    }

    if (!applied) {
        ++ownership_conflict_;
        return false;
    }

    drain_waiters(child, now, depth + 1);
    return true;
}

void ContextStore::drain_waiters(hng::Process anchor, hng::RelationTimePoint now,
                                 uint32_t depth)
{
    if (depth > kMaxWaitDepth) {
        return;
    }

    auto root = resolve_root_of(anchor, now);
    if (!root.has_value()) {
        return;
    }
    auto anchorID = resolve_context_id_of(anchor, now);
    if (!anchorID.has_value()) {
        return;
    }

    const std::vector<typename hng::DeferredRelationTable<
        hng::Process, hng::Process, LinkAction>::Entry>
        links = link_pending_.take(anchor);
    if (!links.empty()) {
        std::unique_lock lock(parent.smtx);
        for (const auto& entry : links) {
            parent.map.emplace(entry.action.contextID, *anchorID);
        }
    }
    pending_resolved_ += links.size();

    const std::vector<typename hng::DeferredRelationTable<
        hng::Process, hng::Process, std::monostate>::Entry>
        binds = bind_pending_.take(anchor);
    for (const auto& entry : binds) {
        if (bind_child(entry.waiter, *root, now, depth)) {
            ++pending_resolved_;
        }
    }
}

void ContextStore::fail_waiters(hng::Process anchor, uint32_t depth)
{
    if (depth > kMaxWaitDepth) {
        return;
    }

    const std::vector<typename hng::DeferredRelationTable<
        hng::Process, hng::Process, LinkAction>::Entry>
        links = link_pending_.take(anchor);
    if (!links.empty()) {
        std::unique_lock lock(parent.smtx);
        for (const auto& entry : links) {
            parent.map.erase(entry.action.contextID);
        }
    }
    parent_missing_ += links.size();

    const std::vector<typename hng::DeferredRelationTable<
        hng::Process, hng::Process, std::monostate>::Entry>
        binds = bind_pending_.take(anchor);
    for (const auto& entry : binds) {
        ++bind_orphaned_;
        fail_waiters(entry.waiter, depth + 1);
    }
}

void ContextStore::expire_pending(hng::RelationTimePoint now)
{
    const std::vector<typename hng::DeferredRelationTable<
        hng::Process, hng::Process, LinkAction>::Entry>
        expired_links = link_pending_.expire(now);
    if (!expired_links.empty()) {
        std::unique_lock lock(parent.smtx);
        for (const auto& entry : expired_links) {
            parent.map.erase(entry.action.contextID);
        }
    }
    pending_expired_ += expired_links.size();
    parent_missing_  += expired_links.size();

    const std::vector<typename hng::DeferredRelationTable<
        hng::Process, hng::Process, std::monostate>::Entry>
        expired_binds = bind_pending_.expire(now);
    for (const auto& entry : expired_binds) {
        ++pending_expired_;
        ++bind_orphaned_;
        fail_waiters(entry.waiter, 0);
    }

    tombstones_.expire(now);
}

void ContextStore::refresh_depths()
{
    pending_depth_.store(link_pending_.size() + bind_pending_.size(),
                         std::memory_order_relaxed);
    tombstone_depth_.store(tombstones_.size(), std::memory_order_relaxed);
}

void ContextStore::on_process_exited_(hng::Process p, hng::RelationTimePoint now)
{
    if (find_tombstone(p, now).has_value()) {
        return;  // 已处理过该进程的退出
    }

    // 墓碑必须在移除归属之前写入，供迟到的注册/挂靠拒绝
    ContextTombstone info;
    {
        std::shared_lock lock(to_context_root.smtx);
        auto it = to_context_root.map.find(p);
        if (it != to_context_root.map.end()) {
            info.last_root = it->second;
        }
    }
    if (info.last_root.has_value()) {
        info.context_id = context_id_of(*info.last_root).value_or(0);
    }
    tombstones_.add(p, info, now);

    if (link_pending_.cancel(p).has_value()) {
        ++pending_cancelled_;
    }
    if (bind_pending_.cancel(p).has_value()) {
        ++pending_cancelled_;
    }

    auto links = link_pending_.take(p);
    auto binds = bind_pending_.take(p);
    auto root  = resolve_root_of(p, now);

    // 先收敛以 p 为锚点的挂靠：子进程成为成员，context 不会因 p 退出而清空
    if (root.has_value()) {
        for (const auto& entry : binds) {
            if (bind_child(entry.waiter, *root, now, 0)) {
                ++pending_resolved_;
            }
        }
    }
    else {
        for (const auto& entry : binds) {
            ++bind_orphaned_;
            fail_waiters(entry.waiter, 0);
        }
    }

    std::optional<ContextKey> emptied_root;
    {
        std::unique_lock lock(to_context_root.smtx);
        auto it = to_context_root.map.find(p);
        if (it != to_context_root.map.end()) {
            const ContextKey current_root = it->second;
            to_context_root.map.erase(it);

            auto members = to_context_root.processes_by_root.find(current_root);
            if (members != to_context_root.processes_by_root.end()) {
                members->second.erase(p);
                if (members->second.empty()) {
                    to_context_root.processes_by_root.erase(members);
                    emptied_root = current_root;
                }
            }
        }
    }

    if (emptied_root.has_value() && context_exists(*emptied_root)) {
        delContextID(hng::Process{emptied_root->pid, emptied_root->start_time},
                     now);
    }

    // 再应用以 p 为锚点的父链接：context 已删时保持森林根
    std::optional<uint32_t> surviving_id;
    if (root.has_value()) {
        surviving_id = context_id_of(*root);
    }
    for (const auto& entry : links) {
        if (surviving_id.has_value()) {
            std::unique_lock lock(parent.smtx);
            parent.map.emplace(entry.action.contextID, *surviving_id);
            ++pending_resolved_;
        }
        else {
            ++parent_missing_;
        }
    }
}
