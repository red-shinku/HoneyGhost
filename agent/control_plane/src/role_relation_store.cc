#include "agent/control_plane/src/role_relation_store.hpp"

#include <algorithm>
#include <mutex>
#include <utility>

#include "agent/control_plane/src/role_label_builder.hpp"

namespace {

/// 入口拒收判据：缺实例键或锚点
bool acceptable(const hng::role::RolePayload& payload)
{
    return !payload.identity.instance_key.empty() &&
           payload.main_process.pid != 0 &&
           payload.main_process.pid_start_time != 0;
}

}  // namespace

RoleRelationStore::RoleRelationStore(RoleRelationOptions options)
    : options_(std::move(options)),
      bind_pending_(options_.bind_pending),
      tombstones_(options_.tombstones)
{
}

RoleTransition RoleRelationStore::join(const hng::role::RolePayload& payload,
                                       const std::vector<hng::Process>& members)
{
    std::unique_lock lock(mutex_);
    const hng::RelationTimePoint now = options_.now();

    if (!acceptable(payload)) {
        ++stats_.rejected;
        return RoleTransition{};
    }

    auto instance = instance_to_role_.find(payload.identity.instance_key);
    if (instance != instance_to_role_.end()) {
        uint32_t role_id = instance->second;
        auto record      = role_table_.find(role_id);
        if (record == role_table_.end()) {
            return RoleTransition{};
        }
        RoleTransition transition{};
        if (record->second.main_process == payload.main_process) {
            adopt_all(role_id, record->second, payload.main_process, members,
                      now);
        }
        else {
            transition =
                rebind_anchor(role_id, record->second, payload, members, now);
        }
        drain_anchor(payload.main_process, now, 0);
        for (const hng::Process& p : members) {
            drain_anchor(p, now, 0);
        }
        return transition;
    }

    uint32_t role_id = next_role_id_++;
    instance_to_role_.emplace(payload.identity.instance_key, role_id);

    auto record          = role_table_.emplace(role_id, RoleRecord{});
    RoleRecord& fresh    = record.first->second;
    fresh.role.roleID    = role_id;
    fresh.role.roleLabel = RoleLabelBuilder::build(payload.identity);
    fresh.identity       = payload.identity;
    fresh.main_process   = payload.main_process;
    fresh.cgroup_path    = payload.cgroup_path;
    adopt_all(role_id, fresh, payload.main_process, members, now);
    drain_anchor(payload.main_process, now, 0);
    for (const hng::Process& p : members) {
        drain_anchor(p, now, 0);
    }

    return RoleTransition{RoleTransition::Kind::JOINED, fresh.role};
}

RoleTransition RoleRelationStore::main_process_change(
    const hng::role::RolePayload& payload,
    const std::vector<hng::Process>& members)
{
    std::unique_lock lock(mutex_);
    const hng::RelationTimePoint now = options_.now();

    if (!acceptable(payload)) {
        ++stats_.rejected;
        return RoleTransition{};
    }

    auto instance = instance_to_role_.find(payload.identity.instance_key);
    if (instance == instance_to_role_.end()) {
        ++stats_.unknown_instance;
        return RoleTransition{};
    }

    uint32_t role_id = instance->second;
    auto record      = role_table_.find(role_id);
    if (record == role_table_.end()) {
        return RoleTransition{};
    }
    RoleTransition transition{};
    if (record->second.main_process == payload.main_process) {
        adopt_all(role_id, record->second, payload.main_process, members, now);
    }
    else {
        transition =
            rebind_anchor(role_id, record->second, payload, members, now);
    }
    drain_anchor(payload.main_process, now, 0);
    for (const hng::Process& p : members) {
        drain_anchor(p, now, 0);
    }
    return transition;
}

RoleTransition RoleRelationStore::leave(const std::string& instance_key)
{
    std::unique_lock lock(mutex_);

    auto instance = instance_to_role_.find(instance_key);
    if (instance == instance_to_role_.end()) {
        ++stats_.unknown_instance;
        return RoleTransition{};
    }
    uint32_t role_id = instance->second;
    supervised_.erase(role_id);

    auto record = role_table_.find(role_id);
    if (record == role_table_.end()) {
        instance_to_role_.erase(instance);
        return RoleTransition{};
    }

    // 只按反向索引遍历，不扫全表；核对当前值，故不误删已被别的角色认领的条目
    for (const hng::Process& p : record->second.entries) {
        bind_pending_.cancel(p);
        fail_anchor(p, 0);
        auto owned = process_to_role_.find(p);
        if (owned != process_to_role_.end() && owned->second == role_id) {
            process_to_role_.erase(owned);
        }
    }
    if (record->second.anchor_removed) {
        --stats_.anchors_removed;
    }
    const hng::Role role = record->second.role;
    instance_to_role_.erase(instance);
    role_table_.erase(record);

    return RoleTransition{RoleTransition::Kind::LEFT, role};
}

void RoleRelationStore::bind_to_role(hng::Process child, hng::Process parent)
{
    std::unique_lock lock(mutex_);
    const hng::RelationTimePoint now = options_.now();

    if (tombstones_.find(child, now).has_value()) {
        ++stats_.bind_rejected;
        return;
    }

    auto child_owned = process_to_role_.find(child);
    if (child_owned != process_to_role_.end()) {
        ++stats_.bind_ignored;
        drain_anchor(child, now, 0);
        return;
    }

    auto parent_owned = process_to_role_.find(parent);
    if (parent_owned != process_to_role_.end()) {
        uint32_t role_id = parent_owned->second;
        auto record      = role_table_.find(role_id);
        if (record != role_table_.end()) {
            if (adopt(role_id, record->second, child, now)) {
                drain_anchor(child, now, 0);
            }
            return;
        }
    }

    if (tombstones_.find(parent, now).has_value()) {
        ++stats_.bind_rejected;
        return;
    }

    const decltype(bind_pending_)::Result result =
        bind_pending_.defer(parent, child, std::monostate{}, now);
    if (result == decltype(bind_pending_)::Result::DEFERRED) {
        ++stats_.bind_deferred;
    }
    else {
        ++stats_.bind_rejected;
    }
}

void RoleRelationStore::on_process_exited(hng::Process p)
{
    std::unique_lock lock(mutex_);
    const hng::RelationTimePoint now = options_.now();

    tombstones_.add(p, std::monostate{}, now);
    bind_pending_.cancel(p);
    fail_anchor(p, 0);

    process_to_role_.erase(p);

    for (auto& entry : role_table_) {
        RoleRecord& record = entry.second;
        if (record.main_process == p && !record.anchor_removed) {
            record.anchor_removed = true;
            ++stats_.anchors_removed;
        }
    }
}

void RoleRelationStore::expire()
{
    std::unique_lock lock(mutex_);
    const hng::RelationTimePoint now = options_.now();

    for (const auto& entry : bind_pending_.expire(now)) {
        (void)entry;
        ++stats_.bind_expired;
    }
    tombstones_.expire(now);
}

bool RoleRelationStore::is_dead(hng::Process p)
{
    std::unique_lock lock(mutex_);

    return tombstones_.find(p, options_.now()).has_value();
}

std::optional<uint32_t> RoleRelationStore::lookup(hng::Process p) const
{
    std::shared_lock lock(mutex_);

    auto owned = process_to_role_.find(p);
    if (owned == process_to_role_.end()) {
        return std::nullopt;
    }
    return owned->second;
}

std::optional<hng::Role> RoleRelationStore::role(uint32_t role_id) const
{
    std::shared_lock lock(mutex_);

    auto record = role_table_.find(role_id);
    if (record == role_table_.end()) {
        return std::nullopt;
    }
    return record->second.role;
}

std::optional<hng::Process> RoleRelationStore::main_process(
    uint32_t role_id) const
{
    std::shared_lock lock(mutex_);

    auto record = role_table_.find(role_id);
    if (record == role_table_.end() || record->second.anchor_removed) {
        return std::nullopt;
    }
    return record->second.main_process;
}

std::vector<hng::Role> RoleRelationStore::roles() const
{
    std::shared_lock lock(mutex_);

    std::vector<hng::Role> result;
    result.reserve(role_table_.size());
    for (const auto& entry : role_table_) {
        result.push_back(entry.second.role);
    }
    std::sort(result.begin(), result.end(),
              [](const hng::Role& lhs, const hng::Role& rhs) {
                  return lhs.roleID < rhs.roleID;
              });
    return result;
}

void RoleRelationStore::set_supervised(uint32_t role_id, bool supervised)
{
    std::unique_lock lock(mutex_);

    if (!supervised) {
        supervised_.erase(role_id);
        return;
    }
    if (role_table_.find(role_id) != role_table_.end()) {
        supervised_.insert(role_id);
    }
}

std::vector<hng::Role> RoleRelationStore::supervised_roles() const
{
    std::shared_lock lock(mutex_);

    std::vector<hng::Role> result;
    result.reserve(supervised_.size());
    for (uint32_t role_id : supervised_) {
        auto record = role_table_.find(role_id);
        if (record != role_table_.end()) {
            result.push_back(record->second.role);
        }
    }
    std::sort(result.begin(), result.end(),
              [](const hng::Role& lhs, const hng::Role& rhs) {
                  return lhs.roleID < rhs.roleID;
              });
    return result;
}

std::optional<hng::role::RoleIdentity> RoleRelationStore::identity(
    uint32_t role_id) const
{
    std::shared_lock lock(mutex_);

    auto record = role_table_.find(role_id);
    if (record == role_table_.end()) {
        return std::nullopt;
    }
    return record->second.identity;
}

std::optional<std::string> RoleRelationStore::cgroup_path(uint32_t role_id) const
{
    std::shared_lock lock(mutex_);

    auto record = role_table_.find(role_id);
    if (record == role_table_.end()) {
        return std::nullopt;
    }
    return record->second.cgroup_path;
}

RoleStoreStats RoleRelationStore::stats() const
{
    std::shared_lock lock(mutex_);

    RoleStoreStats snapshot  = stats_;
    snapshot.tombstone_depth = tombstones_.size();
    return snapshot;
}

bool RoleRelationStore::adopt(uint32_t role_id, RoleRecord& record,
                              hng::Process p, hng::RelationTimePoint now)
{
    if (tombstones_.find(p, now).has_value()) {
        return false;
    }

    auto owned = process_to_role_.find(p);
    if (owned == process_to_role_.end()) {
        process_to_role_.emplace(p, role_id);
    }
    else if (owned->second != role_id) {
        owned->second = role_id;
        ++stats_.owner_conflict;
    }
    record.entries.insert(p);
    return true;
}

void RoleRelationStore::adopt_all(uint32_t role_id, RoleRecord& record,
                                  hng::Process anchor,
                                  const std::vector<hng::Process>& members,
                                  hng::RelationTimePoint now)
{
    if (!adopt(role_id, record, anchor, now)) {
        ++stats_.late_adopt_rejected;
    }
    for (const hng::Process& p : members) {
        if (!adopt(role_id, record, p, now)) {
            ++stats_.late_adopt_rejected;
        }
    }
}

void RoleRelationStore::drain_anchor(hng::Process anchor,
                                     hng::RelationTimePoint now, int depth)
{
    if (depth >= kMaxDrainDepth) {
        return;
    }

    auto owned = process_to_role_.find(anchor);
    if (owned == process_to_role_.end()) {
        return;
    }
    const uint32_t role_id = owned->second;
    if (role_table_.find(role_id) == role_table_.end()) {
        return;
    }

    const auto waiters = bind_pending_.take(anchor);
    for (const auto& entry : waiters) {
        const hng::Process child = entry.waiter;
        if (tombstones_.find(child, now).has_value()) {
            ++stats_.bind_rejected;
            continue;
        }
        if (process_to_role_.find(child) == process_to_role_.end()) {
            auto record = role_table_.find(role_id);
            if (record == role_table_.end() ||
                !adopt(role_id, record->second, child, now)) {
                ++stats_.bind_rejected;
                continue;
            }
        }
        ++stats_.bind_resolved;
        drain_anchor(child, now, depth + 1);
    }
}

void RoleRelationStore::fail_anchor(hng::Process anchor, int depth)
{
    if (depth >= kMaxDrainDepth) {
        return;
    }

    const auto waiters = bind_pending_.take(anchor);
    for (const auto& entry : waiters) {
        ++stats_.bind_rejected;
        fail_anchor(entry.waiter, depth + 1);
    }
}

RoleTransition RoleRelationStore::rebind_anchor(
    uint32_t role_id, RoleRecord& record, const hng::role::RolePayload& payload,
    const std::vector<hng::Process>& members, hng::RelationTimePoint now)
{
    // 锚点更换后不再是「锚点已删」：这里说的是旧锚点
    if (record.anchor_removed) {
        record.anchor_removed = false;
        --stats_.anchors_removed;
    }

    // 并入而非覆盖 entries：覆盖会丢掉旧键，LEAVE 便漏删
    adopt_all(role_id, record, payload.main_process, members, now);

    record.identity       = payload.identity;
    record.main_process   = payload.main_process;
    record.cgroup_path    = payload.cgroup_path;
    record.role.roleLabel = RoleLabelBuilder::build(payload.identity);

    return RoleTransition{RoleTransition::Kind::MAIN_PROCESS_CHANGED,
                          record.role};
}
