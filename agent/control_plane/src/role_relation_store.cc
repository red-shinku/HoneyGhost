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

RoleTransition RoleRelationStore::join(const hng::role::RolePayload& payload,
                                       const std::vector<hng::Process>& members)
{
    std::unique_lock lock(mutex_);

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
        if (record->second.main_process == payload.main_process) {
            return RoleTransition{};
        }
        return rebind_anchor(role_id, record->second, payload, members);
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
    adopt_all(role_id, fresh, payload.main_process, members);

    return RoleTransition{RoleTransition::Kind::JOINED, fresh.role};
}

RoleTransition RoleRelationStore::main_process_change(
    const hng::role::RolePayload& payload,
    const std::vector<hng::Process>& members)
{
    std::unique_lock lock(mutex_);

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
    if (record->second.main_process == payload.main_process) {
        return RoleTransition{};
    }
    return rebind_anchor(role_id, record->second, payload, members);
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

    auto record      = role_table_.find(role_id);
    if (record == role_table_.end()) {
        instance_to_role_.erase(instance);
        return RoleTransition{};
    }

    // 只按反向索引遍历，不扫全表；核对当前值，故不误删已被别的角色认领的条目
    for (const hng::Process& p : record->second.entries) {
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

    auto owned = process_to_role_.find(parent);
    if (owned == process_to_role_.end()) {
        return;
    }
    uint32_t role_id = owned->second;

    auto record      = role_table_.find(role_id);
    if (record == role_table_.end()) {
        return;
    }
    adopt(role_id, record->second, child);
}

void RoleRelationStore::on_process_removed(hng::Process p)
{
    std::unique_lock lock(mutex_);

    process_to_role_.erase(p);

    for (auto& entry : role_table_) {
        RoleRecord& record = entry.second;
        if (record.main_process == p && !record.anchor_removed) {
            record.anchor_removed = true;
            ++stats_.anchors_removed;
        }
    }
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

    return stats_;
}

void RoleRelationStore::adopt(uint32_t role_id, RoleRecord& record,
                              hng::Process p)
{
    auto owned = process_to_role_.find(p);
    if (owned == process_to_role_.end()) {
        process_to_role_.emplace(p, role_id);
    }
    else if (owned->second != role_id) {
        owned->second = role_id;
        ++stats_.owner_conflict;
    }
    record.entries.insert(p);
}

void RoleRelationStore::adopt_all(uint32_t role_id, RoleRecord& record,
                                  hng::Process anchor,
                                  const std::vector<hng::Process>& members)
{
    adopt(role_id, record, anchor);
    for (const hng::Process& p : members) {
        adopt(role_id, record, p);
    }
}

RoleTransition RoleRelationStore::rebind_anchor(
    uint32_t role_id, RoleRecord& record, const hng::role::RolePayload& payload,
    const std::vector<hng::Process>& members)
{
    // 锚点更换后不再是「锚点已删」：这里说的是旧锚点
    if (record.anchor_removed) {
        record.anchor_removed = false;
        --stats_.anchors_removed;
    }

    // 并入而非覆盖 entries：覆盖会丢掉旧键，LEAVE 便漏删
    adopt_all(role_id, record, payload.main_process, members);

    record.identity       = payload.identity;
    record.main_process   = payload.main_process;
    record.cgroup_path    = payload.cgroup_path;
    record.role.roleLabel = RoleLabelBuilder::build(payload.identity);

    return RoleTransition{RoleTransition::Kind::MAIN_PROCESS_CHANGED,
                          record.role};
}
