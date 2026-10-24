#include "agent/control_plane/src/role_manager.hpp"

#include <utility>

#include "agent/role_discovery/src/role_cgroup_reader.hpp"

RoleManager::RoleManager(RoleManagerProbe probe, RoleRelationOptions options)
    : probe_(std::move(probe)), store_(std::move(options))
{
}

void RoleManager::add_lifecycle_sink(RoleLifecycleSink* sink)
{
    if (sink == nullptr) {
        return;
    }
    lifecycle_sinks_.push_back(sink);
}

void RoleManager::on_role_event(const hng::role::RoleEvent& event)
{
    enqueue(RoleTask{event});
}

void RoleManager::bind_to_role(hng::Process child, hng::Process parent)
{
    enqueue(RoleTask{BindMessage{child, parent}});
}

void RoleManager::on_process_exited(hng::Process p)
{
    enqueue(RoleTask{ExitedMessage{p}});
}

void RoleManager::enqueue(RoleTask task)
{
    if (!queue_.push(std::move(task))) {
        queue_rejected_.fetch_add(1, std::memory_order_relaxed);
    }
}

void RoleManager::run()
{
    RoleTask task;
    // 取与处理分离：队列临界区内没有 cgroup 读取，也没有出口回调
    while (queue_.wait_pop(task)) {
        land(task);
    }
}

void RoleManager::stop() { queue_.stop(); }

void RoleManager::land(RoleTask& task)
{
    if (auto* event = std::get_if<hng::role::RoleEvent>(&task)) {
        land_event(*event);
    }
    else if (auto* bind = std::get_if<BindMessage>(&task)) {
        notify_members(store_.bind_to_role(bind->child, bind->parent));
    }
    else if (auto* exited = std::get_if<ExitedMessage>(&task)) {
        store_.on_process_exited(exited->process);
    }

    store_.expire();
}

void RoleManager::land_event(const hng::role::RoleEvent& event)
{
    switch (event.action) {
        case hng::role::RoleAction::JOIN:
            if (anchor_exited(event.payload.main_process)) {
                dead_anchor_rejected_.fetch_add(1, std::memory_order_relaxed);
                return;
            }
            notify(store_.join(event.payload, member_set(event.payload)));
            break;
        case hng::role::RoleAction::MAIN_PROCESS_CHANGE:
            if (anchor_exited(event.payload.main_process)) {
                dead_anchor_rejected_.fetch_add(1, std::memory_order_relaxed);
                return;
            }
            notify(store_.main_process_change(event.payload,
                                              member_set(event.payload)));
            break;
        case hng::role::RoleAction::LEAVE:
            // 退出不重读 cgroup：成员由记录的反向索引定向删
            notify(store_.leave(event.payload.identity.instance_key));
            break;
    }
}

bool RoleManager::anchor_exited(hng::Process p)
{
    if (probe_.is_exited && probe_.is_exited(p)) {
        return true;
    }
    return store_.is_dead(p);
}

std::vector<hng::Process> RoleManager::member_set(
    const hng::role::RolePayload& payload)
{
    std::vector<hng::Process> members;

    auto append = [this, &members](const hng::Process& p) {
        if (probe_.is_exited && probe_.is_exited(p)) {
            dead_member_rejected_.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        members.push_back(p);
    };

    for (const hng::Process& p : payload.member_processes) {
        append(p);
    }

    if (!payload.cgroup_path.empty()) {
        std::vector<hng::Process> reread =
            probe_.read_members
                ? probe_.read_members(payload.cgroup_path)
                : hng::role::RoleCgroupReader::read(payload.cgroup_path);
        if (reread.empty()) {
            cgroup_read_empty_.fetch_add(1, std::memory_order_relaxed);
        }
        for (const hng::Process& p : reread) {
            append(p);
        }
    }

    append(payload.main_process);
    return members;
}

void RoleManager::notify(const RoleTransition& transition)
{
    // 生命周期通知先于本次落地的新增成员：订阅方先建立角色再收成员
    if (transition.kind != RoleTransition::Kind::NONE) {
        for (RoleLifecycleSink* sink : lifecycle_sinks_) {
            switch (transition.kind) {
                case RoleTransition::Kind::NONE:
                    break;  // 上面已排除
                case RoleTransition::Kind::JOINED:
                    sink->on_role_joined(transition.role);
                    break;
                case RoleTransition::Kind::LEFT:
                    sink->on_role_left(transition.role);
                    break;
                case RoleTransition::Kind::MAIN_PROCESS_CHANGED:
                    sink->on_role_main_process_changed(transition.role);
                    break;
            }
        }
    }
    notify_members(transition.members);
}

void RoleManager::notify_members(const RoleMemberChanges& changes)
{
    for (const RoleMemberChanges::Entry& entry : changes.entries) {
        if (entry.members.empty()) {
            continue;
        }
        /** @note 落地已释放关系表锁，此处查角色视图可能拿到已被 LEAVE 删掉的
         * 结果，跳过即可。 */
        std::optional<hng::Role> role = store_.role(entry.role_id);
        if (!role) {
            continue;
        }
        for (RoleLifecycleSink* sink : lifecycle_sinks_) {
            sink->on_role_members_changed(*role, entry.members);
        }
    }
}

std::optional<uint32_t> RoleManager::lookup(hng::Process p) const
{
    return store_.lookup(p);
}

std::optional<hng::Role> RoleManager::role(uint32_t role_id) const
{
    return store_.role(role_id);
}

std::optional<hng::Process> RoleManager::main_process(uint32_t role_id) const
{
    return store_.main_process(role_id);
}

std::vector<hng::Role> RoleManager::roles() const { return store_.roles(); }

std::vector<hng::Role> RoleManager::supervised_roles() const
{
    return store_.supervised_roles();
}

void RoleManager::set_supervised(uint32_t role_id, bool supervised)
{
    store_.set_supervised(role_id, supervised);
}

std::optional<hng::role::RoleIdentity> RoleManager::identity(
    uint32_t role_id) const
{
    return store_.identity(role_id);
}

std::vector<hng::Process> RoleManager::members(uint32_t role_id) const
{
    std::optional<std::string> cgroup_path = store_.cgroup_path(role_id);
    if (!cgroup_path || cgroup_path->empty()) {
        return {};
    }
    if (probe_.read_members) {
        return probe_.read_members(*cgroup_path);
    }
    return hng::role::RoleCgroupReader::read(*cgroup_path);
}

RoleManagerStats RoleManager::stats() const
{
    RoleManagerStats snapshot;
    snapshot.store               = store_.stats();
    snapshot.bind_deferred       = snapshot.store.bind_deferred;
    snapshot.bind_resolved       = snapshot.store.bind_resolved;
    snapshot.bind_rejected       = snapshot.store.bind_rejected;
    snapshot.bind_expired        = snapshot.store.bind_expired;
    snapshot.bind_ignored        = snapshot.store.bind_ignored;
    snapshot.late_adopt_rejected = snapshot.store.late_adopt_rejected;
    snapshot.tombstone_depth     = snapshot.store.tombstone_depth;
    snapshot.cgroup_read_empty =
        cgroup_read_empty_.load(std::memory_order_relaxed);
    snapshot.queue_rejected = queue_rejected_.load(std::memory_order_relaxed);
    snapshot.dead_member_rejected =
        dead_member_rejected_.load(std::memory_order_relaxed);
    snapshot.dead_anchor_rejected =
        dead_anchor_rejected_.load(std::memory_order_relaxed);
    return snapshot;
}
