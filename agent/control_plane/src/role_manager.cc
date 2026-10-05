#include "agent/control_plane/src/role_manager.hpp"

#include <utility>

#include "agent/role_discovery/src/role_cgroup_reader.hpp"

RoleManager::RoleManager(RoleManagerProbe probe) : probe_(std::move(probe)) {}

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

void RoleManager::on_process_removed(hng::Process p)
{
    enqueue(RoleTask{RemovedMessage{p}});
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
        store_.bind_to_role(bind->child, bind->parent);
    }
    else if (auto* removed = std::get_if<RemovedMessage>(&task)) {
        store_.on_process_removed(removed->process);
    }
}

void RoleManager::land_event(const hng::role::RoleEvent& event)
{
    switch (event.action) {
        case hng::role::RoleAction::JOIN:
            notify(store_.join(event.payload, member_set(event.payload)));
            break;
        case hng::role::RoleAction::MAIN_PROCESS_CHANGE:
            notify(store_.main_process_change(event.payload,
                                              member_set(event.payload)));
            break;
        case hng::role::RoleAction::LEAVE:
            // 退出不重读 cgroup：成员由记录的反向索引定向删
            notify(store_.leave(event.payload.identity.instance_key));
            break;
    }
}

std::vector<hng::Process> RoleManager::member_set(
    const hng::role::RolePayload& payload)
{
    std::vector<hng::Process> members = payload.member_processes;

    if (!payload.cgroup_path.empty()) {
        std::vector<hng::Process> reread =
            probe_.read_members
                ? probe_.read_members(payload.cgroup_path)
                : hng::role::RoleCgroupReader::read(payload.cgroup_path);
        if (reread.empty()) {
            cgroup_read_empty_.fetch_add(1, std::memory_order_relaxed);
        }
        members.insert(members.end(), reread.begin(), reread.end());
    }

    members.push_back(payload.main_process);
    return members;
}

void RoleManager::notify(const RoleTransition& transition)
{
    if (transition.kind == RoleTransition::Kind::NONE) {
        return;  // 幂等重放、入口拒收、未知实例键：一次都不通知
    }
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

std::optional<uint32_t> RoleManager::lookup(hng::Process p) const
{
    return store_.lookup(p);
}

std::optional<hng::Role> RoleManager::role(uint32_t role_id) const
{
    return store_.role(role_id);
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
    snapshot.store = store_.stats();
    snapshot.cgroup_read_empty =
        cgroup_read_empty_.load(std::memory_order_relaxed);
    snapshot.queue_rejected = queue_rejected_.load(std::memory_order_relaxed);
    return snapshot;
}
