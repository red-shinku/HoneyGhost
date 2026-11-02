#include "agent/control_plane/src/role_manager.hpp"

#include <algorithm>
#include <queue>
#include <unordered_map>
#include <utility>
#include <vector>

#include "agent/role_discovery/src/role_cgroup_reader.hpp"

namespace {

/// @brief 身份的确定性顺序：先按 pid，再按启动时间
bool process_less(const hng::Process& lhs, const hng::Process& rhs)
{
    if (lhs.pid != rhs.pid) {
        return lhs.pid < rhs.pid;
    }
    return lhs.pid_start_time < rhs.pid_start_time;
}

}  // namespace

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

bool RoleManager::enqueue(RoleTask task)
{
    if (queue_.push(std::move(task))) {
        return true;
    }
    queue_rejected_.fetch_add(1, std::memory_order_relaxed);
    return false;
}

void RoleManager::run()
{
    if (state_.load(std::memory_order_acquire) != hng::ComponentState::READY) {
        return;
    }
    state_.store(hng::ComponentState::RUNNING, std::memory_order_release);

    RoleTask task;
    // 取与处理分离：队列临界区内没有 cgroup 读取，也没有出口回调
    while (queue_.wait_pop(task)) {
        land(task);
    }

    state_.store(hng::ComponentState::STOPPED, std::memory_order_release);
}

void RoleManager::stop()
{
    queue_.stop();
    if (state_.load(std::memory_order_acquire) != hng::ComponentState::RUNNING) {
        state_.store(hng::ComponentState::STOPPED, std::memory_order_release);
    }
}

void RoleManager::drain()
{
    RoleTask task;
    while (queue_.try_pop(task)) {
        land(task);
    }
}

bool RoleManager::barrier(std::chrono::milliseconds timeout)
{
    if (state_.load(std::memory_order_acquire) != hng::ComponentState::RUNNING) {
        return false;
    }
    auto done                = std::make_shared<std::promise<void>>();
    std::future<void> landed = done->get_future();
    if (!enqueue(RoleTask{BarrierMessage{std::move(done)}})) {
        return false;
    }
    return landed.wait_for(timeout) == std::future_status::ready;
}

hng::ComponentState RoleManager::state() const
{
    return state_.load(std::memory_order_relaxed);
}

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
    else if (auto* barrier_task = std::get_if<BarrierMessage>(&task)) {
        // 屏障不写表：此前任务都已落地，置位即可
        if (barrier_task->done) {
            barrier_task->done->set_value();
        }
        return;
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

RoleReconcileReport RoleManager::reconcile(const hng::ProcessSeedBatch& batch)
{
    RoleReconcileReport report;
    if (state_.load(std::memory_order_acquire) !=
        hng::ComponentState::CONSTRUCTED) {
        report.rejected_state = 1;
        return report;
    }
    report.snapshot_complete = batch.complete;

    // 批次身份：每个身份只留首条；无效身份不参与任何一步
    std::vector<hng::ProcessSeedEntry> nodes;
    nodes.reserve(batch.entries.size());
    std::unordered_map<hng::Process, std::size_t> index;
    index.reserve(batch.entries.size());
    for (const hng::ProcessSeedEntry& entry : batch.entries) {
        if (entry.process.pid == 0 || entry.process.pid_start_time == 0) {
            continue;
        }
        if (!index.emplace(entry.process, nodes.size()).second) {
            continue;
        }
        nodes.push_back(entry);
    }

    const std::vector<hng::Process> owned = store_.ownership_processes();
    report.ownership_entries              = owned.size();

    // ① 幽灵清理：仅完整快照；/proc 无结论时按未知保留
    if (batch.complete) {
        for (const hng::Process& p : owned) {
            if (index.find(p) != index.end()) {
                continue;
            }
            if (!probe_.is_exited) {
                ++report.proc_unknown;
                continue;
            }
            if (!probe_.is_exited(p)) {
                continue;
            }
            store_.on_process_exited(p);
            ++report.pruned;
        }
    }

    // ② 父先子后：确定性 Kahn，就绪按 pid 升序；理论无环，残留按 pid 升序
    //    当根补尾；父边只在 ppid 与 ppid_start_time 都已知且父在批内时成立
    const std::size_t count = nodes.size();
    std::vector<std::size_t> indegree(count, 0);
    std::vector<std::vector<std::size_t>> children(count);
    std::vector<int> parent_of(count, -1);
    for (std::size_t i = 0; i < count; ++i) {
        const hng::ProcessSeedEntry& entry = nodes[i];
        if (entry.ppid == 0 || entry.ppid_start_time == 0) {
            continue;
        }
        auto parent = index.find(hng::Process{entry.ppid, entry.ppid_start_time});
        if (parent == index.end() || parent->second == i) {
            continue;
        }
        parent_of[i] = static_cast<int>(parent->second);
        ++indegree[i];
        children[parent->second].push_back(i);
    }

    const auto later = [&nodes](std::size_t lhs, std::size_t rhs) {
        return process_less(nodes[lhs].process, nodes[rhs].process);
    };
    std::priority_queue<std::size_t, std::vector<std::size_t>, decltype(later)>
        ready(later);
    for (std::size_t i = 0; i < count; ++i) {
        if (indegree[i] == 0) {
            ready.push(i);
        }
    }

    std::vector<std::size_t> order;
    order.reserve(count);
    std::vector<bool> placed(count, false);
    while (!ready.empty()) {
        const std::size_t i = ready.top();
        ready.pop();
        placed[i] = true;
        order.push_back(i);
        for (std::size_t child : children[i]) {
            if (--indegree[child] == 0) {
                ready.push(child);
            }
        }
    }
    if (order.size() != count) {
        std::vector<std::size_t> rest;
        for (std::size_t i = 0; i < count; ++i) {
            if (!placed[i]) {
                rest.push_back(i);
            }
        }
        std::sort(rest.begin(), rest.end(), later);
        order.insert(order.end(), rest.begin(), rest.end());
    }

    for (const std::size_t i : order) {
        if (parent_of[i] < 0) {
            continue;
        }
        const hng::Process parent = nodes[parent_of[i]].process;
        if (!store_.lookup(parent)) {
            ++report.bind_ignored;
            continue;
        }
        RoleMemberChanges changes =
            store_.bind_to_role_initial(nodes[i].process, parent);
        if (changes.entries.empty()) {
            continue;
        }
        notify_members(changes);
        ++report.bind_adopted;
    }

    // ③ cgroup 重读：空结果保留原成员；非空按当下枚举改判
    for (const hng::Role& role : store_.roles()) {
        std::optional<std::string> path = store_.cgroup_path(role.roleID);
        if (!path || path->empty()) {
            continue;
        }
        ++report.roles_resynced;
        const std::vector<hng::Process> reread =
            probe_.read_members ? probe_.read_members(*path)
                                : hng::role::RoleCgroupReader::read(*path);
        if (reread.empty()) {
            ++report.cgroup_read_empty;
            continue;
        }
        notify_members(store_.adopt_members(role.roleID, reread));
    }

    state_.store(hng::ComponentState::READY, std::memory_order_release);
    return report;
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
    std::vector<hng::Process> result       = store_.members(role_id);

    std::optional<std::string> cgroup_path = store_.cgroup_path(role_id);
    if (!cgroup_path || cgroup_path->empty()) {
        return result;
    }
    const std::vector<hng::Process> reread =
        probe_.read_members ? probe_.read_members(*cgroup_path)
                            : hng::role::RoleCgroupReader::read(*cgroup_path);
    result.insert(result.end(), reread.begin(), reread.end());
    std::sort(result.begin(), result.end(), process_less);
    result.erase(std::unique(result.begin(), result.end()), result.end());
    return result;
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
