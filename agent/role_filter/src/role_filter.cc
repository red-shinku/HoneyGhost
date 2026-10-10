#include "agent/role_filter/src/role_filter_state.hpp"

#include <stdexcept>
#include <utility>

namespace hng::detail {
RoleFilterState::RoleFilterState(const RoleLookupService& lookup, RoleFilterPolicy policy,
                                std::unique_ptr<ProcessFilterMap> map, RoleFilterOptions options)
    : lookup_(lookup), policy_(std::move(policy)), map_(std::move(map)), options_(std::move(options))
{
    if (!map_) throw std::invalid_argument("名单 map 不可为空");
    if (options_.refresh_interval.count() <= 0) throw std::invalid_argument("刷新周期必须为正");
    if (!options_.liveness) options_.liveness = [](Process p) { return proc_liveness(p); };
}

void RoleFilterState::enqueue(FilterTask task)
{
    {
        std::lock_guard lock(queue_mutex_);
        if (stopped_) { ++rejected_; return; }
        queue_.push_back(std::move(task));
    }
    cv_.notify_one();
}

void RoleFilterState::stop()
{
    {
        std::lock_guard lock(queue_mutex_);
        stopped_ = true;
    }
    cv_.notify_all();
}

void RoleFilterState::run()
{
    auto next = std::chrono::steady_clock::now() + options_.refresh_interval;
    while (true) {
        std::deque<FilterTask> batch;
        bool done;
        {
            std::unique_lock lock(queue_mutex_);
            cv_.wait_until(lock, next, [&] { return stopped_ || !queue_.empty(); });
            batch.swap(queue_);
            done = stopped_;
        }
        for (const auto& task : batch) land(task);
        refresh();
        if (done) return;  // stop 排空已接收的通知；重试错误请先观察 stats
        next = std::chrono::steady_clock::now() + options_.refresh_interval;
    }
}

void RoleFilterState::drain()
{
    std::deque<FilterTask> batch;
    {
        std::lock_guard lock(queue_mutex_);
        batch.swap(queue_);
    }
    for (const auto& task : batch) land(task);
    refresh();
}

void RoleFilterState::land(const FilterTask& task)
{
    switch (task.kind) {
        case FilterTask::Kind::UPDATE:
            if (task.role.roleID) roles_[task.role.roleID] = task.role;
            break;
        case FilterTask::Kind::LEAVE:
            roles_.erase(task.role.roleID);
            members_.erase(task.role.roleID);
            break;
        case FilterTask::Kind::POLICY:
            policy_ = *task.policy;
            break;
        case FilterTask::Kind::REFRESH:
            break;
    }
}

void RoleFilterState::refresh()
{
    for (auto it = roles_.begin(); it != roles_.end();) {
        const uint32_t id = it->first;
        try {
            // 回调和异步处理之间角色可能已退出/换标签，查询当前事实。
            auto current = lookup_.role(id);
            if (!current) {
                members_.erase(id);
                it = roles_.erase(it);
                continue;
            }
            it->second = *current;
            if (!policy_.should_collect(current->roleLabel)) {
                members_.erase(id);
            } else {
                auto latest = lookup_.members(id);
                if (latest.empty()) ++empty_members_;
                auto& known = members_[id];
                for (Process p : latest) {
                    if (p.pid && p.pid_start_time) known.insert(p);
                }
                // 空/部分 cgroup 枚举不等于离开。仅由明确退出/PID 复用清理。
                for (auto p = known.begin(); p != known.end();) {
                    if (options_.liveness(*p) == ProcessLiveness::DEAD) p = known.erase(p);
                    else ++p;
                }
            }
        } catch (...) {
            ++lookup_errors_;  // 保留上次成员，后续重试；失败不杀死消费线程
        }
        ++it;
    }

    ProcessSet desired;
    for (const auto& [id, known] : members_) {
        auto entry = roles_.find(id);
        if (entry == roles_.end() || !policy_.should_collect(entry->second.roleLabel)) continue;
        for (Process p : known) {
            try {
                auto owner = lookup_.lookup(p);
                if (owner) {
                    auto owner_role = lookup_.role(*owner);
                    if (!owner_role || !policy_.should_collect(owner_role->roleLabel)) continue;
                    // 权威归属变更到另一角色时不再依赖旧角色的历史成员记录。
                    if (*owner != id) continue;
                }
                desired.insert(p);
            } catch (...) { ++lookup_errors_; }
        }
    }

    // 先撤销、后允许。集合去重，不受重复通知/重复成员影响。
    ProcessSet removable = applied_;
    removable.insert(uncertain_.begin(), uncertain_.end());
    for (Process p : removable) {
        if (desired.count(p)) continue;
        auto error = map_->erase(p);
        if (error) { ++map_errors_; last_map_error_ = error.value(); }
        else { applied_.erase(p); uncertain_.erase(p); }
    }
    for (Process p : desired) {
        if (applied_.count(p) && !uncertain_.count(p)) continue;
        auto error = map_->allow(p);
        if (error) {
            ++map_errors_; last_map_error_ = error.value(); uncertain_.insert(p);
        } else {
            applied_.insert(p); uncertain_.erase(p);
        }
    }
    roles_count_ = roles_.size();
    applied_count_ = applied_.size();
}

RoleFilterStats RoleFilterState::stats() const
{
    return {roles_count_.load(), applied_count_.load(), map_errors_.load(),
            lookup_errors_.load(), empty_members_.load(), rejected_.load(), last_map_error_.load()};
}
}  // namespace hng::detail

namespace hng {
RoleFilter::RoleFilter(const RoleLookupService& lookup, RoleFilterPolicy policy,
                       std::unique_ptr<ProcessFilterMap> map, RoleFilterOptions options)
    : state_(std::make_unique<detail::RoleFilterState>(lookup, std::move(policy),
                                                     std::move(map), std::move(options))) {}
RoleFilter::~RoleFilter() = default;  // 装配方须先 stop 并 join
void RoleFilter::on_role_joined(const Role& r) { state_->enqueue({detail::FilterTask::Kind::UPDATE, r, {}}); }
void RoleFilter::on_role_main_process_changed(const Role& r) { on_role_joined(r); }
void RoleFilter::on_role_left(const Role& r) { state_->enqueue({detail::FilterTask::Kind::LEAVE, r, {}}); }
void RoleFilter::request_refresh() { state_->enqueue({detail::FilterTask::Kind::REFRESH, {}, {}}); }
void RoleFilter::replace_policy(RoleFilterPolicy p)
{
    state_->enqueue({detail::FilterTask::Kind::POLICY, {}, std::make_shared<RoleFilterPolicy>(std::move(p))});
}
void RoleFilter::run() { state_->run(); }
void RoleFilter::stop() { state_->stop(); }
void RoleFilter::drain() { state_->drain(); }
RoleFilterStats RoleFilter::stats() const { return state_->stats(); }
}  // namespace hng
