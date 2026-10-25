/**
 * @file
 * @brief 角色通知消费、成员缓存、策略替换与进程名单差异同步。
 * @author inless427
 */
#include "agent/role_filter/src/role_filter_state.hpp"
#include <stdexcept>
#include <utility>

namespace hng::detail {
RoleFilterState::RoleFilterState(const ::RoleLookupService& lookup,
                                 RoleFilterPolicy policy,
                                 std::unique_ptr<ProcessFilterMap> map,
                                 RoleFilterOptions options)
    : lookup_(lookup),
      policy_(std::move(policy)),
      map_(std::move(map)),
      options_(std::move(options))
{
    if (!map_) throw std::invalid_argument("名单 map 不可为空");
    if (options_.refresh_interval.count() <= 0)
        throw std::invalid_argument("刷新周期必须为正");
    if (!options_.liveness)
        options_.liveness = [](Process process) {
            return proc_liveness(process);
        };
}

void RoleFilterState::enqueue(FilterTask task)
{
    {
        std::lock_guard lock(queue_mutex_);
        if (stopped_) {
            ++rejected_;
            return;
        }
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

void RoleFilterState::set_supervision_service(::RoleSupervisionService* service)
{
    supervision_ = service;
}

const ::RoleLookupService& RoleFilterState::lookup() const { return lookup_; }

void RoleFilterState::sync_supervision(uint32_t role_id, bool supervised)
{
    if (supervision_ == nullptr) return;
    const bool registered = supervised_.count(role_id) != 0;
    if (registered == supervised) return;
    supervision_->set_supervised(role_id, supervised);
    if (supervised)
        supervised_.insert(role_id);
    else
        supervised_.erase(role_id);
}

void RoleFilterState::run()
{
    auto next = std::chrono::steady_clock::now() + options_.refresh_interval;
    while (true) {
        std::deque<FilterTask> batch;
        bool done;
        bool due;
        {
            std::unique_lock lock(queue_mutex_);
            cv_.wait_until(lock, next,
                           [&] { return stopped_ || !queue_.empty(); });
            batch.swap(queue_);
            done = stopped_;
            due  = std::chrono::steady_clock::now() >= next;
        }
        /** @note 只有成员新增任务时不必重查权威源：成员并入后直接重算差异，
         * 周期刷新仍按原到点时刻执行，不被成员通知无限推迟。 */
        bool rescan = done || due;
        for (const auto& task : batch) {
            land(task);
            if (task.kind != FilterTask::Kind::MEMBERS) rescan = true;
        }
        if (rescan) {
            refresh();
            next = std::chrono::steady_clock::now() + options_.refresh_interval;
        }
        else {
            apply();
        }
        if (done) return;
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
            sync_supervision(task.role.roleID, false);
            break;
        case FilterTask::Kind::POLICY:
            policy_ = *task.policy;
            break;
        case FilterTask::Kind::REFRESH:
            break;
        case FilterTask::Kind::MEMBERS: {
            auto tracked = roles_.find(task.role.roleID);
            if (tracked == roles_.end() ||
                !policy_.should_collect(tracked->second.roleLabel))
                break;
            /** @note 只并入不替换：枚举为空或偏少都不能当作成员离开。 */
            auto& known = members_[task.role.roleID];
            for (Process process : task.members)
                if (process.pid && process.pid_start_time) known.insert(process);
            break;
        }
    }
}

void RoleFilterState::refresh()
{
    for (auto it = roles_.begin(); it != roles_.end();) {
        const uint32_t id = it->first;
        try {
            /** @note 通知排队后角色可能退出或换标签，重新查询权威事实。 */
            auto current = lookup_.role(id);
            if (!current) {
                members_.erase(id);
                sync_supervision(id, false);
                it = roles_.erase(it);
                continue;
            }
            it->second         = *current;
            const bool collect = policy_.should_collect(current->roleLabel);
            sync_supervision(id, collect);
            if (!collect) {
                members_.erase(id);
            }
            else {
                auto latest = lookup_.members(id);
                if (latest.empty()) ++empty_members_;
                auto& known = members_[id];
                for (Process process : latest)
                    if (process.pid && process.pid_start_time)
                        known.insert(process);
                /** @note 空或部分成员枚举不代表离开，仅明确退出或 PID
                 * 复用时清理。 */
                for (auto p = known.begin(); p != known.end();) {
                    if (options_.liveness(*p) == ProcessLiveness::DEAD)
                        p = known.erase(p);
                    else
                        ++p;
                }
            }
        }
        catch (...) {
            ++lookup_errors_;
        }
        ++it;
    }
    apply();
}

void RoleFilterState::apply()
{
    ProcessSet desired;
    for (const auto& [id, known] : members_) {
        auto entry = roles_.find(id);
        if (entry == roles_.end() ||
            !policy_.should_collect(entry->second.roleLabel))
            continue;
        for (Process process : known) {
            try {
                auto owner = lookup_.lookup(process);
                if (owner) {
                    auto owner_role = lookup_.role(*owner);
                    if (!owner_role ||
                        !policy_.should_collect(owner_role->roleLabel))
                        continue;
                    if (*owner != id) continue;
                }
                desired.insert(process);
            }
            catch (...) {
                ++lookup_errors_;
            }
        }
    }
    /** @note 先撤销再允许；uncertain_ 也必须参与删除，避免部分写入后漏删。 */
    ProcessSet removable = applied_;
    removable.insert(uncertain_.begin(), uncertain_.end());
    for (Process process : removable) {
        if (desired.count(process)) continue;
        auto error = map_->erase(process);
        if (error) {
            ++map_errors_;
            last_map_error_ = error.value();
        }
        else {
            applied_.erase(process);
            uncertain_.erase(process);
        }
    }
    for (Process process : desired) {
        if (applied_.count(process) && !uncertain_.count(process)) continue;
        auto error = map_->allow(process);
        if (error) {
            ++map_errors_;
            last_map_error_ = error.value();
            uncertain_.insert(process);
        }
        else {
            applied_.insert(process);
            uncertain_.erase(process);
        }
    }
    roles_count_   = roles_.size();
    applied_count_ = applied_.size();
}

RoleFilterStats RoleFilterState::stats() const
{
    return {roles_count_.load(),   applied_count_.load(), map_errors_.load(),
            lookup_errors_.load(), empty_members_.load(), rejected_.load(),
            last_map_error_.load()};
}

}  // namespace hng::detail

namespace hng {
RoleFilter::RoleFilter(const ::RoleLookupService& lookup, RoleFilterPolicy policy,
                       std::unique_ptr<ProcessFilterMap> map,
                       RoleFilterOptions options)
    : state_(std::make_unique<detail::RoleFilterState>(
          lookup, std::move(policy), std::move(map), std::move(options)))
{
}

RoleFilter::~RoleFilter() = default;

void RoleFilter::on_role_joined(const Role& role)
{
    state_->enqueue({detail::FilterTask::Kind::UPDATE, role, {}, {}});
}

void RoleFilter::on_role_left(const Role& role)
{
    state_->enqueue({detail::FilterTask::Kind::LEAVE, role, {}, {}});
}

void RoleFilter::on_role_main_process_changed(const Role& role)
{
    on_role_joined(role);
}

void RoleFilter::on_role_members_changed(const Role& role,
                                         const std::vector<Process>& added)
{
    state_->enqueue({detail::FilterTask::Kind::MEMBERS, role, {}, added});
}

void RoleFilter::request_refresh()
{
    state_->enqueue({detail::FilterTask::Kind::REFRESH, {}, {}, {}});
}

void RoleFilter::replace_policy(RoleFilterPolicy policy)
{
    state_->enqueue({detail::FilterTask::Kind::POLICY,
                     {},
                     std::make_shared<RoleFilterPolicy>(std::move(policy)),
                     {}});
}

void RoleFilter::set_supervision_service(::RoleSupervisionService* service)
{
    state_->set_supervision_service(service);
}

void RoleFilter::seed_initial_roles()
{
    if (lifecycle_.load() != hng::ComponentState::CONSTRUCTED) return;
    const auto roles = state_->lookup().roles();
    for (const Role& role : roles) {
        state_->enqueue({detail::FilterTask::Kind::UPDATE, role, {}, {}});
        auto anchor = state_->lookup().main_process(role.roleID);
        if (anchor)
            state_->enqueue(
                {detail::FilterTask::Kind::MEMBERS, role, {}, {*anchor}});
    }
    state_->drain();
    lifecycle_.store(hng::ComponentState::READY);
}

hng::ComponentState RoleFilter::state() const { return lifecycle_.load(); }

void RoleFilter::run()
{
    if (lifecycle_.load() != hng::ComponentState::READY) return;
    lifecycle_.store(hng::ComponentState::RUNNING);
    state_->run();
    lifecycle_.store(hng::ComponentState::STOPPED);
}

void RoleFilter::stop()
{
    state_->stop();
    hng::ComponentState current = lifecycle_.load();
    while (current != hng::ComponentState::RUNNING &&
           !lifecycle_.compare_exchange_weak(current,
                                             hng::ComponentState::STOPPED)) {
    }
}

void RoleFilter::drain() { state_->drain(); }

RoleFilterStats RoleFilter::stats() const { return state_->stats(); }

}  // namespace hng
