/**
 * @file role_signal_table.cc
 * @brief 角色存活状态表的跃迁判定与快照对账实现
 * @author red_shinku
 * @date 2026.9.11
 */

#include "./include/role_signal_table.hpp"

#include <algorithm>
#include <utility>

namespace hng {
namespace role {

std::optional<RoleEvent> RoleSignalTable::submit(
    const RoleObservation& observation)
{
    const std::string& key = observation.payload.identity.instance_key;
    auto it                = alive_.find(key);

    switch (observation.kind) {
        case ObservationKind::PRESENT: {
            if (it == alive_.end()) {
                alive_.emplace(key, Entry{observation.payload, generation_,
                                          observation.scope});
                return RoleEvent{RoleAction::JOIN, observation.payload};
            }
            it->second.generation = generation_;
            if (it->second.payload.main_process ==
                observation.payload.main_process) {
                return std::nullopt;  // 实例仍存活且锚点未变：重复观察或重连重放
            }
            it->second.payload = observation.payload;
            return RoleEvent{RoleAction::MAIN_PROCESS_CHANGE,
                             observation.payload};
        }
        case ObservationKind::ABSENT: {
            if (it == alive_.end()) {
                return std::nullopt;  // 未知实例的离开观察
            }
            RolePayload cached = it->second.payload;
            cached.member_processes.clear();
            alive_.erase(it);
            return RoleEvent{RoleAction::LEAVE, std::move(cached)};
        }
        case ObservationKind::UNKNOWN: {
            if (!snapshot_open_ || it == alive_.end()) {
                return std::nullopt;  // 段外的未知观察无处可依，直接丢弃
            }
            it->second.generation = generation_;  // 本段已见，但不产生跃迁
            return std::nullopt;
        }
    }
    return std::nullopt;
}

bool RoleSignalTable::is_alive(const std::string& instance_key) const
{
    return alive_.find(instance_key) != alive_.end();
}

std::optional<RolePayload> RoleSignalTable::lookup(
    const std::string& instance_key) const
{
    auto it = alive_.find(instance_key);
    if (it == alive_.end()) {
        return std::nullopt;
    }
    return it->second.payload;
}

void RoleSignalTable::begin_snapshot(const std::vector<std::string>& scope)
{
    ++generation_;
    snapshot_open_ = true;
    scope_         = scope;
}

std::vector<RoleEvent> RoleSignalTable::end_snapshot()
{
    std::vector<RoleEvent> events;
    if (!snapshot_open_) {
        return events;  // 没有段在跑，没有可结算的差额
    }

    for (auto it = alive_.begin(); it != alive_.end();) {
        if (it->second.generation >= generation_ ||
            !in_current_scope(it->second)) {
            ++it;
            continue;
        }
        RolePayload payload = std::move(it->second.payload);
        payload.member_processes.clear();
        events.push_back(RoleEvent{RoleAction::LEAVE, std::move(payload)});
        it = alive_.erase(it);
    }

    snapshot_open_ = false;
    scope_.clear();

    std::sort(events.begin(), events.end(),
              [](const RoleEvent& a, const RoleEvent& b) {
                  return a.payload.identity.instance_key <
                         b.payload.identity.instance_key;
              });
    return events;
}

bool RoleSignalTable::in_current_scope(const Entry& entry) const
{
    if (scope_.empty()) {
        return true;  // 空范围即表的整个域
    }
    return std::find(scope_.begin(), scope_.end(), entry.scope) != scope_.end();
}

}  // namespace role
}  // namespace hng
