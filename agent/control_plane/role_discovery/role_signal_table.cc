/**
 * @file role_signal_table.cc
 * @brief 角色存活状态表的跃迁判定实现
 * @author red_shinku
 * @date 2026.9.11
 */

#include "./include/role_signal_table.hpp"

namespace hng {
namespace role {

std::optional<RoleEvent> RoleSignalTable::submit(
    const RoleObservation& observation)
{
    const std::string& key = observation.payload.identity.instance_key;
    auto it                = alive_.find(key);

    if (observation.present) {
        if (it == alive_.end()) {
            alive_.emplace(key, observation.payload);
            return RoleEvent{RoleAction::JOIN, observation.payload};
        }
        if (same_process(it->second.main_process,
                         observation.payload.main_process)) {
            return std::nullopt;  // 实例仍存活且锚点未变：重复观察或重连重放
        }
        it->second = observation.payload;
        return RoleEvent{RoleAction::MAIN_PROCESS_CHANGE, observation.payload};
    }

    if (it == alive_.end()) {
        return std::nullopt;  // 未知实例的离开观察
    }
    RolePayload cached = it->second;
    cached.member_processes.clear();
    alive_.erase(it);
    return RoleEvent{RoleAction::LEAVE, std::move(cached)};
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
    return it->second;
}

}  // namespace role
}  // namespace hng
