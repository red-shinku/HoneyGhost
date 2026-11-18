/**
 * @file runtime_packaging.cc
 * @brief 语义事件 → RuntimeEvent 的组装 实现
 * @author red-shinku
 * @date 2026.10.10
 */

#include "agent/runtime_engine/src/runtime_packaging.hpp"

#include <type_traits>
#include <utility>
#include <variant>

hng::RuntimeEvent RuntimePackaging::pack(hng::syscall_semantic_data src,
                                         uint32_t roleID,
                                         hng::role_label_t roleLabel,
                                         uint32_t contextID)
{
    hng::RuntimeEvent event{};
    event.runtimeInfo.process =
        hng::Process{src.head.pid, src.head.pid_start_time};
    event.runtimeInfo.parent =
        hng::Process{src.head.ppid, src.head.ppid_start_time};
    event.runtimeInfo.roleID    = roleID;
    event.runtimeInfo.roleLabel = std::move(roleLabel);
    event.runtimeInfo.contextID = contextID;
    event.runtimeInfo.etype     = hng::EventType::SYSCALL_EVENT;

    static_assert(
        std::variant_size_v<std::decay_t<decltype(src.data)>> == 8,
        "The payload quantity of syscall semantic events must correspond to "
        "1..8 of hng::EventKind");
    event.runtimeInfo.kind = static_cast<hng::EventKind>(src.data.index() + 1);
    event.data             = std::move(src);
    return event;
}
