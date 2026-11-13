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

namespace {

/// @brief 不同维度事件包装方法的公共部分
/// @tparam SemanticData hng::syscall_semantic_data 或 hng::file_semantic_data
/// @note 事件类型取搬运后载荷的 variant 索引，语义子类型在 syscall 流取内层
/// 载荷序号、在 file 流固定为 FILE
template <class SemanticData>
hng::RuntimeEvent assemble(SemanticData&& src, uint32_t roleID,
                           hng::role_label_t roleLabel, uint32_t contextID)
{
    using Data = std::decay_t<SemanticData>;

    hng::RuntimeEvent event{};
    event.runtimeInfo.process =
        hng::Process{src.head.pid, src.head.pid_start_time};
    event.runtimeInfo.parent =
        hng::Process{src.head.ppid, src.head.ppid_start_time};
    event.runtimeInfo.roleID    = roleID;
    event.runtimeInfo.roleLabel = std::move(roleLabel);
    event.runtimeInfo.contextID = contextID;
    event.data                  = std::forward<SemanticData>(src);
    event.runtimeInfo.etype     = static_cast<hng::EventType>(event.data.index());

    if constexpr (std::is_same_v<Data, hng::syscall_semantic_data>) {
        const auto& payload = std::get<hng::syscall_semantic_data>(event.data);
        static_assert(
            std::variant_size_v<std::decay_t<decltype(payload.data)>> == 8,
            "The payload quantity of syscall semantic events must correspond to "
            "1..8 of hng::EventKind");
        event.runtimeInfo.kind =
            static_cast<hng::EventKind>(payload.data.index() + 1);
    }
    else {
        event.runtimeInfo.kind = hng::EventKind::FILE;
    }
    return event;
}

}  // namespace

hng::RuntimeEvent RuntimePackaging::pack(hng::syscall_semantic_data src,
                                         uint32_t roleID,
                                         hng::role_label_t roleLabel,
                                         uint32_t contextID)
{
    return assemble(std::move(src), roleID, std::move(roleLabel), contextID);
}

hng::RuntimeEvent RuntimePackaging::pack(hng::file_semantic_data src,
                                         uint32_t roleID,
                                         hng::role_label_t roleLabel,
                                         uint32_t contextID)
{
    return assemble(std::move(src), roleID, std::move(roleLabel), contextID);
}
