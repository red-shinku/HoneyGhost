/**
 * @file runtime_packaging.cc
 * @brief 语义事件 → RuntimeEvent 的组装 实现
 * @author red-shinku
 * @date 2026.10.10
 */

#include "agent/runtime_engine/src/runtime_packaging.hpp"

#include <utility>

namespace {

/// @brief 不同维度事件包装方法的公共部分
/// @tparam SemanticData hng::syscall_semantic_data 或 hng::file_semantic_data
/// @note 事件类型取搬运后载荷的 variant 索引
template <class SemanticData>
hng::RuntimeEvent assemble(SemanticData&& src, uint32_t roleID,
                           uint32_t contextID)
{
    hng::RuntimeEvent event{};
    event.runtimeInfo.process =
        hng::Process{src.head.pid, src.head.pid_start_time};
    event.runtimeInfo.roleID    = roleID;
    event.runtimeInfo.contextID = contextID;
    event.data                  = std::forward<SemanticData>(src);
    event.runtimeInfo.etype     = static_cast<hng::EventType>(event.data.index());
    return event;
}

}  // namespace

hng::RuntimeEvent RuntimePackaging::pack(hng::syscall_semantic_data src,
                                         uint32_t roleID, uint32_t contextID)
{
    return assemble(std::move(src), roleID, contextID);
}

hng::RuntimeEvent RuntimePackaging::pack(hng::file_semantic_data src,
                                         uint32_t roleID, uint32_t contextID)
{
    return assemble(std::move(src), roleID, contextID);
}
