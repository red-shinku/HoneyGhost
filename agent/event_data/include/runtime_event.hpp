/**
 * @file runtime_event.hpp
 * @brief 带运行时信息的事件类型
 * @author red-shinku
 * @date 2026.10.10
 */
#ifndef HNG_RUNTIME_EVENT_HPP_
#define HNG_RUNTIME_EVENT_HPP_

#include <variant>

#include "agent/event_data/include/process.hpp"
#include "agent/event_data/include/role.hpp"
#include "agent/event_data/include/syscall_event.hpp"
#include "agent/event_data/include/file_event.hpp"

namespace hng {

struct RuntimeInformation {
    hng::Process process;  ///< 事件主体进程
    hng::EventType etype;  ///< 事件维度，由载荷 variant 索引推出
    uint32_t roleID;       ///< 0 表示此刻未落定
    /// 归属角色在包装时刻的标签快照；未落定时为空
    /// @note 与 roleID 同属角色维度，取同一个归属快照
    hng::role_label_t roleLabel;
    uint32_t contextID;  ///< 0 表示此刻未落定
};

struct RuntimeEvent {
    RuntimeInformation runtimeInfo;
    std::variant<hng::syscall_semantic_data, hng::file_semantic_data> data;
};

}  // namespace hng

#endif  // HNG_RUNTIME_EVENT_HPP_