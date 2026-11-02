/**
 * @file event_converter.hpp
 * @brief 运行时事件与 RuntimeService 响应报文之间的转换，以及事件类型的双边映射
 * @author red-shinku
 * @date 2026.10.16
 */

#ifndef HNG_EVENT_CONVERTER_HPP
#define HNG_EVENT_CONVERTER_HPP

#include <proto/cli_service.pb.h>

#include "agent/event_data/include/event_type.hpp"
#include "agent/event_data/include/runtime_event.hpp"

namespace hng::cli {

/// @brief 事件类型：内部 → 报文
hng::clisv::EventType ToProtoEventType(hng::EventType etype);

/// @brief 事件类型：报文 → 内部
hng::EventType FromProtoEventType(hng::clisv::EventType etype);

/// @brief 把一条运行时事件搬进响应报文
/// @param event 源事件；其载荷被移动，返回后 event.data 处于已移出状态
/// @param out 目标响应；head 与 event oneof 被覆盖
/// @note 载荷用 set_allocated_* 移动，不逐字段拷贝
void ToProto(hng::RuntimeEvent& event, hng::clisv::ReceiveEventResponse& out);

}  // namespace hng::cli

#endif  // HNG_EVENT_CONVERTER_HPP
