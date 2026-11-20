/**
 * @file event_type.hpp
 * @brief 事件类型定义
 * @author red_shinku
 * @date 2026.9.3
 */

#ifndef _USER_MODE_EVENT_TYPE_HPP_
#define _USER_MODE_EVENT_TYPE_HPP_

#include <cstdint>

namespace hng {

/**
 * @brief 事件来源，写入通用事件头 event_head::type
 * @details 本期只有内核探针一种来源，统一记为 SYSCALL_EVENT；非探针来源
 * （agent 自产、procfs 快照等）将来在此新增取值，不复用已删除的编号。
 * 注意强类型枚举，避免与 kernel 侧无作用域枚举 syscall_event_type
 * 的同名成员在裸用时的歧义。
 */
enum class EventType : uint8_t {
    SYSCALL_EVENT = 0  ///< 内核探针来源（系统调用与其它 tracepoint/kprobe）
};

}  // namespace hng

#endif  //_USER_MODE_EVENT_TYPE_HPP_
