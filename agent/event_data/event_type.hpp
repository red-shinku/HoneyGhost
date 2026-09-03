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
 * @brief 顶层事件大类，写入通用事件头 event_head::type，标记事件所属采集流
 * @details 四种事件分别对应四路 采集 / 语义化
 * 模块（syscall、file、network、ipc）。
 * 注意强类型枚举，避免与 kernel 侧无作用域枚举 syscall_event_type
 * 的同名成员在裸用时的歧义。
 */
enum class EventType : uint8_t {
    SYSCALL_EVENT = 0,  ///< 系统调用事件流
    FILE_EVENT    = 1,  ///< 文件访问事件流
    NETWORK_EVENT = 2,  ///< 网络连接事件流
    IPC_EVENT     = 3   ///< IPC 通信事件流
};

}  // namespace hng

#endif  //_USER_MODE_EVENT_TYPE_HPP_