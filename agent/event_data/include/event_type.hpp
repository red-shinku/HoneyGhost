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
 * @details 当前唯一的事件来源是系统调用采集线；其余取值保留至 CLI 词汇收敛。
 * 注意强类型枚举，避免与 kernel 侧无作用域枚举 syscall_event_type
 * 的同名成员在裸用时的歧义。
 */
enum class EventType : uint8_t {
    SYSCALL_EVENT = 0,  ///< 系统调用事件流
    FILE_EVENT    = 1,  ///< 文件访问事件流
    NETWORK_EVENT = 2,  ///< 网络连接事件流
    IPC_EVENT     = 3   ///< IPC 通信事件流
};

/**
 * @brief 语义子类型，细化顶层事件大类 hng::EventType
 * @details 取值与 syscall_event.proto 的载荷 oneof 序号、cli_service.proto 的
 * EventKind 一致：取内层载荷序号（从 1 起）。0 保留给未指定。
 * @note FILE_SYSCALL 是 open / unlink 等文件系统调用载荷；FILE 是已删除的
 * 文件采集流遗留的编号，当前无事件来源。
 * @see hng::EventType
 */
enum class EventKind : uint8_t {
    UNSPECIFIED     = 0,  ///< 未指定
    PROCESS         = 1,  ///< 进程生命周期
    EXEC            = 2,  ///< 执行镜像
    CREDENTIAL      = 3,  ///< 凭证变更
    NAMESPACE       = 4,  ///< 命名空间变更
    FILE_SYSCALL    = 5,  ///< 文件系统调用
    MEMORY          = 6,  ///< 内存操作
    NETWORK_SYSCALL = 7,  ///< 网络系统调用
    KERNEL          = 8,  ///< 内核事件
    FILE            = 9   ///< 文件访问采集流
};

}  // namespace hng

#endif  //_USER_MODE_EVENT_TYPE_HPP_