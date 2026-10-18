/**
 * @file runtime_packaging.hpp
 * @brief 语义事件 → RuntimeEvent 的组装
 * @author red-shinku
 * @date 2026.10.10
 */
#ifndef HNG_RUNTIME_PACKAGING_HPP_
#define HNG_RUNTIME_PACKAGING_HPP_

#include <cstdint>

#include "agent/event_data/include/runtime_event.hpp"

/**
 * @brief 把语义事件组装成 RuntimeEvent
 * @details 无状态、与队列和线程无关的纯转换：进程身份取事件头的
 * (pid, pid_start_time)，事件类型取 RuntimeEvent::data 的 variant 索引，
 * 载荷按值搬运。
 */
class RuntimePackaging {
   public:
    /// @brief 系统调用语义事件 → RuntimeEvent
    /// @param roleID 归属角色；未落定为 0
    /// @param roleLabel 该角色在同一快照下的标签；未落定为空
    static hng::RuntimeEvent pack(hng::syscall_semantic_data src, uint32_t roleID,
                                  hng::role_label_t roleLabel,
                                  uint32_t contextID);

    /// @brief 文件语义事件 → RuntimeEvent
    /// @copydetails pack(hng::syscall_semantic_data, uint32_t, hng::role_label_t,
    /// uint32_t)
    static hng::RuntimeEvent pack(hng::file_semantic_data src, uint32_t roleID,
                                  hng::role_label_t roleLabel,
                                  uint32_t contextID);
};

#endif  // HNG_RUNTIME_PACKAGING_HPP_
