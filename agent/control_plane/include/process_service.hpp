/**
 * @file process_service.hpp
 * @brief 包含一个接口类，是工作平面访问控制平面中进程相关服务的方式
 *  process_manager.hpp 中 ProcessManager 实现了该接口
 * @author red_shinku
 * @date 2026.8.20
 */

#ifndef _CONTROL_PLANE_PROCESSSERVICE_HPP
#define _CONTROL_PLANE_PROCESSSERVICE_HPP

#include <optional>

#include "agent/event_data/include/process.hpp"

class ProcessLookupService {
   protected:
    virtual ~ProcessLookupService() = default;

   public:
    /// @brief 查询进程信息
    virtual std::optional<hng::ProcessMessage> lookup(hng::Process p) const = 0;

    /// @brief 按 pid 反查进程实体；不存在时为空
    /// @note 存活进程优先；未命中时取虚拟根中该 pid 的最新实例
    virtual std::optional<hng::Process> resolve(uint32_t pid) const = 0;
};

class ProcessJoinService {
   protected:
    virtual ~ProcessJoinService() = default;

   public:
    /// @brief 通知控制平面注册新 PID
    virtual void register_pid(hng::event_head ehead) = 0;

    /// @brief 通知控制平面注销 PID
    virtual void unregister_pid(hng::Process p)      = 0;
};

#endif  // _CONTROL_PLANE_PROCESSSERVICE_HPP