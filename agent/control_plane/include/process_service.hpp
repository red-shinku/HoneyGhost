/**
 * @file process_service.hpp
 * @brief 包含进程相关的服务接口，是工作平面访问控制平面中进程相关服务的方式
 *  process_manager.hpp 中 ProcessManager 实现了这些接口
 * @author red_shinku
 * @date 2026.8.20
 */

#ifndef _CONTROL_PLANE_PROCESSSERVICE_HPP
#define _CONTROL_PLANE_PROCESSSERVICE_HPP

#include <optional>
#include <string>

#include "agent/event_data/include/process.hpp"

class ProcessLookupService {
   protected:
    virtual ~ProcessLookupService() = default;

   public:
    /// @brief 查询进程信息
    virtual std::optional<hng::ProcessMessage> lookup(hng::Process p) const = 0;

    /// @brief 按 pid 反查进程实体；不存在时为空
    /// @note 存活进程优先；未命中时取虚拟根中该 pid 的最新实例
    virtual std::optional<hng::Process> resolve(uint32_t pid) const         = 0;
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

/// @brief 进程信息的更新接口
/// @details 运行期 exec 事件的通知写；ProcessManager 实现。
class ProcessUpdateService {
   protected:
    virtual ~ProcessUpdateService() = default;

   public:
    /// @brief 更新进程最近一次 exec 的镜像路径
    /// @param p 目标进程；按 (pid, pid_start_time) 匹配，不命中同 pid 的新实例
    /// @param exe 语义化后的 exec 路径
    /// @note 通知写：入队即返回，落地在 ProcessManager 的消费线程上。落地时
    ///       先查实进程树，未命中再查虚拟根；都不命中则丢弃。
    virtual void update_exe_image(hng::Process p, std::string exe) = 0;
};

#endif  // _CONTROL_PLANE_PROCESSSERVICE_HPP