/**
 * @file process_lifecycle_sink.hpp
 * @brief 进程生命周期的下行出口
 * @details 需要感知进程退出的模块实现该接口，并经
 *          ProcessManager::add_process_lifecycle_sink 注册。通知只表达“该身份
 *          不再产生事件”，内部关系如何清理由订阅方决定。
 * @author red_shinku
 * @date 2026.10.22
 */

#ifndef HNG_PROCESS_LIFECYCLE_SINK_HPP_
#define HNG_PROCESS_LIFECYCLE_SINK_HPP_

#include "agent/event_data/include/process.hpp"

/**
 * @brief 进程退出的下游接收方
 * @warning 接口的实现不可阻塞
 * @note 按 (pid, pid_start_time) 通知，不影响同 pid 的新实例；同一次退出可能
 *       被重复投递，实现须幂等
 */
class ProcessLifecycleSink {
   protected:
    /// @note 析构为 protected：下游自持其实现，ProcessManager 不接管生命周期
    virtual ~ProcessLifecycleSink() = default;

   public:
    /// @brief 进程已退出：该身份不再产生事件
    virtual void on_process_exited(hng::Process p) = 0;
};

#endif  // HNG_PROCESS_LIFECYCLE_SINK_HPP_
