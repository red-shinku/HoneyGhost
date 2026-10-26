/**
 * @file role_source_barrier.hpp
 * @brief 角色源就绪屏障
 * @details 装配层用 expect() 声明本次启用的角色源，各发现器在第一个初始快照
 *          发布后各上报一次 ready()。屏障只汇总结果，不产出事件、不持线程；
 *          未启用的源不 expect()，不计入等待。
 * @author red_shinku
 * @date 2026.10.25
 */

#ifndef HNG_ROLE_SOURCE_BARRIER_HPP_
#define HNG_ROLE_SOURCE_BARRIER_HPP_

#include <chrono>
#include <condition_variable>
#include <map>
#include <mutex>

#include "agent/role_discovery/include/role_event.hpp"

/**
 * @brief 角色源就绪屏障
 * @details 线程安全：expect() / ready() 可在任意线程调用，wait() 阻塞到结论
 *          出现或超时。
 */
class RoleSourceBarrier {
   public:
    /// @brief 登记一个本次启用的源
    /// @note 重复登记会清除该源已有的上报
    void expect(hng::role::RoleSource source);

    /// @brief 上报一个源的首个快照结论
    /// @param source 源
    /// @param available 该源是否可用
    /// @note 未 expect() 的源忽略；重复上报以最后一次为准
    void ready(hng::role::RoleSource source, bool available);

    /// @brief 等待全部已登记的源上报
    /// @param timeout 最长等待时长
    /// @return 全部源都已上报且全部可用时为 true；超时或有源不可用时为 false
    /// @note 未登记任何源时立即返回 true
    bool wait(std::chrono::milliseconds timeout);

    /// @brief 是否发生过等待超时
    /// @note 只有超时置位；源上报不可用不置位
    bool timed_out() const;

   private:
    /// 一个源的上报结果
    struct SourceState {
        bool reported  = false;  ///< 是否已上报
        bool available = false;  ///< 上报的可用性
    };

    /// @brief 全部已登记的源都已上报
    bool all_reported() const;

    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::map<hng::role::RoleSource, SourceState> sources_;
    bool timed_out_ = false;
};

inline void RoleSourceBarrier::expect(hng::role::RoleSource source)
{
    std::lock_guard<std::mutex> lock(mutex_);
    sources_[source] = SourceState{};
}

inline void RoleSourceBarrier::ready(hng::role::RoleSource source, bool available)
{
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto state = sources_.find(source);
        if (state == sources_.end()) {
            return;
        }
        state->second.reported  = true;
        state->second.available = available;
    }
    cv_.notify_all();
}

inline bool RoleSourceBarrier::wait(std::chrono::milliseconds timeout)
{
    std::unique_lock<std::mutex> lock(mutex_);

    if (!cv_.wait_for(lock, timeout, [this] { return all_reported(); })) {
        timed_out_ = true;
        return false;
    }
    for (const auto& entry : sources_) {
        if (!entry.second.available) {
            return false;
        }
    }
    return true;
}

inline bool RoleSourceBarrier::timed_out() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return timed_out_;
}

inline bool RoleSourceBarrier::all_reported() const
{
    for (const auto& entry : sources_) {
        if (!entry.second.reported) {
            return false;
        }
    }
    return true;
}

#endif  // HNG_ROLE_SOURCE_BARRIER_HPP_
