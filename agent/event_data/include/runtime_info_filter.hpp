/**
 * @file runtime_info_filter.hpp
 * @brief 运行时信息过滤器
 * @author red-shinku
 * @date 2026.10.10
 */
#ifndef HNG_RUNTIME_INFO_FILTER_HPP_
#define HNG_RUNTIME_INFO_FILTER_HPP_

#include <cstdint>
#include <optional>

#include "agent/event_data/include/runtime_event.hpp"

/**
 * @brief 订阅流关心的运行时信息组合
 * @details 值对象，可拷贝。
 * 未设置的维度不参与判定，故默认构造即全选；
 * @note set_* 仅在构造期调用，成员变量构造完成后不变。
 */
class RuntimeInfoFilter {
   public:
    /// @brief 全选：四个维度都不限
    RuntimeInfoFilter() = default;

    /// @brief 设置进程维度，按 (pid, pid_start_time) 判等
    RuntimeInfoFilter& set_process(hng::Process p);

    /// @brief 设置角色维度
    RuntimeInfoFilter& set_role(uint32_t roleID);

    /// @brief 设置上下文维度
    RuntimeInfoFilter& set_context(uint32_t contextID);

    /// @brief 设置事件类型维度
    RuntimeInfoFilter& set_etype(hng::EventType etype);

    /// @brief 判定一条运行时信息是否命中本过滤器
    /// @return 所有已设置维度均命中为 true；无已设置维度时为 true
    bool should_take(const hng::RuntimeInformation& info) const;

   private:
    std::optional<hng::Process> process_;
    std::optional<uint32_t> roleID_;
    std::optional<uint32_t> contextID_;
    std::optional<hng::EventType> etype_;
};

inline RuntimeInfoFilter& RuntimeInfoFilter::set_process(hng::Process p)
{
    process_ = p;
    return *this;
}

inline RuntimeInfoFilter& RuntimeInfoFilter::set_role(uint32_t roleID)
{
    roleID_ = roleID;
    return *this;
}

inline RuntimeInfoFilter& RuntimeInfoFilter::set_context(uint32_t contextID)
{
    contextID_ = contextID;
    return *this;
}

inline RuntimeInfoFilter& RuntimeInfoFilter::set_etype(hng::EventType etype)
{
    etype_ = etype;
    return *this;
}

inline bool RuntimeInfoFilter::should_take(
    const hng::RuntimeInformation& info) const
{
    if (process_ && !(info.process == *process_)) {
        return false;
    }
    if (roleID_ && info.roleID != *roleID_) {
        return false;
    }
    if (contextID_ && info.contextID != *contextID_) {
        return false;
    }
    if (etype_ && info.etype != *etype_) {
        return false;
    }
    return true;
}

#endif  // HNG_RUNTIME_INFO_FILTER_HPP_
