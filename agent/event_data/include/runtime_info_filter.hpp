/**
 * @file runtime_info_filter.hpp
 * @brief 运行时信息过滤器
 * @author red-shinku
 * @date 2026.10.10
 */
#ifndef HNG_RUNTIME_INFO_FILTER_HPP_
#define HNG_RUNTIME_INFO_FILTER_HPP_

#include <algorithm>
#include <cstdint>
#include <utility>
#include <vector>

#include "agent/event_data/include/runtime_event.hpp"

/**
 * @brief 订阅流关心的运行时信息组合
 * @details 值对象，可拷贝。四个维度各持一个取值集合，空集合表示该维度不限，
 * 故默认构造即全选。
 * @note 匹配语义：维度之间取交集，维度之内取并集——已设置的维度要求事件至少
 * 命中该集合中的一个成员。
 * @note 各 set_* 只在构造期调用，构造完成后成员不变。
 */
class RuntimeInfoFilter {
   public:
    /// @brief 全选：四个维度都不限
    RuntimeInfoFilter() = default;

    /// @brief 设置进程维度
    /// @note 只比 pid，不比 pid_start_time：进程身份本是二者的组合，此处为
    /// 单键是订阅方只给得出 pid 所致，故 pid 复用后可能误命中
    RuntimeInfoFilter& set_process(std::vector<uint32_t> pids);

    /// @brief 设置角色维度
    /// @note 0 是「未落定」哨兵，按键值比较而非当作不限
    RuntimeInfoFilter& set_role(std::vector<uint32_t> roleIDs);

    /// @brief 设置上下文维度
    /// @note 0 是「未落定」哨兵，按键值比较而非当作不限
    RuntimeInfoFilter& set_context(std::vector<uint32_t> contextIDs);

    /// @brief 设置事件类型维度
    RuntimeInfoFilter& set_etype(std::vector<hng::EventType> etypes);

    /// @brief 判定一条运行时信息是否命中本过滤器
    /// @return 所有已设置维度均命中为 true；无已设置维度时为 true
    bool should_take(const hng::RuntimeInformation& info) const;

   private:
    std::vector<uint32_t> pids_;
    std::vector<uint32_t> roleIDs_;
    std::vector<uint32_t> contextIDs_;
    std::vector<hng::EventType> etypes_;
};

inline RuntimeInfoFilter& RuntimeInfoFilter::set_process(
    std::vector<uint32_t> pids)
{
    pids_ = std::move(pids);
    return *this;
}

inline RuntimeInfoFilter& RuntimeInfoFilter::set_role(
    std::vector<uint32_t> roleIDs)
{
    roleIDs_ = std::move(roleIDs);
    return *this;
}

inline RuntimeInfoFilter& RuntimeInfoFilter::set_context(
    std::vector<uint32_t> contextIDs)
{
    contextIDs_ = std::move(contextIDs);
    return *this;
}

inline RuntimeInfoFilter& RuntimeInfoFilter::set_etype(
    std::vector<hng::EventType> etypes)
{
    etypes_ = std::move(etypes);
    return *this;
}

inline bool RuntimeInfoFilter::should_take(
    const hng::RuntimeInformation& info) const
{
    if (!pids_.empty() &&
        std::find(pids_.begin(), pids_.end(), info.process.pid) == pids_.end()) {
        return false;
    }
    if (!roleIDs_.empty() && std::find(roleIDs_.begin(), roleIDs_.end(),
                                       info.roleID) == roleIDs_.end()) {
        return false;
    }
    if (!contextIDs_.empty() && std::find(contextIDs_.begin(), contextIDs_.end(),
                                          info.contextID) == contextIDs_.end()) {
        return false;
    }
    if (!etypes_.empty() &&
        std::find(etypes_.begin(), etypes_.end(), info.etype) == etypes_.end()) {
        return false;
    }
    return true;
}

#endif  // HNG_RUNTIME_INFO_FILTER_HPP_
