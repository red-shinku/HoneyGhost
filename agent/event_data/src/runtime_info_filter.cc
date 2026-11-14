/**
 * @file runtime_info_filter.cc
 * @brief 运行时信息过滤器 实现
 * @author red-shinku
 * @date 2026.11.13
 */

#include "agent/event_data/include/runtime_info_filter.hpp"

#include <algorithm>
#include <utility>

namespace {

/// @brief 排序并去除重复取值
template <class T>
void sort_unique(std::vector<T>& values)
{
    std::sort(values.begin(), values.end());
    values.erase(std::unique(values.begin(), values.end()), values.end());
}

template <class T>
bool contains(const std::vector<T>& sorted_values, const T& value)
{
    return std::binary_search(sorted_values.begin(), sorted_values.end(), value);
}

}  // namespace

RuntimeInfoFilter& RuntimeInfoFilter::set_process(std::vector<uint32_t> pids)
{
    pids_ = std::move(pids);
    sort_unique(pids_);
    return *this;
}

RuntimeInfoFilter& RuntimeInfoFilter::set_role(
    std::vector<uint32_t> roleIDs, std::vector<hng::role_label_t> roleLabels)
{
    roleIDs_    = std::move(roleIDs);
    roleLabels_ = std::move(roleLabels);
    sort_unique(roleIDs_);
    sort_unique(roleLabels_);
    return *this;
}

RuntimeInfoFilter& RuntimeInfoFilter::set_context(
    std::vector<uint32_t> contextIDs)
{
    contextIDs_ = std::move(contextIDs);
    sort_unique(contextIDs_);
    return *this;
}

RuntimeInfoFilter& RuntimeInfoFilter::set_etype(
    std::vector<hng::EventType> etypes)
{
    etypes_ = std::move(etypes);
    sort_unique(etypes_);
    return *this;
}

RuntimeInfoFilter& RuntimeInfoFilter::add_expression(hng::FilterExpr expr)
{
    expressions_.push_back(std::move(expr));
    return *this;
}

bool RuntimeInfoFilter::should_take(const hng::RuntimeInformation& info) const
{
    if (!etypes_.empty() && !contains(etypes_, info.etype)) {
        return false;
    }
    if (!pids_.empty() && !contains(pids_, info.process.pid)) {
        return false;
    }
    if (!contextIDs_.empty() && !contains(contextIDs_, info.contextID)) {
        return false;
    }
    if (!roleIDs_.empty() || !roleLabels_.empty()) {
        const bool id_hit    = contains(roleIDs_, info.roleID);
        const bool label_hit = contains(roleLabels_, info.roleLabel);
        if (!id_hit && !label_hit) {
            return false;
        }
    }
    for (const hng::FilterExpr& expr : expressions_) {
        if (!expr.matches(info)) {
            return false;
        }
    }
    return true;
}
