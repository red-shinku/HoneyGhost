/**
 * @file
 * @brief 预编译规则集合与黑名单优先的标签匹配。
 */
#include "agent/role_filter/include/role_filter_policy.hpp"
#include <regex>
#include <stdexcept>
#include <unordered_set>

namespace hng::detail {
/** @brief 精确标签哈希集合与预编译的正则列表。 */
struct Rules {
    std::unordered_set<std::string> exact;
    std::vector<std::regex> patterns;
    explicit Rules(const std::vector<LabelRule>& rules)
    {
        for (const auto& rule : rules) {
            if (rule.expression.empty() || rule.expression.size() > 4096 ||
                rule.expression.find('\0') != std::string::npos)
                throw std::runtime_error("角色标签规则为空、过长或包含 NUL");
            if (rule.match == LabelMatch::EXACT) {
                exact.insert(rule.expression);
            } else if (rule.match == LabelMatch::REGEX) {
                try {
                    patterns.emplace_back(rule.expression,
                        std::regex::ECMAScript | std::regex::optimize);
                } catch (const std::regex_error& error) {
                    throw std::runtime_error("非法正则 " + rule.expression + ": " + error.what());
                }
            } else {
                throw std::runtime_error("未知角色标签匹配类型");
            }
        }
    }
    bool matches(const std::string& label) const
    {
        if (exact.count(label)) return true;
        for (const auto& pattern : patterns)
            if (std::regex_match(label, pattern)) return true;
        return false;
    }
};
/** @brief 可共享的只读白名单与黑名单数据。 */
class RoleFilterPolicyData {
   public:
    explicit RoleFilterPolicyData(const RoleFilterConfig& config)
        : white(config.whitelist), black(config.blacklist) {}
    Rules white;
    Rules black;
};
}
namespace hng {
RoleFilterPolicy::RoleFilterPolicy(const RoleFilterConfig& config)
    : data_(std::make_shared<const detail::RoleFilterPolicyData>(config)) {}
bool RoleFilterPolicy::should_collect(const std::string& label) const
{
    return !label.empty() && !data_->black.matches(label) && data_->white.matches(label);
}
}  // namespace hng
