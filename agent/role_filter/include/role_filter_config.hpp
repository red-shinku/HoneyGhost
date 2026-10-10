#ifndef HNG_ROLE_FILTER_CONFIG_HPP_
#define HNG_ROLE_FILTER_CONFIG_HPP_

#include <istream>
#include <string>
#include <vector>

namespace hng {

enum class LabelMatch { EXACT, REGEX };

struct LabelRule {
    LabelMatch match = LabelMatch::EXACT;
    std::string expression;
};

struct RoleFilterConfig {
    std::vector<LabelRule> whitelist;
    std::vector<LabelRule> blacklist;
};

/* 严格 .conf 语法：两段 [whitelist]/[blacklist]，每行 exact:或regex:。
 * 空配置默认拒绝；重复段、未知段/规则、非法正则均抛 std::runtime_error。
 * stream 入口不取得句柄所有权，便于将来适配其他配置来源。
 */
RoleFilterConfig parse_role_filter_config(std::istream& input,
                                          const std::string& source = "<stream>");
RoleFilterConfig load_role_filter_config(const std::string& path);

}  // namespace hng
#endif
