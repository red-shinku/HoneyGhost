/**
 * @file
 * @brief 角色标签名单的数据结构与严格配置解析接口。
 * @author inless427
 */
#ifndef HNG_ROLE_FILTER_CONFIG_HPP_
#define HNG_ROLE_FILTER_CONFIG_HPP_
#include <istream>
#include <string>
#include <vector>

namespace hng {
/** @brief EXACT 为精确匹配，REGEX 为 ECMAScript 正则整串匹配。 */
enum class LabelMatch { EXACT, REGEX };

/** @brief 一条标签匹配规则。 */
struct LabelRule {
    LabelMatch match = LabelMatch::EXACT;  ///< 默认精确匹配。
    std::string expression;                ///< 完整标签或正则表达式。
};

/** @brief 标签规则集合；黑名单优先，未命中白名单默认拒绝。 */
struct RoleFilterConfig {
    std::vector<LabelRule> whitelist;  ///< 允许普通事件采集的规则。
    std::vector<LabelRule> blacklist;  ///< 优先拒绝普通事件采集的规则。
};

/**
 * @brief 从输入流解析配置并校验所有规则。
 * @details 使用 [whitelist]、[blacklist] 段，每行 exact:标签 或 regex:正则。
 * 支持空行和以 # 开头的整行注释；不截断规则内容中的冒号和 #。
 * 总输入限 1 MiB、单行限 8192 字节、表达式限 4096 字节、规则限 4096 条。
 * @param[in,out] input 借用的流，读取推进当前位置，不接管所有权。
 * @param[in] source 用于错误消息的来源名称。
 * @return 完整校验后的规则集合；空配置默认拒绝普通事件采集。
 * @throws std::runtime_error 读取、语法、边界或正则校验失败，附来源和行号。
 */
RoleFilterConfig parse_role_filter_config(std::istream& input,
                                          const std::string& source = "<stream>");
/**
 * @brief 打开文件并解析配置。
 * @param[in] path 配置文件路径。
 * @return 完整校验后的规则集合。
 * @throws std::runtime_error 文件无法打开或解析失败。
 */
RoleFilterConfig load_role_filter_config(const std::string& path);
}  // namespace hng
#endif
