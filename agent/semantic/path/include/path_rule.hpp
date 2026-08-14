/**
 * @file path_rule.hpp
 * @brief 语义化规则引擎：结构规则（trie）+ 兜底扫描
 * @details
 * 语义化建模为"已知静态前缀 + 槽位（slot）"的结构匹配：
 *  - 阶段一：快路径门控，首段不在根集合内直接透传，避免整条路径拆分与匹配；
 *  - 阶段二：trie 结构规则匹配，静态优先、最长匹配；
 *  - 阶段三：兜底扫描，对结构规则覆盖不到、但实例特征无歧义的段做保守替换。
 *
 * @author red_shinku
 * @date 2026.08.14
 */

#ifndef PATH_RULE_HPP
#define PATH_RULE_HPP

#include <string>
#include <string_view>

namespace hng {
namespace path {

/**
 * @brief 语义化主入口：消除路径中的实例性，保留行为类别
 * @details
 * 三段式：快路径门控（首段不在根集合内直接透传，避免拆分与匹配）→ trie 结构规则
 * 匹配（静态优先、最长匹配）→ 兜底扫描（对结构规则未覆盖、但实例特征无歧义的段
 * 做保守替换）。输入必须为已归一化绝对路径（见 path_normalizer::normalize）。
 * @param norm_path 已归一化绝对路径
 * @param out 语义化结果；未命中任何规则时原样拷贝
 * @return 是否发生改写
 */
bool semanticize(std::string_view norm_path, std::string& out);

}  // namespace path
}  // namespace hng

#endif  // PATH_RULE_HPP
