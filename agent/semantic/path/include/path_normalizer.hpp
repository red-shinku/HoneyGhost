/**
 * @file path_normalizer.hpp
 * @brief 路径归一化：词法层统一路径写法，供规则引擎匹配前调用
 * @details
 * 同一文件可能因书写差异（//、./、..、/var/run 与 /run 符号链接）产生多个拼写，
 * 归一化先消除写法差异，否则规则会漏过同一对象的其他写法。
 *
 * @author red_shinku
 * @date 2026.08.14
 */

#ifndef PATH_NORMALIZER_HPP
#define PATH_NORMALIZER_HPP

#include <string>
#include <string_view>

namespace hng {
namespace path {

/**
 * @brief 归一化绝对路径，消除同一文件的不同拼写
 * @details
 * 词法层统一写法：合并连续 '/'、去尾部 '/'、解析 '.'/'..'，并将 /var/run 归一为
 * /run（真实符号链接，两种写法指向同一目录）。语义化依赖它保证规则只看到规范拼写，
 * 否则同一对象会因写法差异漏过规则。
 * @param raw 原始路径（来自内核事件，可能为 openat 相对路径）
 * @param out 归一化结果
 * @return 是否发生改写；相对路径（不以 '/' 开头）原样返回并返回 false
 */
bool normalize(std::string_view raw, std::string& out);

}  // namespace path
}  // namespace hng

#endif  // PATH_NORMALIZER_HPP
