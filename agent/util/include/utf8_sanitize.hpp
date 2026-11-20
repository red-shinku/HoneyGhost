/**
 * @file utf8_sanitize.hpp
 * @brief 把任意字节串收敛为合法 UTF-8
 * @details 合法 UTF-8 序列原样保留，每个非法字节替换为 '?'，替换前后字节数相等。
 */

#ifndef HNG_UTIL_UTF8_SANITIZE_HPP_
#define HNG_UTIL_UTF8_SANITIZE_HPP_

#include <cstddef>
#include <string>
#include <string_view>

namespace hng {

/**
 * @brief 判断字节串是否为合法 UTF-8
 * @param text 待检查的字节串
 * @return 全部字节都能组成合法 UTF-8 序列时为 true；空串为 true
 * @details 排除 overlong 编码、代理区编码与超出 U+10FFFF 的取值，判定规则与
 *          protobuf 对 string 字段的要求一致。
 * @see sanitize_utf8
 */
bool is_valid_utf8(std::string_view text);

/**
 * @brief 把任意字节串收敛为合法 UTF-8
 * @param text 待收敛的字节串
 * @return 合法序列原样保留，每个非法字节替换为 '?'，输出与输入等长；空串返回空串
 * @details 尾部被截断的多字节序列逐字节按非法处理。
 * @see is_valid_utf8
 */
std::string sanitize_utf8(std::string_view text);

/**
 * @brief 把定长缓冲收敛为合法 UTF-8
 * @param raw 缓冲起始地址
 * @param size 缓冲容量
 * @return 只读 size 字节、截到首个 NUL 后按 sanitize_utf8 收敛的结果；
 *         raw 为空或 size 为 0 时返回空串
 * @note 不要求缓冲以 NUL 结尾。
 * @see sanitize_utf8
 */
std::string sanitize_utf8(const char* raw, std::size_t size);

}  // namespace hng

#endif  // HNG_UTIL_UTF8_SANITIZE_HPP_
