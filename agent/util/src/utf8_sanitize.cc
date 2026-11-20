/**
 * @file utf8_sanitize.cc
 * @brief utf8_sanitize.hpp 的实现
 */

#include "agent/util/include/utf8_sanitize.hpp"

#include <cstddef>
#include <string>
#include <string_view>

namespace hng {

namespace {

/**
 * @brief 判断从 pos 起是否为一段合法 UTF-8，返回其长度
 * @param text 待检查的字节串
 * @param pos 起始位置
 * @return 合法序列的字节数（1..4）；非法或越界返回 0
 * @details 排除 overlong 编码、代理区编码与超出 U+10FFFF 的取值，
 *          与 protobuf 对 string 字段的 UTF-8 要求一致。
 */
std::size_t utf8_sequence_length(std::string_view text, std::size_t pos)
{
    const unsigned char lead = static_cast<unsigned char>(text[pos]);
    if (lead < 0x80) {
        return 1;
    }
    std::size_t length = 0;
    unsigned char low  = 0x80;
    unsigned char high = 0xBF;
    if (lead >= 0xC2 && lead <= 0xDF) {
        length = 2;
    }
    else if (lead >= 0xE0 && lead <= 0xEF) {
        length = 3;
        if (lead == 0xE0) {
            low = 0xA0;  // overlong
        }
        if (lead == 0xED) {
            high = 0x9F;  // 代理区
        }
    }
    else if (lead >= 0xF0 && lead <= 0xF4) {
        length = 4;
        if (lead == 0xF0) {
            low = 0x90;
        }
        if (lead == 0xF4) {
            high = 0x8F;
        }
    }
    else {
        return 0;
    }
    if (pos + length > text.size()) {
        return 0;
    }
    const unsigned char second = static_cast<unsigned char>(text[pos + 1]);
    if (second < low || second > high) {
        return 0;
    }
    for (std::size_t i = 2; i < length; ++i) {
        const unsigned char next = static_cast<unsigned char>(text[pos + i]);
        if (next < 0x80 || next > 0xBF) {
            return 0;
        }
    }
    return length;
}

}  // namespace

bool is_valid_utf8(std::string_view text)
{
    std::size_t pos = 0;
    while (pos < text.size()) {
        const std::size_t length = utf8_sequence_length(text, pos);
        if (length == 0) {
            return false;
        }
        pos += length;
    }
    return true;
}

std::string sanitize_utf8(std::string_view text)
{
    std::string out;
    out.reserve(text.size());
    std::size_t pos = 0;
    while (pos < text.size()) {
        const std::size_t length = utf8_sequence_length(text, pos);
        if (length == 0) {
            out += '?';
            ++pos;
            continue;
        }
        out.append(text.substr(pos, length));
        pos += length;
    }
    return out;
}

std::string sanitize_utf8(const char* raw, std::size_t size)
{
    if (raw == nullptr || size == 0) {
        return std::string();
    }
    const std::string_view text(raw, size);
    return sanitize_utf8(text.substr(0, text.find('\0')));
}

}  // namespace hng
