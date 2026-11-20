/**
 * @file test_utf8_sanitize.cc
 * @brief UTF-8 收敛工具的表驱动单元测试
 * @details
 * 覆盖合法序列原样保留、非法字节逐字节替换为 '?'、定长缓冲的 NUL 截断与空指针，
 * 以及 is_valid_utf8 与 sanitize_utf8 判定一致、收敛幂等。无 IO / 无特权。
 * @author red_shinku
 * @date 2026.11.20
 */

#include "agent/util/include/utf8_sanitize.hpp"

#include <cstddef>
#include <cstdio>
#include <string>

namespace {

int g_fail = 0;

#define CHECK(cond, msg)                                                         \
    do {                                                                         \
        if (!(cond)) {                                                           \
            ++g_fail;                                                            \
            std::fprintf(stderr, "[FAIL] %s:%d  %s\n", __FILE__, __LINE__, msg); \
        }                                                                        \
    } while (0)

struct SanitizeCase {
    const char* input;
    const char* expected;
};

// 合法序列：ASCII、2 字节（¢）、3 字节（中）、4 字节（😀）
// 非法：孤立续字节、非法首字节、overlong、代理区、超 U+10FFFF、尾部截断
constexpr SanitizeCase kSanitizeCases[] = {
    {"", ""},
    {"plain ascii", "plain ascii"},
    {"\xC2\xA2", "\xC2\xA2"},
    {"\xE4\xB8\xAD", "\xE4\xB8\xAD"},
    {"\xF0\x9F\x98\x80", "\xF0\x9F\x98\x80"},
    {"\x80", "?"},
    {"\xC0", "?"},
    {"\xF5", "?"},
    {"\xFF", "?"},
    {"\xC0\xAF", "??"},
    {"\xED\xA0\x80", "???"},
    {"\xF4\x90\x80\x80", "????"},
    {"\xE4\xB8", "??"},
    {"a\x80\xFF\xE4\xB8", "a????"},
};

void run_sanitize_cases()
{
    for (const SanitizeCase& c : kSanitizeCases) {
        const std::string input(c.input);
        const std::string out = hng::sanitize_utf8(input);
        CHECK(out == c.expected, "sanitize_utf8 结果");
        CHECK(hng::is_valid_utf8(input) == (out == input),
              "is_valid_utf8 与 sanitize 判定一致");
        CHECK(hng::is_valid_utf8(out), "收敛结果必为合法 UTF-8");
        CHECK(hng::sanitize_utf8(out) == out, "sanitize_utf8 幂等");
    }
}

void run_fixed_buffer_cases()
{
    // 截到首个 NUL：后续非法字节不参与收敛
    const char with_nul[5] = {'a', 'b', '\0', '\xFF', 'c'};
    CHECK(hng::sanitize_utf8(with_nul, sizeof(with_nul)) == "ab",
          "定长缓冲截到首个 NUL");

    // 满缓冲无 NUL：只读 size 字节，尾部被截断的序列逐字节替换
    const char full[4] = {'a', 'b', 'c', static_cast<char>(0xE4)};
    CHECK(hng::sanitize_utf8(full, sizeof(full)) == "abc?",
          "满缓冲无 NUL 不越界");

    // 满缓冲内的完整多字节序列原样保留
    const char utf8_full[4] = {static_cast<char>(0xE4), static_cast<char>(0xB8),
                               static_cast<char>(0xAD), 'x'};
    CHECK(hng::sanitize_utf8(utf8_full, sizeof(utf8_full)) == "\xE4\xB8\xADx",
          "满缓冲合法序列原样保留");

    CHECK(hng::sanitize_utf8(nullptr, 0).empty(), "nullptr 与 size 0");
    CHECK(hng::sanitize_utf8(nullptr, 8).empty(), "nullptr 非零 size");
    CHECK(hng::sanitize_utf8("abc", 0).empty(), "非空指针 size 0");
}

}  // namespace

int main()
{
    run_sanitize_cases();
    run_fixed_buffer_cases();

    if (g_fail) {
        std::fprintf(stderr, "TOTAL FAILURES: %d\n", g_fail);
        return 1;
    }
    std::printf("ALL PASS (cases=%zu)\n",
                sizeof(kSanitizeCases) / sizeof(SanitizeCase));
    return 0;
}
