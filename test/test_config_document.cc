/**
 * @file test_config_document.cc
 * @brief ConfigDocument 的语法、类型读取与读取上限单元测试
 * @author inless427
 */
#include "agent/config/include/config_document.hpp"
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>

namespace {
using namespace hng;

int g_fail = 0;

#define CHECK(cond, msg)                                                         \
    do {                                                                         \
        if (!(cond)) {                                                           \
            ++g_fail;                                                            \
            std::fprintf(stderr, "[FAIL] %s:%d  %s\n", __FILE__, __LINE__, msg); \
        }                                                                        \
    } while (0)

ConfigDocument parse(const std::string& text,
                     const std::string& source = "unit.conf")
{
    std::istringstream input(text);
    return ConfigDocument::parse(input, source);
}

void expect_reject(const std::function<void()>& action,
                   const std::string& fragment, const char* expression, int line)
{
    try {
        action();
    }
    catch (const std::exception& error) {
        const std::string message = error.what();
        if (message.find(fragment) == std::string::npos) {
            ++g_fail;
            std::fprintf(stderr,
                         "[FAIL] %s:%d  %s\n        消息 \"%s\" 应包含 "
                         "\"%s\"\n",
                         __FILE__, line, expression, message.c_str(),
                         fragment.c_str());
        }
        return;
    }
    ++g_fail;
    std::fprintf(stderr, "[FAIL] %s:%d  %s 未抛出异常\n", __FILE__, line,
                 expression);
}

#define REJECTS(action, fragment) \
    expect_reject([&] { (void)(action); }, fragment, #action, __LINE__)

void run_basic_parsing()
{
    const auto document = parse(
        "[collector]\n"
        "enabled = true\n"
        "name = honeypot\n");
    CHECK(document.contains("collector", "enabled"), "应包含已声明的键");
    CHECK(!document.contains("collector", "missing"), "缺省键不应存在");
    CHECK(!document.contains("missing", "enabled"), "缺省节不应存在");
    CHECK(document.get_bool("collector", "enabled", false), "布尔值应为 true");
    CHECK(document.get_string("collector", "name") == "honeypot",
          "字符串值应原样保留");
    CHECK(document.get_string("collector", "missing", "fallback") == "fallback",
          "缺键应返回默认值");
}

void run_line_of()
{
    const auto document = parse(
        "[collector]\n"
        "enabled = true\n"
        "\n"
        "[cli]\n"
        "socket_path = /tmp/cli.sock\n");
    CHECK(document.line_of("collector", "enabled") == 2, "应返回键值行号");
    CHECK(document.line_of("cli", "socket_path") == 5, "空行也计入行号");
    CHECK(document.line_of("cli", "missing") == 0, "缺失键应返回 0");
    CHECK(document.line_of("missing", "enabled") == 0, "缺失节应返回 0");
}

void run_comments_and_blank_lines()
{
    const auto document = parse(
        "# 顶部注释\n"
        "   # 缩进注释\n"
        "\n"
        "[collector]\n"
        "\t# 节内注释\n"
        "enabled = 1\n");
    CHECK(document.get_bool("collector", "enabled", false),
          "注释与空行不应影响解析");
}

void run_values()
{
    const auto document = parse(
        "[s]\n"
        "key = a = b#c\n"
        "empty =\n"
        "spaced =\t value with space \t\n");
    CHECK(document.get_string("s", "key") == "a = b#c", "值应保留 = 与 #");
    CHECK(document.contains("s", "empty"), "空值键应存在");
    CHECK(document.get_string("s", "empty").empty(), "空值应返回空串");
    CHECK(document.get_string("s", "spaced") == "value with space",
          "值两端空白应去除");
}

void run_repeated_sections()
{
    const auto document = parse(
        "[s]\n"
        "a = 1\n"
        "[s]\n"
        "b = 2\n");
    CHECK(document.get_uint("s", "a", 0) == 1, "首次出现的键应可读");
    CHECK(document.get_uint("s", "b", 0) == 2, "重复节中的键应可读");
    REJECTS(parse("[s]\na = 1\na = 2\n"), "重复的键");
    REJECTS(parse("[s]\na = 1\na = 2\n"), "unit.conf:3:");
}

void run_syntax_errors()
{
    REJECTS(parse("a = 1\n"), "必须位于节内");
    REJECTS(parse("[s]\nkey\n"), "缺少 =");
    REJECTS(parse("[]\n"), "节名不能为空");
    REJECTS(parse("[S]\n"), "节名只能包含");
    REJECTS(parse("[s\n"), "右方括号");
    REJECTS(parse("[s] extra\n"), "多余字符");
    REJECTS(parse("[a b]\n"), "节名只能包含");
    REJECTS(parse("[s]\nKey = 1\n"), "键名只能包含");
    REJECTS(parse("[s]\n = 1\n"), "键名不能为空");
}

void run_nul_rejection()
{
    const std::string text = std::string("[s]\nkey = a") + '\0' + "b\n";
    REJECTS(parse(text), "NUL");
}

void run_unknown_keys()
{
    const auto document = parse(
        "[a]\n"
        "x = 1\n"
        "[b]\n"
        "y = 2\n");
    REJECTS(document.reject_unknown_keys({{"a", "x"}}), "未知节");
    REJECTS(document.reject_unknown_keys({{"a", "x"}}), "b");
    REJECTS(document.reject_unknown_keys({{"a", "x"}}), "unit.conf:3:");

    const auto empty_section = parse(
        "[a]\n"
        "x = 1\n"
        "[b]\n");
    REJECTS(empty_section.reject_unknown_keys({{"a", "x"}}), "未知节");
    REJECTS(empty_section.reject_unknown_keys({{"a", "x"}}), "b");

    const auto unknown_key = parse(
        "[a]\n"
        "x = 1\n"
        "y = 2\n");
    REJECTS(unknown_key.reject_unknown_keys({{"a", "x"}}), "未知键");
    CHECK(document.contains("a", "x"), "拒绝后文档仍可读取");

    const auto declared_empty = parse("[a]\n");
    declared_empty.reject_unknown_keys({{"a", "x"}});
}

bool read_bool(const std::string& value)
{
    return parse("[s]\nb = " + value + "\n").get_bool("s", "b", false);
}

void run_booleans()
{
    CHECK(read_bool("true"), "true 应为真");
    CHECK(read_bool("TRUE"), "布尔值不区分大小写");
    CHECK(read_bool("1"), "1 应为真");
    CHECK(!read_bool("false"), "false 应为假");
    CHECK(!read_bool("False"), "布尔值不区分大小写");
    CHECK(!read_bool("0"), "0 应为假");
    CHECK(parse("[s]\n").get_bool("s", "b", true), "缺键应返回默认值");
    REJECTS(read_bool("yes"), "布尔值");
    REJECTS(read_bool(""), "布尔值");
}

std::uint32_t read_uint(const std::string& value)
{
    return parse("[s]\nn = " + value + "\n").get_uint("s", "n", 0);
}

void run_uints()
{
    CHECK(read_uint("0") == 0, "0 应可读");
    CHECK(read_uint("42") == 42, "十进制整数应可读");
    CHECK(read_uint("4294967295") == std::numeric_limits<std::uint32_t>::max(),
          "uint32 上界应可读");
    CHECK(parse("[s]\n").get_uint("s", "n", 7) == 7, "缺键应返回默认值");
    REJECTS(read_uint("4294967296"), "溢出");
    REJECTS(read_uint("-1"), "十进制");
    REJECTS(read_uint("12x"), "十进制");
    REJECTS(read_uint(""), "不能为空");
}

std::chrono::milliseconds read_duration(const std::string& value)
{
    return parse("[s]\nt = " + value + "\n")
        .get_duration("s", "t", std::chrono::milliseconds(0));
}

void run_durations()
{
    using namespace std::chrono_literals;
    CHECK(read_duration("10ms") == 10ms, "ms 单位应可读");
    CHECK(read_duration("2s") == 2s, "s 单位应可读");
    CHECK(read_duration("3m") == 3min, "m 单位应可读");
    CHECK(read_duration("1h") == 1h, "h 单位应可读");
    CHECK(parse("[s]\n").get_duration("s", "t", 5ms) == 5ms, "缺键应返回默认值");
    REJECTS(read_duration("10"), "ms、s、m 或 h");
    REJECTS(read_duration("10x"), "ms、s、m 或 h");
    REJECTS(read_duration("s"), "ms、s、m 或 h");
    REJECTS(read_duration(""), "ms、s、m 或 h");
    REJECTS(read_duration("12.5s"), "十进制");
    REJECTS(read_duration("18446744073709551616ms"), "溢出");
    REJECTS(read_duration("9223372036854775807h"), "溢出");
}

void run_error_location()
{
    const auto document = parse("[s]\nb = maybe\n", "conf/agent.conf");
    REJECTS(document.get_bool("s", "b", true), "conf/agent.conf:2:");
    REJECTS(parse("[ok]\n[Bad]\n"), "unit.conf:2:");
}

void run_bounds()
{
    const std::string boundary = "[s]\nk = " + std::string(8188, 'x') + "\n";
    const auto document        = parse(boundary);
    CHECK(document.get_string("s", "k").size() == 8188, "8192 字节的行应被接受");
    REJECTS(parse("[s]\n" + std::string(8193, 'x') + "\n"), "8192");
    REJECTS(parse(std::string(1024 * 1024 + 1, '\n')), "1 MiB");
}

}  // namespace

int main()
{
    run_basic_parsing();
    run_line_of();
    run_comments_and_blank_lines();
    run_values();
    run_repeated_sections();
    run_syntax_errors();
    run_nul_rejection();
    run_unknown_keys();
    run_booleans();
    run_uints();
    run_durations();
    run_error_location();
    run_bounds();

    if (g_fail) {
        std::fprintf(stderr, "TOTAL FAILURES: %d\n", g_fail);
        return 1;
    }
    std::printf("ALL PASS\n");
    return 0;
}
