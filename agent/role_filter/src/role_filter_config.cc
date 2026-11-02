/**
 * @file
 * @brief 有界配置读取、严格语法解析及来源行号错误报告。
 * @author inless427
 */
#include "agent/role_filter/include/role_filter_config.hpp"
#include "agent/role_filter/include/role_filter_policy.hpp"
#include <fstream>
#include <stdexcept>
#include <utility>

namespace {
/** @brief 去除两端的空格、制表符与回车，保留规则内部内容。 */
std::string trim(const std::string& text)
{
    const auto first = text.find_first_not_of(" \t\r");
    if (first == std::string::npos) return {};
    return text.substr(first, text.find_last_not_of(" \t\r") - first + 1);
}
}  // namespace

namespace hng {

RoleFilterConfig parse_role_filter_config(std::istream& input,
                                          const std::string& source)
{
    RoleFilterConfig result;
    std::vector<LabelRule>* section = nullptr;
    bool white_seen = false, black_seen = false;
    std::string line;
    std::size_t number = 0, bytes = 0, count = 0;
    auto fail = [&](const std::string& why) {
        throw std::runtime_error(source + ":" + std::to_string(number + 1) +
                                 ": " + why);
    };
    while (true) {
        line.clear();
        char ch;
        /** @note 有界逐字节读取，避免无换行的超长输入导致无界分配。 */
        while (input.get(ch)) {
            if (++bytes > 1024 * 1024) fail("配置超过 1 MiB");
            if (ch == '\n') break;
            line.push_back(ch);
            if (line.size() > 8192) fail("配置行超过 8192 字节");
        }
        if (input.bad() || (input.fail() && !input.eof())) fail("配置读取失败");
        if (line.empty() && input.eof()) break;
        line = trim(line);
        if (line.find('\0') != std::string::npos) fail("不允许 NUL 字符");
        if (!line.empty() && line.front() != '#') {
            if (line == "[whitelist]") {
                if (white_seen) fail("重复 whitelist 段");
                white_seen = true;
                section    = &result.whitelist;
            }
            else if (line == "[blacklist]") {
                if (black_seen) fail("重复 blacklist 段");
                black_seen = true;
                section    = &result.blacklist;
            }
            else {
                if (!section) fail("规则必须放在名单段内");
                const auto colon = line.find(':');
                if (colon == std::string::npos)
                    fail("规则应为 exact:标签 或 regex:正则");
                const auto kind       = trim(line.substr(0, colon));
                const auto expression = trim(line.substr(colon + 1));
                if (expression.empty() || expression.size() > 4096)
                    fail("规则为空或超过 4096 字节");
                LabelMatch match = LabelMatch::EXACT;
                if (kind == "exact")
                    match = LabelMatch::EXACT;
                else if (kind == "regex")
                    match = LabelMatch::REGEX;
                else
                    fail("未知规则类型: " + kind);
                if (++count > 4096) fail("规则数超过 4096");
                LabelRule rule{match, expression};
                try {
                    (void)RoleFilterPolicy(RoleFilterConfig{{rule}, {}});
                }
                catch (const std::runtime_error& error) {
                    fail(error.what());
                }
                section->push_back(std::move(rule));
            }
        }
        ++number;
    }
    return result;
}

RoleFilterConfig load_role_filter_config(const std::string& path)
{
    std::ifstream input(path, std::ios::binary);
    if (!input) throw std::runtime_error("无法打开角色名单配置: " + path);
    return parse_role_filter_config(input, path);
}
}  // namespace hng
