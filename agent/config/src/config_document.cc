/**
 * @file
 * @brief INI 子集的有界读取、严格语法检查与类型转换。
 * @author inless427
 */
#include "agent/config/include/config_document.hpp"
#include <charconv>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace {
constexpr std::size_t kMaxBytes = 1024 * 1024;
constexpr std::size_t kMaxLine  = 8192;

/** @brief 去除两端的空格、制表符与回车，保留内部内容。 */
std::string trim(const std::string& text)
{
    const auto first = text.find_first_not_of(" \t\r");
    if (first == std::string::npos) return {};
    return text.substr(first, text.find_last_not_of(" \t\r") - first + 1);
}

/** @brief 节名与键名只允许小写字母、数字、下划线、连字符与点。 */
bool valid_name(const std::string& name)
{
    for (const char ch : name) {
        if (ch >= 'a' && ch <= 'z') continue;
        if (ch >= '0' && ch <= '9') continue;
        if (ch == '_' || ch == '-' || ch == '.') continue;
        return false;
    }
    return true;
}

char ascii_lower(char ch)
{
    return (ch >= 'A' && ch <= 'Z') ? static_cast<char>(ch - 'A' + 'a') : ch;
}

bool equals_ignore_case(std::string_view text, std::string_view expected)
{
    if (text.size() != expected.size()) return false;
    for (std::size_t i = 0; i < text.size(); ++i) {
        if (ascii_lower(text[i]) != ascii_lower(expected[i])) return false;
    }
    return true;
}

/** @brief 解析布尔字面量；非法时返回空。 */
std::optional<bool> parse_boolean(std::string_view text)
{
    if (equals_ignore_case(text, "true") || text == "1") return true;
    if (equals_ignore_case(text, "false") || text == "0") return false;
    return std::nullopt;
}
}  // namespace

namespace hng {

ConfigDocument ConfigDocument::parse(std::istream& input,
                                     const std::string& source)
{
    ConfigDocument document;
    document.source_ = source;
    std::string section;
    bool in_section = false;
    std::string line;
    std::size_t number = 0;
    std::size_t bytes  = 0;
    auto fail          = [&](const std::string& reason) {
        throw std::runtime_error(source + ":" + std::to_string(number + 1) +
                                          ": " + reason);
    };
    while (true) {
        line.clear();
        char ch = '\0';
        /** @note 有界逐字节读取，避免无换行的超长输入导致无界分配。 */
        while (input.get(ch)) {
            if (++bytes > kMaxBytes) fail("配置超过 1 MiB");
            if (ch == '\n') break;
            line.push_back(ch);
            if (line.size() > kMaxLine) fail("配置行超过 8192 字节");
        }
        if (input.bad() || (input.fail() && !input.eof())) fail("配置读取失败");
        if (line.empty() && input.eof()) break;
        if (line.find('\0') != std::string::npos) fail("不允许 NUL 字符");
        const std::string text = trim(line);
        if (!text.empty() && text.front() != '#') {
            if (text.front() == '[') {
                const auto close = text.find(']');
                if (close == std::string::npos) fail("节名缺少右方括号");
                if (close + 1 != text.size()) fail("节名后有多余字符");
                section = text.substr(1, close - 1);
                if (section.empty()) fail("节名不能为空");
                if (!valid_name(section))
                    fail("节名只能包含小写字母、数字、_、-、.");
                in_section = true;
                (void)document.sections_.emplace(section, Section{});
                (void)document.section_lines_.emplace(section, number + 1);
            }
            else {
                if (!in_section) fail("键值必须位于节内");
                const auto equals = text.find('=');
                if (equals == std::string::npos) fail("缺少 =");
                std::string key   = trim(text.substr(0, equals));
                std::string value = trim(text.substr(equals + 1));
                if (key.empty()) fail("键名不能为空");
                if (!valid_name(key)) fail("键名只能包含小写字母、数字、_、-、.");
                auto& entries = document.sections_[section];
                const auto inserted =
                    entries.emplace(key, Entry{std::move(value), number + 1});
                if (!inserted.second) fail("重复的键: " + section + "." + key);
            }
        }
        ++number;
    }
    return document;
}

bool ConfigDocument::contains(std::string_view section,
                              std::string_view key) const
{
    return find_entry(section, key) != nullptr;
}

std::size_t ConfigDocument::line_of(std::string_view section,
                                    std::string_view key) const
{
    const auto* entry = find_entry(section, key);
    return entry == nullptr ? 0 : entry->line;
}

std::string ConfigDocument::get_string(std::string_view section,
                                       std::string_view key,
                                       std::string default_value) const
{
    const auto* entry = find_entry(section, key);
    return entry == nullptr ? default_value : entry->value;
}

bool ConfigDocument::get_bool(std::string_view section, std::string_view key,
                              bool default_value) const
{
    const auto* entry = find_entry(section, key);
    if (entry == nullptr) return default_value;
    const auto parsed = parse_boolean(entry->value);
    if (!parsed) {
        fail_at(entry->line, std::string(section) + "." + std::string(key) +
                                 ": 布尔值应为 true、false、1 或 0");
    }
    return *parsed;
}

std::uint32_t ConfigDocument::get_uint(std::string_view section,
                                       std::string_view key,
                                       std::uint32_t default_value) const
{
    const auto* entry = find_entry(section, key);
    if (entry == nullptr) return default_value;
    const std::string label = std::string(section) + "." + std::string(key);
    if (entry->value.empty())
        fail_at(entry->line, label + ": 无符号整数不能为空");
    const std::string_view text = entry->value;
    std::uint64_t raw           = 0;
    const auto result =
        std::from_chars(text.data(), text.data() + text.size(), raw);
    if (result.ec == std::errc::result_out_of_range)
        fail_at(entry->line, label + ": 无符号整数溢出");
    if (result.ec != std::errc() || result.ptr != text.data() + text.size())
        fail_at(entry->line, label + ": 无符号整数只能包含十进制数字");
    if (raw > std::numeric_limits<std::uint32_t>::max())
        fail_at(entry->line, label + ": 无符号整数溢出");
    return static_cast<std::uint32_t>(raw);
}

std::chrono::milliseconds ConfigDocument::get_duration(
    std::string_view section, std::string_view key,
    std::chrono::milliseconds default_value) const
{
    const auto* entry = find_entry(section, key);
    if (entry == nullptr) return default_value;
    const std::string& value = entry->value;
    std::uint64_t factor     = 0;
    std::size_t digits       = 0;
    if (value.size() >= 2 && value.compare(value.size() - 2, 2, "ms") == 0) {
        factor = 1;
        digits = value.size() - 2;
    }
    else if (!value.empty()) {
        switch (value.back()) {
            case 's':
                factor = 1000;
                digits = value.size() - 1;
                break;
            case 'm':
                factor = 60 * 1000;
                digits = value.size() - 1;
                break;
            case 'h':
                factor = 60 * 60 * 1000;
                digits = value.size() - 1;
                break;
            default:
                break;
        }
    }
    const std::string label = std::string(section) + "." + std::string(key);
    if (factor == 0 || digits == 0)
        fail_at(entry->line, label + ": 时长应为无符号整数加 ms、s、m 或 h");
    const std::string_view text(value.data(), digits);
    std::uint64_t raw = 0;
    const auto result =
        std::from_chars(text.data(), text.data() + text.size(), raw);
    if (result.ec == std::errc::result_out_of_range)
        fail_at(entry->line, label + ": 时长溢出");
    if (result.ec != std::errc() || result.ptr != text.data() + text.size())
        fail_at(entry->line, label + ": 时长的数字部分只能包含十进制数字");
    const auto max_milliseconds =
        static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
    if (raw > max_milliseconds / factor)
        fail_at(entry->line, label + ": 时长溢出");
    return std::chrono::milliseconds(static_cast<std::int64_t>(raw * factor));
}

void ConfigDocument::reject_unknown_keys(
    std::initializer_list<ConfigKey> allowed) const
{
    auto section_declared = [&allowed](std::string_view section) {
        for (const auto& item : allowed) {
            if (item.section == section) return true;
        }
        return false;
    };
    auto key_declared = [&allowed](std::string_view section,
                                   std::string_view key) {
        for (const auto& item : allowed) {
            if (item.section == section && item.key == key) return true;
        }
        return false;
    };
    for (const auto& [section, entries] : sections_) {
        if (!section_declared(section)) {
            const auto line = section_lines_.find(section);
            fail_at(line == section_lines_.end() ? 0 : line->second,
                    "未知节: " + section);
        }
        for (const auto& [key, entry] : entries) {
            if (!key_declared(section, key))
                fail_at(entry.line, "未知键: " + section + "." + key);
        }
    }
}

void ConfigDocument::fail_at(std::size_t line, const std::string& reason) const
{
    throw std::runtime_error(source_ + ":" + std::to_string(line) + ": " +
                             reason);
}

const ConfigDocument::Entry* ConfigDocument::find_entry(
    std::string_view section, std::string_view key) const
{
    const auto section_it = sections_.find(section);
    if (section_it == sections_.end()) return nullptr;
    const auto entry_it = section_it->second.find(key);
    if (entry_it == section_it->second.end()) return nullptr;
    return &entry_it->second;
}

}  // namespace hng
