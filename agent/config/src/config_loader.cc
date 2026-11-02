/**
 * @file
 * @brief 主配置的读取、环境变量覆盖与相对路径解析。
 * @author inless427
 */
#include "agent/config/include/config_loader.hpp"
#include "agent/config/include/config_document.hpp"
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace {

/** @brief 主配置的一个键，环境变量名由节名与键名派生。 */
struct Field {
    const char* section;
    const char* key;
};

constexpr Field kFields[] = {
    {"collector", "enabled"},
    {"role_discovery", "systemd"},
    {"role_discovery", "containerd"},
    {"role_discovery", "containerd_socket_path"},
    {"role_filter", "path"},
    {"cli", "enabled"},
    {"cli", "socket_path"},
    {"cli", "config"},
};

constexpr const char* kConfigVariable = "HNG_CONFIG";
constexpr std::size_t kMaxSocketPath  = 107;

std::string uppercase(const char* text)
{
    std::string result;
    for (; *text != '\0'; ++text) {
        char ch = *text;
        if (ch >= 'a' && ch <= 'z') ch = static_cast<char>(ch - 'a' + 'A');
        result.push_back(ch);
    }
    return result;
}

/** @brief 由节名与键名派生环境变量名：HNG_ + 节名 + _ + 键名，全大写。 */
std::string environment_name(const Field& field)
{
    return "HNG_" + uppercase(field.section) + "_" + uppercase(field.key);
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

bool parse_boolean(const std::string& text, const std::string& name)
{
    if (equals_ignore_case(text, "true") || text == "1") return true;
    if (equals_ignore_case(text, "false") || text == "0") return false;
    throw std::runtime_error(name + ": 布尔值应为 true、false、1 或 0");
}

/** @brief 校验 socket 类路径：非空时必须是绝对路径且不超过 107 字节。 */
void validate_absolute_path(const std::string& value, bool allow_empty,
                            const std::string& label)
{
    if (value.empty()) {
        if (allow_empty) return;
        throw std::runtime_error(label + ": 值不能为空");
    }
    if (value.front() != '/')
        throw std::runtime_error(label + ": 值必须为绝对路径");
    if (value.size() > kMaxSocketPath)
        throw std::runtime_error(label + ": 路径超过 107 字节");
}

/** @brief 非空的环境变量值；未设置或为空时返回 nullptr。 */
const std::string* lookup(const hng::ConfigEnvironment& environment,
                          const Field& field, std::string& name)
{
    name          = environment_name(field);
    const auto it = environment.find(name);
    if (it == environment.end() || it->second.empty()) return nullptr;
    return &it->second;
}

bool is_readable_regular_file(const std::string& path)
{
    std::error_code error;
    const auto status = std::filesystem::status(path, error);
    if (error || !std::filesystem::is_regular_file(status)) return false;
    std::ifstream input(path, std::ios::binary);
    return static_cast<bool>(input);
}

}  // namespace

namespace hng {

ConfigEnvironment collect_environment()
{
    ConfigEnvironment environment;
    if (const char* value = std::getenv(kConfigVariable))
        environment.emplace(kConfigVariable, value);
    for (const auto& field : kFields) {
        std::string name = environment_name(field);
        if (const char* value = std::getenv(name.c_str()))
            environment.emplace(std::move(name), value);
    }
    return environment;
}

AgentConfigSource resolve_agent_config_source(
    const std::string& command_line_path, const ConfigEnvironment& environment)
{
    if (!command_line_path.empty()) return {command_line_path, true};
    const auto it = environment.find(kConfigVariable);
    if (it != environment.end() && !it->second.empty()) return {it->second, true};
    return {"/etc/honeyghost/agent.conf", false};
}

AgentConfig parse_agent_config(std::istream& input, const std::string& source)
{
    const auto document = ConfigDocument::parse(input, source);
    document.reject_unknown_keys({
        {"collector", "enabled"},
        {"role_discovery", "systemd"},
        {"role_discovery", "containerd"},
        {"role_discovery", "containerd_socket_path"},
        {"role_filter", "path"},
        {"cli", "enabled"},
        {"cli", "socket_path"},
        {"cli", "config"},
    });

    AgentConfig config;
    config.collector.enabled =
        document.get_bool("collector", "enabled", config.collector.enabled);
    config.role_discovery.systemd = document.get_bool(
        "role_discovery", "systemd", config.role_discovery.systemd);
    config.role_discovery.containerd = document.get_bool(
        "role_discovery", "containerd", config.role_discovery.containerd);
    config.role_discovery.containerd_socket_path =
        document.get_string("role_discovery", "containerd_socket_path",
                            config.role_discovery.containerd_socket_path);
    config.role_filter_config_path = document.get_string("role_filter", "path");
    if (document.contains("cli", "enabled"))
        config.cli.enabled = document.get_bool("cli", "enabled", false);
    config.cli.socket_path = document.get_string("cli", "socket_path");
    config.cli.config_path = document.get_string("cli", "config");

    auto path_label        = [&document, &source](std::string_view section,
                                           std::string_view key) {
        const std::string name = std::string(section) + "." + std::string(key);
        const std::size_t line = document.line_of(section, key);
        if (line == 0) return source + ": " + name;
        return source + ":" + std::to_string(line) + ": " + name;
    };
    validate_absolute_path(
        config.role_discovery.containerd_socket_path, false,
        path_label("role_discovery", "containerd_socket_path"));
    validate_absolute_path(config.cli.socket_path, true,
                           path_label("cli", "socket_path"));
    return config;
}

void apply_config_environment(AgentConfig& config,
                              const ConfigEnvironment& environment)
{
    std::string name;
    if (const auto* value = lookup(environment, {"collector", "enabled"}, name))
        config.collector.enabled = parse_boolean(*value, name);
    if (const auto* value =
            lookup(environment, {"role_discovery", "systemd"}, name))
        config.role_discovery.systemd = parse_boolean(*value, name);
    if (const auto* value =
            lookup(environment, {"role_discovery", "containerd"}, name))
        config.role_discovery.containerd = parse_boolean(*value, name);
    if (const auto* value = lookup(
            environment, {"role_discovery", "containerd_socket_path"}, name)) {
        validate_absolute_path(*value, false, name);
        config.role_discovery.containerd_socket_path = *value;
    }
    if (const auto* value = lookup(environment, {"role_filter", "path"}, name))
        config.role_filter_config_path = *value;
    if (const auto* value = lookup(environment, {"cli", "enabled"}, name))
        config.cli.enabled = parse_boolean(*value, name);
    if (const auto* value = lookup(environment, {"cli", "socket_path"}, name)) {
        validate_absolute_path(*value, true, name);
        config.cli.socket_path = *value;
    }
    if (const auto* value = lookup(environment, {"cli", "config"}, name))
        config.cli.config_path = *value;
}

AgentConfig load_agent_config(const AgentConfigSource& source,
                              const ConfigEnvironment& environment)
{
    AgentConfig config;
    bool loaded = false;
    std::filesystem::path base;
    if (!source.path.empty()) {
        std::error_code error;
        const auto status = std::filesystem::status(source.path, error);
        const bool exists = !error && std::filesystem::exists(status);
        if (error && error != std::errc::no_such_file_or_directory)
            throw std::runtime_error("无法访问配置文件: " + source.path + ": " +
                                     error.message());
        if (exists) {
            if (!std::filesystem::is_regular_file(status))
                throw std::runtime_error("配置路径不是普通文件: " + source.path);
            std::ifstream input(source.path, std::ios::binary);
            if (!input)
                throw std::runtime_error("无法打开配置文件: " + source.path);
            config = parse_agent_config(input, source.path);
            base   = std::filesystem::absolute(source.path).parent_path();
            loaded = true;
        }
        else if (source.required) {
            throw std::runtime_error("配置文件不存在: " + source.path);
        }
    }
    if (!loaded) base = std::filesystem::current_path();

    apply_config_environment(config, environment);

    auto resolve = [&base](std::string& path) {
        if (path.empty()) return;
        std::filesystem::path target(path);
        if (target.is_relative()) target = base / target;
        path = target.lexically_normal().string();
    };
    resolve(config.role_filter_config_path);
    resolve(config.cli.config_path);

    if (!config.role_filter_config_path.empty() &&
        !is_readable_regular_file(config.role_filter_config_path))
        throw std::runtime_error("role_filter.path 引用不可读的普通文件: " +
                                 config.role_filter_config_path);
    if (!config.cli.config_path.empty() &&
        !is_readable_regular_file(config.cli.config_path))
        throw std::runtime_error("cli.config 引用不可读的普通文件: " +
                                 config.cli.config_path);
    return config;
}

}  // namespace hng
