/**
 * @file test_agent_config.cc
 * @brief 主配置的文件解析、环境变量覆盖与路径解析单元测试
 * @author inless427
 */
#include "agent/config/include/agent_config.hpp"
#include "agent/config/include/config_loader.hpp"
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <sstream>
#include <stdexcept>
#include <string>

namespace {
using namespace hng;
namespace fs = std::filesystem;

int g_fail   = 0;

#define CHECK(cond, msg)                                                         \
    do {                                                                         \
        if (!(cond)) {                                                           \
            ++g_fail;                                                            \
            std::fprintf(stderr, "[FAIL] %s:%d  %s\n", __FILE__, __LINE__, msg); \
        }                                                                        \
    } while (0)

AgentConfig parse(const std::string& text,
                  const std::string& source = "agent.conf")
{
    std::istringstream input(text);
    return parse_agent_config(input, source);
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

fs::path temp_root()
{
    return fs::temp_directory_path() / "hng_agent_config_test";
}

void reset_dir(const fs::path& path)
{
    std::error_code ignored;
    fs::remove_all(path, ignored);
    fs::create_directories(path);
}

void write_file(const fs::path& path, const std::string& text)
{
    fs::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::binary);
    output << text;
    if (!output) throw std::runtime_error("写测试文件失败: " + path.string());
}

void run_defaults()
{
    std::istringstream input;
    const AgentConfig config = parse_agent_config(input, "empty.conf");
    CHECK(config.collector.enabled, "采集器默认开启");
    CHECK(config.role_discovery.systemd, "systemd 发现源默认开启");
    CHECK(config.role_discovery.containerd, "containerd 发现源默认开启");
    CHECK(config.role_discovery.containerd_socket_path ==
              "/run/honeyghost/containerd-bridge.sock",
          "containerd socket 应有内建默认值");
    CHECK(config.role_filter_config_path.empty(), "角色过滤路径默认为空");
    CHECK(!config.cli.enabled.has_value(), "cli.enabled 默认未设置");
    CHECK(config.cli.socket_path.empty(), "cli.socket_path 默认为空");
    CHECK(config.cli.config_path.empty(), "cli.config 默认为空");
}

void run_full_document()
{
    const AgentConfig config = parse(
        "[collector]\n"
        "enabled = false\n"
        "[role_discovery]\n"
        "systemd = false\n"
        "containerd = false\n"
        "containerd_socket_path = /tmp/containerd.sock\n"
        "[role_filter]\n"
        "path = conf/role_filter.conf\n"
        "[cli]\n"
        "enabled = true\n"
        "socket_path = /tmp/cli.sock\n"
        "config = conf/cli_server.conf\n");
    CHECK(!config.collector.enabled, "应读取 collector.enabled");
    CHECK(!config.role_discovery.systemd, "应读取 role_discovery.systemd");
    CHECK(!config.role_discovery.containerd, "应读取 role_discovery.containerd");
    CHECK(config.role_discovery.containerd_socket_path == "/tmp/containerd.sock",
          "应读取 containerd socket");
    CHECK(config.role_filter_config_path == "conf/role_filter.conf",
          "parse 应保持文件路径原样");
    CHECK(config.cli.enabled.has_value() && *config.cli.enabled,
          "应读取 cli.enabled");
    CHECK(config.cli.socket_path == "/tmp/cli.sock", "应读取 cli.socket_path");
    CHECK(config.cli.config_path == "conf/cli_server.conf", "应读取 cli.config");
}

void run_unknown_keys()
{
    REJECTS(parse("[collector]\nunknown = 1\n"), "未知键");
    REJECTS(parse("[collector]\nunknown = 1\n"), "agent.conf:2:");
    REJECTS(parse("[nope]\nx = 1\n"), "未知节");
    REJECTS(parse("[nope]\n"), "未知节");
}

void run_invalid_values()
{
    REJECTS(parse("[collector]\nenabled = maybe\n"), "布尔值");
    REJECTS(parse("[cli]\nenabled = maybe\n"), "布尔值");
    REJECTS(parse("[role_discovery]\ncontainerd_socket_path = relative.sock\n"),
            "绝对路径");
    REJECTS(parse("[role_discovery]\ncontainerd_socket_path = relative.sock\n"),
            "agent.conf:2: role_discovery.containerd_socket_path");
    REJECTS(parse("[role_discovery]\ncontainerd_socket_path =\n"), "不能为空");
    REJECTS(parse("[role_discovery]\ncontainerd_socket_path = /" +
                  std::string(107, 'a') + "\n"),
            "107");
    REJECTS(parse("[cli]\nsocket_path = relative.sock\n"), "绝对路径");
    REJECTS(parse("[cli]\nsocket_path = relative.sock\n"),
            "agent.conf:2: cli.socket_path");

    const AgentConfig empty_socket = parse("[cli]\nsocket_path =\n");
    CHECK(empty_socket.cli.socket_path.empty(), "cli.socket_path 允许为空");

    const AgentConfig relative = parse(
        "[role_filter]\n"
        "path = conf/role_filter.conf\n"
        "[cli]\n"
        "config = conf/cli_server.conf\n");
    CHECK(relative.role_filter_config_path == "conf/role_filter.conf",
          "role_filter.path 允许相对路径");
    CHECK(relative.cli.config_path == "conf/cli_server.conf",
          "cli.config 允许相对路径");
}

void run_environment_overrides()
{
    AgentConfig config = parse(
        "[collector]\n"
        "enabled = true\n"
        "[role_discovery]\n"
        "systemd = true\n"
        "[cli]\n"
        "enabled = true\n"
        "socket_path = /tmp/file.sock\n");
    const ConfigEnvironment environment{
        {"HNG_COLLECTOR_ENABLED", "false"},
        {"HNG_ROLE_DISCOVERY_SYSTEMD", "0"},
        {"HNG_CLI_ENABLED", "0"},
        {"HNG_CLI_SOCKET_PATH", "/tmp/env.sock"},
    };
    apply_config_environment(config, environment);
    CHECK(!config.collector.enabled, "环境变量应覆盖文件值");
    CHECK(!config.role_discovery.systemd, "环境变量应覆盖布尔值");
    CHECK(config.cli.enabled.has_value() && !*config.cli.enabled,
          "环境变量应覆盖可选布尔值");
    CHECK(config.cli.socket_path == "/tmp/env.sock", "环境变量应覆盖路径");

    AgentConfig untouched;
    apply_config_environment(untouched, {{"HNG_COLLECTOR_ENABLED", ""}});
    CHECK(untouched.collector.enabled, "空环境变量不应覆盖");

    AgentConfig bootstrap;
    apply_config_environment(bootstrap, {{"HNG_CONFIG", "/tmp/other.conf"}});
    CHECK(bootstrap.role_filter_config_path.empty() &&
              bootstrap.cli.config_path.empty(),
          "HNG_CONFIG 不应写入配置");
}

void run_invalid_environment()
{
    AgentConfig config;
    REJECTS(apply_config_environment(config, {{"HNG_COLLECTOR_ENABLED", "yes"}}),
            "HNG_COLLECTOR_ENABLED:");
    REJECTS(apply_config_environment(config,
                                     {{"HNG_CLI_SOCKET_PATH", "relative.sock"}}),
            "HNG_CLI_SOCKET_PATH:");
    REJECTS(apply_config_environment(
                config, {{"HNG_ROLE_DISCOVERY_CONTAINERD_SOCKET_PATH",
                          "/" + std::string(107, 'a')}}),
            "107");
}

void run_collect_environment()
{
    ::setenv("HNG_CONFIG", "/tmp/bootstrap.conf", 1);
    ::setenv("HNG_COLLECTOR_ENABLED", "false", 1);
    ::setenv("HNG_UNSUPPORTED_VARIABLE", "1", 1);
    const ConfigEnvironment environment = collect_environment();
    CHECK(environment.count("HNG_CONFIG") == 1, "应收集 HNG_CONFIG");
    CHECK(environment.at("HNG_CONFIG") == "/tmp/bootstrap.conf",
          "HNG_CONFIG 的值应保留");
    CHECK(environment.count("HNG_COLLECTOR_ENABLED") == 1,
          "应收集派生的布尔变量");
    CHECK(environment.count("HNG_UNSUPPORTED_VARIABLE") == 0,
          "不应收集未支持的变量");
    ::unsetenv("HNG_CONFIG");
    ::unsetenv("HNG_COLLECTOR_ENABLED");
    ::unsetenv("HNG_UNSUPPORTED_VARIABLE");
}

void run_resolve_source()
{
    AgentConfigSource source = resolve_agent_config_source("", {});
    CHECK(source.path == "/etc/honeyghost/agent.conf" && !source.required,
          "无输入时应使用默认路径且可选");

    source = resolve_agent_config_source("/tmp/a.conf", {});
    CHECK(source.path == "/tmp/a.conf" && source.required,
          "命令行路径优先且必需");

    source = resolve_agent_config_source("/tmp/a.conf",
                                         {{"HNG_CONFIG", "/tmp/b.conf"}});
    CHECK(source.path == "/tmp/a.conf" && source.required,
          "命令行路径应覆盖 HNG_CONFIG");

    source = resolve_agent_config_source("", {{"HNG_CONFIG", "/tmp/b.conf"}});
    CHECK(source.path == "/tmp/b.conf" && source.required,
          "HNG_CONFIG 应覆盖默认路径且必需");

    source = resolve_agent_config_source("", {{"HNG_CONFIG", ""}});
    CHECK(source.path == "/etc/honeyghost/agent.conf" && !source.required,
          "空 HNG_CONFIG 视为未设置");
}

void run_load_missing_source()
{
    const fs::path root = temp_root() / "missing";
    reset_dir(root);
    const std::string missing = (root / "absent.conf").string();
    REJECTS(load_agent_config({missing, true}, {}), "不存在");
    const AgentConfig fallback = load_agent_config({missing, false}, {});
    CHECK(fallback.collector.enabled, "可选缺文件应回落内建默认值");
    CHECK(fallback.role_discovery.containerd_socket_path ==
              "/run/honeyghost/containerd-bridge.sock",
          "可选缺文件应保留内建默认值");
}

void run_load_directory_source()
{
    const fs::path root = temp_root() / "directory";
    reset_dir(root);
    REJECTS(load_agent_config({root.string(), true}, {}), "不是普通文件");
    REJECTS(load_agent_config({root.string(), false}, {}), "不是普通文件");
}

void run_load_relative_paths()
{
    const fs::path root = temp_root() / "relative";
    reset_dir(root);
    write_file(root / "agent.conf",
               "[collector]\n"
               "enabled = false\n"
               "[role_filter]\n"
               "path = role_filter.conf\n"
               "[cli]\n"
               "enabled = true\n"
               "config = cli_server.conf\n");
    write_file(root / "role_filter.conf", "[whitelist]\n");
    write_file(root / "cli_server.conf", "[cli_server]\n");

    const AgentConfig config =
        load_agent_config({(root / "agent.conf").string(), true}, {});
    CHECK(!config.collector.enabled, "应保留文件值");
    const fs::path filter_path(config.role_filter_config_path);
    CHECK(filter_path.is_absolute(), "引用路径应解析为绝对路径");
    CHECK(filter_path.parent_path() == root, "相对路径应基于主配置目录");
    CHECK(filter_path.filename() == "role_filter.conf", "应保留文件名");
    const fs::path cli_path(config.cli.config_path);
    CHECK(cli_path.is_absolute(), "CLI 配置路径应解析为绝对路径");
    CHECK(cli_path.parent_path() == root, "CLI 配置路径应基于主配置目录");
}

void run_load_environment_paths()
{
    // 工作目录为仓库根，由 ctest 的 WORKING_DIRECTORY 保证
    const AgentConfig config = load_agent_config(
        {}, {{"HNG_ROLE_FILTER_PATH", "config/role_filter.conf"},
             {"HNG_CLI_CONFIG", "config/cli_server.conf"}});
    const fs::path filter_path(config.role_filter_config_path);
    CHECK(filter_path.is_absolute(), "环境变量相对路径应按工作目录解析");
    CHECK(filter_path.filename() == "role_filter.conf", "应保留文件名");
    CHECK(fs::is_regular_file(filter_path), "引用文件应可读");
    const fs::path cli_path(config.cli.config_path);
    CHECK(cli_path.is_absolute(), "CLI 配置路径应按工作目录解析");
    CHECK(cli_path.filename() == "cli_server.conf", "应保留文件名");
    CHECK(fs::is_regular_file(cli_path), "引用文件应可读");
}

void run_load_bad_references()
{
    const fs::path root = temp_root() / "references";
    reset_dir(root);
    write_file(root / "agent.conf", "[role_filter]\npath = absent.conf\n");
    REJECTS(load_agent_config({(root / "agent.conf").string(), true}, {}),
            "role_filter");
    write_file(root / "agent.conf", "[cli]\nconfig = .\n");
    REJECTS(load_agent_config({(root / "agent.conf").string(), true}, {}),
            "cli.config");
}

void run_repository_config()
{
    const AgentConfig config = load_agent_config({"config/agent.conf", true}, {});
    CHECK(config.collector.enabled, "示例配置应开启采集器");
    CHECK(config.role_discovery.systemd, "示例配置应开启 systemd 发现源");
    CHECK(config.role_discovery.containerd, "示例配置应开启 containerd 发现源");
    CHECK(config.role_discovery.containerd_socket_path ==
              "/run/honeyghost/containerd-bridge.sock",
          "示例配置应使用默认 containerd socket");
    CHECK(config.cli.enabled.has_value() && *config.cli.enabled,
          "示例配置应开启 CLI");
    CHECK(config.cli.socket_path.empty(), "示例配置不覆盖 CLI socket");

    const fs::path filter_path(config.role_filter_config_path);
    CHECK(filter_path.is_absolute(), "角色过滤路径应为绝对路径");
    CHECK(filter_path.parent_path().filename() == "config",
          "角色过滤路径应位于仓库 config/");
    CHECK(filter_path.filename() == "role_filter.conf",
          "应指向 role_filter.conf");
    CHECK(fs::is_regular_file(filter_path), "role_filter.conf 应可读");

    const fs::path cli_path(config.cli.config_path);
    CHECK(cli_path.is_absolute(), "CLI 配置路径应为绝对路径");
    CHECK(cli_path.parent_path().filename() == "config",
          "CLI 配置路径应位于仓库 config/");
    CHECK(cli_path.filename() == "cli_server.conf", "应指向 cli_server.conf");
    CHECK(fs::is_regular_file(cli_path), "cli_server.conf 应可读");
}

}  // namespace

int main()
{
    try {
        run_defaults();
        run_full_document();
        run_unknown_keys();
        run_invalid_values();
        run_environment_overrides();
        run_invalid_environment();
        run_collect_environment();
        run_resolve_source();
        run_load_missing_source();
        run_load_directory_source();
        run_load_relative_paths();
        run_load_environment_paths();
        run_load_bad_references();
        run_repository_config();
    }
    catch (const std::exception& error) {
        ++g_fail;
        std::fprintf(stderr, "[FAIL] 未捕获异常: %s\n", error.what());
    }

    std::error_code ignored;
    fs::remove_all(temp_root(), ignored);

    if (g_fail) {
        std::fprintf(stderr, "TOTAL FAILURES: %d\n", g_fail);
        return 1;
    }
    std::printf("ALL PASS\n");
    return 0;
}
