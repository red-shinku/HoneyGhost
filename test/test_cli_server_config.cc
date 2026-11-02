/**
 * @file test_cli_server_config.cc
 * @brief CLIServer 静态配置 schema 与配置准备的单元测试
 * @details
 * schema 以 YAML 文本写成，平时只在组件注册时解析；此处直接取来解析，使格式错误
 * 或配置项漏写能在单测里暴露，而不是等到进程启动。另覆盖
 * prepare_cli_server_config 的默认值、文件取值、socket 覆盖与错误路径。
 * @author red-shinku
 * @date 2026.10.18
 */

#include "agent/cli_server/include/cli_server_runner.hpp"
#include "agent/cli_server/src/cli_server.hpp"

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <functional>
#include <stdexcept>
#include <string>

namespace {

namespace fs = std::filesystem;

int g_fail   = 0;

#define CHECK(cond, msg)                                                         \
    do {                                                                         \
        if (!(cond)) {                                                           \
            ++g_fail;                                                            \
            std::fprintf(stderr, "[FAIL] %s:%d  %s\n", __FILE__, __LINE__, msg); \
        }                                                                        \
    } while (0)

/**
 * @brief 断言 action 抛出异常且消息包含 fragment
 * @param expression 抛错表达式的文本，仅用于失败报告
 * @param line 调用处的行号
 */
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

/// @return 测试用临时目录根
fs::path temp_root()
{
    return fs::temp_directory_path() / "hng_cli_server_config_test";
}

/// @brief 清空并重建目录
void reset_dir(const fs::path& path)
{
    std::error_code ignored;
    fs::remove_all(path, ignored);
    fs::create_directories(path);
}

/// @brief 写文件；父目录不存在时创建
void write_file(const fs::path& path, const std::string& text)
{
    fs::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::binary);
    output << text;
    if (!output) throw std::runtime_error("写测试文件失败: " + path.string());
}

/// @return text 包含 fragment 时为 true
bool has_text(const std::string& text, const std::string& fragment)
{
    return text.find(fragment) != std::string::npos;
}

/// @brief 在 temp_root()/name 下写一份 CLI 配置文件
/// @return 写入的文件路径
std::string write_case(const std::string& name, const std::string& text)
{
    const fs::path root = temp_root() / name;
    reset_dir(root);
    const fs::path path = root / "cli_server.conf";
    write_file(path, text);
    return path.string();
}

/// @return 只指定配置文件路径的运行参数
CLIServerOptions options_for(const std::string& path)
{
    CLIServerOptions options;
    options.config_path = path;
    return options;
}

/// @brief 内建静态配置 schema：解析 YAML 文本并核对配置项
void run_schema()
{
    const userver::yaml_config::Schema schema =
        CLIServer::GetStaticConfigSchema();

    CHECK(schema.type == userver::yaml_config::FieldType::kObject,
          "顶层应为对象");
    CHECK(schema.properties.has_value(), "应声明配置项");
    if (!schema.properties.has_value()) {
        return;
    }

    const auto& properties = *schema.properties;
    CHECK(properties.count("max-concurrent-streams") == 1, "应声明并发流上限");
    CHECK(properties.count("queue-capacity") == 1, "应声明每流队列容量");
    CHECK(properties.count("drain-timeout") == 1, "应声明停机等待上界");

    CHECK(properties.at("max-concurrent-streams")->type ==
              userver::yaml_config::FieldType::kInteger,
          "并发流上限应为整数");
    CHECK(properties.at("queue-capacity")->type ==
              userver::yaml_config::FieldType::kInteger,
          "每流队列容量应为整数");
    CHECK(properties.at("drain-timeout")->type ==
              userver::yaml_config::FieldType::kString,
          "停机等待上界应为时长字符串");
}

/// @brief 无配置文件：内建默认值 + 四类服务组件 + 无残留占位符
void run_defaults()
{
    const PreparedCliServerConfig prepared = prepare_cli_server_config({});

    CHECK(prepared.unix_socket_path == "/run/honeyghost/cli.sock",
          "默认 socket 应为 /run/honeyghost/cli.sock");
    CHECK(
        has_text(prepared.text, "unix-socket-path: \"/run/honeyghost/cli.sock\""),
        "配置文本应含默认 socket");
    CHECK(has_text(prepared.text, "max-concurrent-streams: 64"),
          "配置文本应含默认并发流上限");
    CHECK(has_text(prepared.text, "queue-capacity: 1024"),
          "配置文本应含默认队列容量");
    CHECK(has_text(prepared.text, "drain-timeout: 10000ms"),
          "配置文本应含默认 drain 超时");
    CHECK(has_text(prepared.text, "cli-role-service"), "应含角色查询服务组件");
    CHECK(has_text(prepared.text, "cli-context-service"),
          "应含上下文查询服务组件");
    CHECK(has_text(prepared.text, "cli-process-service"), "应含进程查询服务组件");
    CHECK(has_text(prepared.text, "cli-runtime-service"), "应含运行时服务组件");

    CHECK(!has_text(prepared.text, "@SOCKET@"), "@SOCKET@ 应已填充");
    CHECK(!has_text(prepared.text, "@MAX_STREAMS@"), "@MAX_STREAMS@ 应已填充");
    CHECK(!has_text(prepared.text, "@QUEUE_CAPACITY@"),
          "@QUEUE_CAPACITY@ 应已填充");
    CHECK(!has_text(prepared.text, "@DRAIN_TIMEOUT@"),
          "@DRAIN_TIMEOUT@ 应已填充");
}

/// @brief 配置文件四个键全部读入并出现在文本与返回值中
void run_file_values()
{
    const std::string path = write_case("values",
                                        "[cli_server]\n"
                                        "max_concurrent_streams = 8\n"
                                        "queue_capacity = 256\n"
                                        "drain_timeout = 3s\n"
                                        "socket_path = /tmp/file.sock\n");

    const PreparedCliServerConfig prepared =
        prepare_cli_server_config(options_for(path));
    CHECK(prepared.unix_socket_path == "/tmp/file.sock", "应使用文件中的 socket");
    CHECK(has_text(prepared.text, "unix-socket-path: \"/tmp/file.sock\""),
          "配置文本应含文件 socket");
    CHECK(has_text(prepared.text, "max-concurrent-streams: 8"),
          "配置文本应含文件并发流上限");
    CHECK(has_text(prepared.text, "queue-capacity: 256"),
          "配置文本应含文件队列容量");
    CHECK(has_text(prepared.text, "drain-timeout: 3000ms"),
          "配置文本应含文件 drain 超时");
}

/// @brief 文件与运行参数的 socket 冲突时运行参数胜出
void run_socket_override()
{
    const std::string text = "[cli_server]\nsocket_path = /tmp/file.sock\n";

    CLIServerOptions options;
    options.unix_socket_path               = "/tmp/option.sock";
    options.config_path                    = write_case("override", text);
    const PreparedCliServerConfig prepared = prepare_cli_server_config(options);
    CHECK(prepared.unix_socket_path == "/tmp/option.sock",
          "运行参数应覆盖文件 socket");
    CHECK(has_text(prepared.text, "unix-socket-path: \"/tmp/option.sock\""),
          "配置文本应含运行参数 socket");
    CHECK(!has_text(prepared.text, "/tmp/file.sock"),
          "配置文本不应残留文件 socket");

    CLIServerOptions only_option;
    only_option.unix_socket_path = "/tmp/option.sock";
    CHECK(prepare_cli_server_config(only_option).unix_socket_path ==
              "/tmp/option.sock",
          "无配置文件时运行参数也应生效");
}

/// @brief 未知键、越界、非法 socket 与不可读文件都抛异常
void run_rejects()
{
    const std::string unknown_key =
        write_case("unknown-key", "[cli_server]\nunknown = 1\n");
    REJECTS(prepare_cli_server_config(options_for(unknown_key)), "未知键");
    REJECTS(prepare_cli_server_config(options_for(unknown_key)),
            unknown_key + ":2: 未知键");

    REJECTS(prepare_cli_server_config(
                options_for(write_case("unknown-section", "[nope]\nx = 1\n"))),
            "未知节");
    REJECTS(prepare_cli_server_config(
                options_for(write_case("empty-section", "[nope]\n"))),
            "未知节");

    const std::string max_streams_zero = write_case(
        "max-streams-zero", "[cli_server]\nmax_concurrent_streams = 0\n");
    REJECTS(prepare_cli_server_config(options_for(max_streams_zero)),
            "cli_server.max_concurrent_streams");
    REJECTS(prepare_cli_server_config(options_for(max_streams_zero)),
            max_streams_zero + ":2: cli_server.max_concurrent_streams");
    REJECTS(prepare_cli_server_config(options_for(
                write_case("max-streams-high",
                           "[cli_server]\nmax_concurrent_streams = 65536\n"))),
            "65535");

    const std::string max_streams_type = write_case(
        "max-streams-type", "[cli_server]\nmax_concurrent_streams = abc\n");
    REJECTS(prepare_cli_server_config(options_for(max_streams_type)),
            "cli_server.max_concurrent_streams");
    REJECTS(prepare_cli_server_config(options_for(max_streams_type)),
            max_streams_type + ":2: cli_server.max_concurrent_streams:");

    REJECTS(prepare_cli_server_config(options_for(
                write_case("queue-zero", "[cli_server]\nqueue_capacity = 0\n"))),
            "cli_server.queue_capacity");
    REJECTS(prepare_cli_server_config(options_for(write_case(
                "queue-high", "[cli_server]\nqueue_capacity = 1048577\n"))),
            "1048576");

    REJECTS(prepare_cli_server_config(options_for(
                write_case("drain-zero", "[cli_server]\ndrain_timeout = 0ms\n"))),
            "cli_server.drain_timeout");
    REJECTS(prepare_cli_server_config(options_for(write_case(
                "drain-high", "[cli_server]\ndrain_timeout = 300001ms\n"))),
            "300s");

    const std::string drain_type =
        write_case("drain-type", "[cli_server]\ndrain_timeout = 10x\n");
    REJECTS(prepare_cli_server_config(options_for(drain_type)),
            "cli_server.drain_timeout");
    REJECTS(prepare_cli_server_config(options_for(drain_type)),
            drain_type + ":2: cli_server.drain_timeout:");

    REJECTS(prepare_cli_server_config(options_for(write_case(
                "relative", "[cli_server]\nsocket_path = relative.sock\n"))),
            "绝对路径");
    REJECTS(prepare_cli_server_config(options_for(
                write_case("empty", "[cli_server]\nsocket_path =\n"))),
            "不能为空");
    REJECTS(prepare_cli_server_config(options_for(write_case(
                "long",
                "[cli_server]\nsocket_path = /" + std::string(107, 'a') + "\n"))),
            "107");

    CLIServerOptions relative_option;
    relative_option.unix_socket_path = "relative.sock";
    REJECTS(prepare_cli_server_config(relative_option), "cli.socket_path");
    REJECTS(prepare_cli_server_config(relative_option), "绝对路径");
    CLIServerOptions long_option;
    long_option.unix_socket_path = "/" + std::string(107, 'a');
    REJECTS(prepare_cli_server_config(long_option), "107");

    const fs::path missing_root = temp_root() / "missing";
    reset_dir(missing_root);
    REJECTS(prepare_cli_server_config(
                options_for((missing_root / "absent.conf").string())),
            "不存在");
    REJECTS(prepare_cli_server_config(options_for(missing_root.string())),
            "不是普通文件");
}

}  // namespace

int main()
{
    try {
        run_schema();
        run_defaults();
        run_file_values();
        run_socket_override();
        run_rejects();
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
