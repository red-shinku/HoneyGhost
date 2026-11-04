/**
 * @file main.cc
 * @brief 节点代理的进程入口
 * @details 主配置文件与环境变量驱动的启动：参数解析、配置加载、角色过滤
 *          配置加载、信号处理、装配层启停，以及编入构建时的 CLI 服务端运行。
 * @author red_shinku
 * @date 2026.10.27
 */

#include "agent/assembly/include/assembly.hpp"
#include "agent/cli_server/include/cli_server_runner.hpp"
#include "agent/config/include/config_loader.hpp"

#include "agent/role_filter/include/role_filter_config.hpp"
#include "agent/util/include/log.hpp"

#include <pthread.h>
#include <signal.h>

#include <cstdio>
#include <cstring>
#include <exception>
#include <string>
#include <utility>

namespace {

/// @brief 本构建是否编入 CLI 服务端
#ifdef HNG_HAVE_CLI_SERVER
constexpr bool kCliCompiled = true;
#else
constexpr bool kCliCompiled = false;
#endif

// 构建信息由 CMake 注入；未注入时给出可读的占位值
#ifndef HNG_VERSION
#define HNG_VERSION "dev"
#endif
#ifndef HNG_COMMIT
#define HNG_COMMIT "unknown"
#endif
#ifndef HNG_BUILD_DATE
#define HNG_BUILD_DATE "unknown"
#endif

/// @brief 命令行解析结果
struct Arguments {
    /// 主配置文件路径；空表示依次回退 HNG_CONFIG 与默认路径
    std::string config_path;
    /// 是否请求打印版本信息
    bool version = false;
    /// 是否请求打印用法
    bool help = false;
};

/**
 * @brief 打印用法
 * @param out 输出流；帮助请求用 stdout，参数错误用 stderr
 */
void print_usage(std::FILE* out)
{
    std::fprintf(
        out,
        "usage: hng_agent [options]\n"
        "  --config PATH  主配置文件；省略时依次取环境变量 HNG_CONFIG、\n"
        "                 /etc/honeyghost/agent.conf\n"
        "  --version      显示版本信息并退出\n"
        "  -h, --help     显示本说明并退出\n");
}

/**
 * @brief 打印构建版本
 * @param out 输出流；固定为 stdout
 * @note 格式与 hghost、containerd-bridge 一致：<name> <version> (<commit>, <date>)
 */
void print_version(std::FILE* out)
{
    std::fprintf(out, "hng_agent %s (%s, %s)\n", HNG_VERSION, HNG_COMMIT,
                 HNG_BUILD_DATE);
}

/**
 * @brief 解析命令行
 * @param argc 参数个数
 * @param argv 参数数组
 * @param args 解析结果
 * @return 解析成功为 true；缺少取值、空取值或未知参数为 false
 * @note --help 与 --version 出现即返回，不再解析后续参数
 */
bool parse_arguments(int argc, char** argv, Arguments& args)
{
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            args.help = true;
            return true;
        }

        if (arg == "--version") {
            args.version = true;
            return true;
        }

        if (arg == "--config") {
            if (i + 1 >= argc) {
                HNG_LOG_ERROR("--config requires a value");
                return false;
            }
            args.config_path = argv[++i];
            if (args.config_path.empty()) {
                HNG_LOG_ERROR("--config requires a non-empty value");
                return false;
            }
        }
        else {
            HNG_LOG_ERROR("unknown argument: {}", arg);
            return false;
        }
    }
    return true;
}

/**
 * @brief 构造信号集并在当前线程阻塞其中信号
 * @param signals 输出：被阻塞的信号集合
 * @param include_cli_signals true：一并阻塞 CLI 服务端接管的
 *        SIGQUIT/SIGUSR1/SIGUSR2
 * @return 屏蔽成功为 true；pthread_sigmask 失败为 false
 * @note 须在构造装配层前调用，之后创建的线程继承该掩码
 */
bool block_signals(sigset_t& signals, bool include_cli_signals)
{
    sigemptyset(&signals);
    sigaddset(&signals, SIGINT);
    sigaddset(&signals, SIGTERM);
    if (include_cli_signals) {
        sigaddset(&signals, SIGQUIT);
        sigaddset(&signals, SIGUSR1);
        sigaddset(&signals, SIGUSR2);
    }

    const int mask_error = pthread_sigmask(SIG_BLOCK, &signals, nullptr);
    if (mask_error != 0) {
        HNG_LOG_ERROR("pthread_sigmask failed: {}", std::strerror(mask_error));
        return false;
    }
    return true;
}

}  // namespace

int main(int argc, char** argv)
{
    Arguments args;
    if (!parse_arguments(argc, argv, args)) {
        print_usage(stderr);
        return 1;
    }
    if (args.help) {
        print_usage(stdout);
        return 0;
    }
    if (args.version) {
        print_version(stdout);
        return 0;
    }

    const hng::ConfigEnvironment environment = hng::collect_environment();
    hng::AgentConfigSource source;
    hng::AgentConfig config;
    try {
        source = hng::resolve_agent_config_source(args.config_path, environment);
        config = hng::load_agent_config(source, environment);
    }
    catch (const std::exception& error) {
        HNG_LOG_ERROR("failed to load agent config: {}", error.what());
        return 1;
    }

    // 未设置 cli.enabled 时取编译期结果
    bool cli_enabled = kCliCompiled;
    if (config.cli.enabled.has_value()) {
        cli_enabled = *config.cli.enabled;
    }
    if (cli_enabled && !kCliCompiled) {
        HNG_LOG_ERROR(
            "cli.enabled is true but the CLI server is not compiled in; "
            "rebuild with -DHNG_ENABLE_CLI_SERVER=ON");
        return 1;
    }

    hng::AssemblyOptions options;
    options.collect                = config.collector.enabled;
    options.enable_systemd         = config.role_discovery.systemd;
    options.enable_containerd      = config.role_discovery.containerd;
    options.containerd_socket_path = config.role_discovery.containerd_socket_path;

    if (config.role_filter_config_path.empty()) {
        HNG_LOG_WARN(
            "no role_filter.path configured; the empty policy rejects "
            "ordinary event collection");
    }
    else {
        try {
            options.role_filter_config =
                hng::load_role_filter_config(config.role_filter_config_path);
        }
        catch (const std::exception& error) {
            HNG_LOG_ERROR("failed to load role filter config {}: {}",
                          config.role_filter_config_path, error.what());
            return 1;
        }
    }

    CLIServerOptions cli_options;
    if (!config.cli.socket_path.empty()) {
        cli_options.unix_socket_path = config.cli.socket_path;
    }
    cli_options.config_path = config.cli.config_path;

    PreparedCliServerConfig cli_config;
    if (cli_enabled) {
#ifdef HNG_HAVE_CLI_SERVER
        try {
            cli_config = prepare_cli_server_config(cli_options);
        }
        catch (const std::exception& error) {
            HNG_LOG_ERROR("failed to prepare cli server config: {}",
                          error.what());
            return 1;
        }
#endif
    }

    const std::string& cli_socket =
        cli_enabled ? cli_config.unix_socket_path : cli_options.unix_socket_path;

    HNG_LOG_INFO(
        "agent config: source {}, collect {}, systemd {}, containerd {}, "
        "role filter {}, cli {}, cli socket {}",
        source.path.empty() ? "<built-in defaults>" : source.path,
        options.collect, options.enable_systemd, options.enable_containerd,
        config.role_filter_config_path.empty() ? "<empty policy>"
                                               : config.role_filter_config_path,
        cli_enabled, cli_socket);

    // 构造装配层前阻塞信号，之后创建的线程继承该掩码
    sigset_t signals;
    if (!block_signals(signals, cli_enabled)) {
        return 1;
    }

    try {
        hng::Assembly assembly(std::move(options));
        const hng::InitReport report = assembly.start();
        if (report.state == hng::InitState::FAILED) {
            HNG_LOG_ERROR("initialization failed; exiting");
            assembly.stop();
            return 1;
        }
        HNG_LOG_INFO(
            "agent started: state {}, process inserted {}, context inserted "
            "{}, role filter applied processes {}, role source timeout {}",
            hng::to_string(report.state), report.process.inserted,
            report.context.inserted, report.role_filter.applied_processes,
            report.role_source_timeout);

        if (cli_enabled) {
#ifdef HNG_HAVE_CLI_SERVER
            const hng::AgentServices services = assembly.services();
            CLIServerDeps deps;
            deps.role    = services.role;
            deps.context = services.context;
            deps.process = services.process;
            deps.subs    = services.subscriber;
            HNG_LOG_INFO("starting cli server on unix socket {}",
                         cli_config.unix_socket_path);
            RunCliServer(deps, cli_config);
#endif
        }
        else {
            int signal_number    = 0;
            const int wait_error = sigwait(&signals, &signal_number);
            if (wait_error != 0) {
                HNG_LOG_ERROR("sigwait failed: {}", std::strerror(wait_error));
                assembly.stop();
                return 1;
            }
            HNG_LOG_INFO("received signal {}; stopping", signal_number);
        }
        assembly.stop();
    }
    catch (const std::exception& error) {
        HNG_LOG_ERROR("agent failed: {}", error.what());
        return 1;
    }

    return 0;
}
