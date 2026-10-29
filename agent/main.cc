/**
 * @file main.cc
 * @brief 节点代理的进程入口
 * @details 参数解析、角色过滤配置加载、信号处理、装配层启停，以及编入构建
 *          时的 CLI 服务端运行。
 * @author red_shinku
 * @date 2026.10.27
 */

#include "agent/assembly/include/assembly.hpp"
#include "agent/cli_server/include/cli_server_runner.hpp"

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

/// @brief 命令行解析结果
struct Arguments {
    /// 角色过滤配置文件路径；空表示使用空策略
    std::string role_filter_config_path;
    /// 装配层构造选项，命令行可覆盖其中字段
    hng::AssemblyOptions options;
    /// 是否请求打印用法
    bool help = false;
    /// CLI 服务端的进程级运行参数
    CLIServerOptions cli_options;
    /// 是否经 --no-cli 关闭 CLI 服务端
    bool cli_disabled = false;
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
        "  --role-filter-config PATH  角色过滤配置；省略时拒绝普通事件采集\n"
        "  --no-collect               不加载探针，只运行控制面与事件引擎\n"
        "  --no-systemd               关闭 systemd 角色发现源\n"
        "  --no-containerd            关闭 containerd 角色发现源\n"
        "  --containerd-socket PATH   翻译进程的 Unix socket 路径\n"
        "  --no-cli                   不启动 CLI 服务端\n"
        "  --cli-socket PATH          覆盖 CLI 服务端的 Unix socket 路径\n"
        "  -h, --help                 显示本说明并退出\n");
}

/**
 * @brief 解析命令行
 * @param argc 参数个数
 * @param argv 参数数组
 * @param args 解析结果
 * @return 解析成功为 true；未知参数或缺少取值为 false
 * @note --help 出现即返回，不再解析后续参数
 */
bool parse_arguments(int argc, char** argv, Arguments& args)
{
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            args.help = true;
            return true;
        }

        if (arg == "--role-filter-config") {
            if (i + 1 >= argc) {
                HNG_LOG_ERROR("--role-filter-config requires a value");
                return false;
            }
            args.role_filter_config_path = argv[++i];
        }
        else if (arg == "--containerd-socket") {
            if (i + 1 >= argc) {
                HNG_LOG_ERROR("--containerd-socket requires a value");
                return false;
            }
            args.options.containerd_socket_path = argv[++i];
        }
        else if (arg == "--no-collect") {
            args.options.collect = false;
        }
        else if (arg == "--no-systemd") {
            args.options.enable_systemd = false;
        }
        else if (arg == "--no-containerd") {
            args.options.enable_containerd = false;
        }
        else if (arg == "--no-cli") {
            args.cli_disabled = true;
        }
        else if (arg == "--cli-socket") {
            if (i + 1 >= argc) {
                HNG_LOG_ERROR("--cli-socket requires a value");
                return false;
            }
            if (!kCliCompiled) {
                HNG_LOG_ERROR(
                    "--cli-socket unavailable: CLI server is not compiled in; "
                    "rebuild with -DHNG_ENABLE_CLI_SERVER=ON");
                return false;
            }
            args.cli_options.unix_socket_path = argv[++i];
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

    if (args.role_filter_config_path.empty()) {
        HNG_LOG_WARN(
            "no --role-filter-config given; the empty policy rejects "
            "ordinary event collection");
    }
    else {
        try {
            args.options.role_filter_config =
                hng::load_role_filter_config(args.role_filter_config_path);
        }
        catch (const std::exception& error) {
            HNG_LOG_ERROR("failed to load role filter config {}: {}",
                          args.role_filter_config_path, error.what());
            return 1;
        }
    }

    const bool cli_enabled = kCliCompiled && !args.cli_disabled;

    // 构造装配层前阻塞信号，之后创建的线程继承该掩码
    sigset_t signals;
    if (!block_signals(signals, cli_enabled)) {
        return 1;
    }

    try {
        hng::Assembly assembly(std::move(args.options));
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
                         args.cli_options.unix_socket_path);
            RunCliServer(deps, args.cli_options);
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
