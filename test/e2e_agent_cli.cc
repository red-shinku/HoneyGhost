/**
 * @file e2e_agent_cli.cc
 * @brief 真实节点代理的端到端测试
 * @details
 * 以子进程启动 hng_agent，父进程按进程级契约断言：
 *  - CLI 模式：经 Unix socket 查询空系统的控制面，RPC 成功且不带数据；
 *    SIGTERM 后在期限内以 0 退出；
 *  - --no-cli 模式：日志出现 "agent started" 即就绪，SIGTERM 后以 0 退出。
 * @note 不依赖测试框架；需要 /proc 与 /tmp，无特权要求。
 * @author red_shinku
 * @date 2026.10.28
 */

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <string>
#include <thread>
#include <vector>

#include <grpcpp/grpcpp.h>

#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <proto/cli_service.grpc.pb.h>

namespace {

int g_fail = 0;

#define CHECK(cond, msg)                                                         \
    do {                                                                         \
        if (!(cond)) {                                                           \
            ++g_fail;                                                            \
            std::fprintf(stderr, "[FAIL] %s:%d  %s\n", __FILE__, __LINE__, msg); \
        }                                                                        \
    } while (false)

using Clock = std::chrono::steady_clock;

constexpr std::chrono::seconds kReadyTimeout{20};
constexpr std::chrono::seconds kExitTimeout{20};
constexpr std::chrono::seconds kRpcTimeout{5};
constexpr std::chrono::milliseconds kPollInterval{20};

/// 就绪日志：main 在装配层启动完成后写出
constexpr char kAgentStarted[]       = "agent started";

/// 空系统下不存在的 pid 与 contextID
constexpr uint32_t kUnknownPid       = 999999;
constexpr uint32_t kUnknownContextID = 999999;

/// @brief 单个用例的 socket 与日志路径
struct Paths {
    std::string socket;
    std::string log;
};

/// @brief 生成 /tmp 下带进程号与后缀的 socket 与日志路径
Paths MakePaths(const char* suffix)
{
    const std::string prefix =
        "/tmp/hng-agent-e2e-" + std::to_string(::getpid()) + suffix;
    return Paths{prefix + ".sock", prefix + ".log"};
}

/// @brief gRPC 的 deadline 走 system_clock，项目内的计时走 steady_clock
void SetDeadline(grpc::ClientContext& context, std::chrono::seconds timeout)
{
    context.set_deadline(std::chrono::system_clock::now() + timeout);
}

/// @brief 轮询到谓词为真或超时
bool WaitFor(const std::function<bool()>& pred, std::chrono::milliseconds timeout)
{
    const auto deadline = Clock::now() + timeout;
    while (Clock::now() < deadline) {
        if (pred()) {
            return true;
        }
        std::this_thread::sleep_for(kPollInterval);
    }
    return pred();
}

/// @brief 在期限内回收子进程；超时返回 false 且不回收
bool WaitForExit(pid_t child, std::chrono::milliseconds timeout, int* code)
{
    const auto deadline = Clock::now() + timeout;
    for (;;) {
        int status         = 0;
        const pid_t reaped = ::waitpid(child, &status, WNOHANG);
        if (reaped == child) {
            *code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
            return true;
        }
        if (reaped < 0 || Clock::now() >= deadline) {
            return false;
        }
        std::this_thread::sleep_for(kPollInterval);
    }
}

/// @brief 打印日志文件末尾，用于启动或停机失败排查
void PrintLogTail(const std::string& path)
{
    std::FILE* file = std::fopen(path.c_str(), "r");
    if (file == nullptr) {
        std::fprintf(stderr, "[INFO] no agent log at %s\n", path.c_str());
        return;
    }

    constexpr long kTailBytes = 4096;
    if (std::fseek(file, 0, SEEK_END) == 0) {
        const long size  = std::ftell(file);
        const long start = size > kTailBytes ? size - kTailBytes : 0;
        (void)std::fseek(file, start, SEEK_SET);
    }

    std::fprintf(stderr, "----- agent log tail: %s -----\n", path.c_str());
    char buffer[512];
    size_t read = 0;
    while ((read = std::fread(buffer, 1, sizeof(buffer), file)) > 0) {
        (void)std::fwrite(buffer, 1, read, stderr);
    }
    std::fprintf(stderr, "\n----- end of agent log -----\n");
    std::fclose(file);
}

/// @brief 日志文件是否已包含指定子串
bool LogContains(const std::string& path, const char* needle)
{
    std::FILE* file = std::fopen(path.c_str(), "r");
    if (file == nullptr) {
        return false;
    }

    std::string text;
    char buffer[4096];
    size_t read = 0;
    while ((read = std::fread(buffer, 1, sizeof(buffer), file)) > 0) {
        text.append(buffer, read);
    }
    std::fclose(file);
    return text.find(needle) != std::string::npos;
}

/**
 * @brief 以子进程启动 hng_agent，stdout/stderr 重定向到日志文件
 * @param arguments 可执行文件路径与其后的参数
 * @param log_path 子进程日志文件；父进程轮询、读取该文件
 * @return 子进程 pid；fork 失败返回 -1
 * @note 用文件而非管道：子进程可能长时间运行，父进程按需读取不阻塞
 */
pid_t StartAgent(const std::vector<std::string>& arguments,
                 const std::string& log_path)
{
    std::vector<char*> argv;
    argv.reserve(arguments.size() + 1);
    for (const std::string& argument : arguments) {
        argv.push_back(const_cast<char*>(argument.c_str()));
    }
    argv.push_back(nullptr);

    const pid_t child = ::fork();
    if (child < 0) {
        return -1;
    }
    if (child > 0) {
        return child;
    }

    const int log_fd =
        ::open(log_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (log_fd >= 0) {
        (void)::dup2(log_fd, STDOUT_FILENO);
        (void)::dup2(log_fd, STDERR_FILENO);
        ::close(log_fd);
    }
    ::execv(argv[0], argv.data());
    ::_exit(127);
}

/// @brief 立即终止子进程并回收，避免僵尸进程与残留 socket
void KillAndReap(pid_t child)
{
    ::kill(child, SIGKILL);
    (void)::waitpid(child, nullptr, 0);
}

/// @brief 等到 CLI 服务端能应答 RM_GetRoles
bool WaitForServer(hng::clisv::RoleManagerService::Stub& stub)
{
    return WaitFor(
        [&stub] {
            grpc::ClientContext context;
            SetDeadline(context, std::chrono::seconds{1});
            hng::clisv::RM_GetRolesRequest request;
            request.set_showoption(hng::clisv::RM_SHOW_ALL);
            hng::clisv::RM_GetRolesResponse response;
            return stub.GetRoles(&context, request, &response).ok();
        },
        kReadyTimeout);
}

/// @brief 空系统的查询面：全部返回成功且不带数据
void RunQueryChecks(hng::clisv::RoleManagerService::Stub& role,
                    hng::clisv::ContextManagerService::Stub& context_service)
{
    {
        grpc::ClientContext context;
        SetDeadline(context, kRpcTimeout);
        hng::clisv::RM_GetRolesRequest request;
        request.set_showoption(hng::clisv::RM_SHOW_ALL);
        hng::clisv::RM_GetRolesResponse response;
        const grpc::Status status = role.GetRoles(&context, request, &response);
        CHECK(status.ok(), "GetRoles should succeed");
        CHECK(response.r_size() == 0, "GetRoles should be empty");
    }

    {
        grpc::ClientContext context;
        SetDeadline(context, kRpcTimeout);
        hng::clisv::RM_WhichRoleRequest request;
        request.set_pid(kUnknownPid);
        hng::clisv::RM_WhichRoleResponse response;
        const grpc::Status status = role.WhichRole(&context, request, &response);
        CHECK(status.ok(), "WhichRole should succeed");
        CHECK(!response.has_roleid(),
              "WhichRole should not set roleID for an unknown pid");
    }

    {
        grpc::ClientContext context;
        SetDeadline(context, kRpcTimeout);
        hng::clisv::CM_GetProcessSetRequest request;
        request.set_contextid(kUnknownContextID);
        hng::clisv::CM_GetProcessSetResponse response;
        const grpc::Status status =
            context_service.GetProcessSet(&context, request, &response);
        CHECK(status.ok(), "CM GetProcessSet should succeed");
        CHECK(response.root_pid() == 0,
              "CM GetProcessSet should leave root_pid at 0");
        CHECK(!response.has_pids(),
              "CM GetProcessSet should not set pids for an unknown context");
    }
}

/// @brief 成功时删除日志；失败时保留日志并打印
void FinishCase(const Paths& paths, int failures_before, bool printed)
{
    if (g_fail == failures_before) {
        ::unlink(paths.log.c_str());
        return;
    }
    if (!printed) {
        PrintLogTail(paths.log);
    }
    std::fprintf(stderr, "[INFO] agent log kept at %s\n", paths.log.c_str());
}

/// @brief 用例 A：CLI 模式查询空系统，SIGTERM 后正常退出
void RunCliCase(const std::string& executable)
{
    const int failures_before = g_fail;
    const Paths paths         = MakePaths("");

    ::unlink(paths.socket.c_str());
    ::unlink(paths.log.c_str());

    const pid_t child =
        StartAgent({executable, "--no-collect", "--no-systemd", "--no-containerd",
                    "--cli-socket", paths.socket},
                   paths.log);
    if (child < 0) {
        CHECK(false, "hng_agent should be spawned");
        FinishCase(paths, failures_before, false);
        return;
    }

    const auto channel   = grpc::CreateChannel("unix:" + paths.socket,
                                               grpc::InsecureChannelCredentials());
    auto role            = hng::clisv::RoleManagerService::NewStub(channel);
    auto context_service = hng::clisv::ContextManagerService::NewStub(channel);

    bool log_printed     = false;
    if (WaitForServer(*role)) {
        RunQueryChecks(*role, *context_service);

        ::kill(child, SIGTERM);
        int exit_code = -1;
        if (WaitForExit(child, kExitTimeout, &exit_code)) {
            CHECK(exit_code == 0, "hng_agent should exit with code 0");
        }
        else {
            CHECK(false, "hng_agent should exit within 20s after SIGTERM");
            KillAndReap(child);
        }
    }
    else {
        CHECK(false, "cli server should become ready within 20s");
        PrintLogTail(paths.log);
        log_printed = true;
        KillAndReap(child);
    }

    ::unlink(paths.socket.c_str());
    FinishCase(paths, failures_before, log_printed);
}

/// @brief 用例 B：--no-cli 模式的就绪日志与信号停机
void RunNoCliCase(const std::string& executable)
{
    const int failures_before = g_fail;
    const Paths paths         = MakePaths("-nocli");

    ::unlink(paths.socket.c_str());
    ::unlink(paths.log.c_str());

    const pid_t child = StartAgent({executable, "--no-collect", "--no-systemd",
                                    "--no-containerd", "--no-cli"},
                                   paths.log);
    if (child < 0) {
        CHECK(false, "hng_agent should be spawned");
        FinishCase(paths, failures_before, false);
        return;
    }

    bool log_printed = false;
    const bool started =
        WaitFor([&paths] { return LogContains(paths.log, kAgentStarted); },
                kReadyTimeout);
    if (started) {
        ::kill(child, SIGTERM);
        int exit_code = -1;
        if (WaitForExit(child, kExitTimeout, &exit_code)) {
            CHECK(exit_code == 0, "hng_agent should exit with code 0");
        }
        else {
            CHECK(false, "hng_agent should exit within 20s after SIGTERM");
            KillAndReap(child);
        }
    }
    else {
        CHECK(false, "agent log should show readiness within 20s");
        PrintLogTail(paths.log);
        log_printed = true;
        KillAndReap(child);
    }

    ::unlink(paths.socket.c_str());
    FinishCase(paths, failures_before, log_printed);
}

}  // namespace

/**
 * @brief 依次运行 CLI 模式与 --no-cli 模式两个用例
 * @param argc 参数个数
 * @param argv argv[1] 为 hng_agent 可执行文件路径
 * @return 全部断言通过为 0，否则为 1
 */
int main(int argc, char** argv)
{
    if (argc < 2 || argv[1][0] == '\0') {
        std::fprintf(stderr, "usage: e2e_agent_cli <path-to-hng_agent>\n");
        return 1;
    }
    const std::string executable = argv[1];
    if (::access(executable.c_str(), X_OK) != 0) {
        std::fprintf(stderr, "hng_agent is not executable: %s\n",
                     executable.c_str());
        return 1;
    }

    RunCliCase(executable);
    RunNoCliCase(executable);

    if (g_fail) {
        std::fprintf(stderr, "TOTAL FAILURES: %d\n", g_fail);
        return 1;
    }
    std::printf("ALL PASS\n");
    return 0;
}
