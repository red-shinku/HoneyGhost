/**
 * @file test_log.cc
 * @brief 统一日志接口的测试
 * @details 把 stderr 重定向到临时文件后断言输出行、级别过滤、占位符、环境
 *          变量与 enabled()。
 * @author red_shinku
 * @date 2026.10.26
 */

#include "agent/util/include/log.hpp"

#include <unistd.h>

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <string>

namespace {

int g_fail            = 0;
int g_saved_stderr_fd = -1;

#define CHECK(cond, msg)                                                         \
    do {                                                                         \
        if (!(cond)) {                                                           \
            ++g_fail;                                                            \
            std::fprintf(stderr, "[FAIL] %s:%d  %s\n", __FILE__, __LINE__, msg); \
        }                                                                        \
    } while (0)

/// @brief 把 stderr 重定向到新建的临时文件
/// @return 临时文件的描述符；失败时为 -1 且 stderr 不变
int begin_capture()
{
    std::fflush(stderr);
    char path[]  = "/tmp/hng_log_test_XXXXXX";
    const int fd = ::mkstemp(path);
    if (fd < 0) {
        return -1;
    }
    ::unlink(path);
    g_saved_stderr_fd = ::dup(STDERR_FILENO);
    if (g_saved_stderr_fd < 0) {
        ::close(fd);
        return -1;
    }
    if (::dup2(fd, STDERR_FILENO) < 0) {
        ::close(g_saved_stderr_fd);
        g_saved_stderr_fd = -1;
        ::close(fd);
        return -1;
    }
    return fd;
}

/// @brief 恢复 stderr 并读回重定向期间的全部输出
/// @param fd begin_capture() 返回的描述符
/// @return 重定向期间的 stderr 内容
std::string end_capture(int fd)
{
    std::fflush(stderr);
    if (g_saved_stderr_fd >= 0) {
        ::dup2(g_saved_stderr_fd, STDERR_FILENO);
        ::close(g_saved_stderr_fd);
        g_saved_stderr_fd = -1;
    }
    if (fd < 0) {
        return std::string();
    }
    ::lseek(fd, 0, SEEK_SET);
    std::string text;
    char buffer[4096];
    ssize_t count = 0;
    while ((count = ::read(fd, buffer, sizeof(buffer))) > 0) {
        text.append(buffer, static_cast<size_t>(count));
    }
    ::close(fd);
    return text;
}

/// @brief 去掉末尾换行，便于断言行尾
std::string strip_trailing_newline(std::string text)
{
    while (!text.empty() && (text.back() == '\n' || text.back() == '\r')) {
        text.pop_back();
    }
    return text;
}

/// @brief 行首是否为 "[YYYY-MM-DD HH:MM:SS.mmm]" 形式的时间戳
bool starts_with_timestamp(const std::string& line)
{
    if (line.size() < 25 || line[0] != '[') {
        return false;
    }
    const int digit_positions[] = {1,  2,  3,  4,  6,  7,  9,  10, 12,
                                   13, 15, 16, 18, 19, 21, 22, 23};
    for (const int position : digit_positions) {
        if (!std::isdigit(static_cast<unsigned char>(line[position]))) {
            return false;
        }
    }
    return line[5] == '-' && line[8] == '-' && line[11] == ' ' &&
           line[14] == ':' && line[17] == ':' && line[20] == '.' &&
           line[24] == ']';
}

/// @brief 未设置环境变量时按 INFO 输出
void test_default_info()
{
    ::unsetenv("HNG_LOG_LEVEL");
    hng::log::init();
    CHECK(hng::log::level() == hng::log::Level::INFO, "默认级别应为 info");

    const int fd = begin_capture();
    CHECK(fd >= 0, "无法重定向 stderr");
    HNG_LOG_INFO("info visible");
    HNG_LOG_DEBUG("debug hidden");
    const std::string out = strip_trailing_newline(end_capture(fd));

    CHECK(starts_with_timestamp(out), "info 行缺少毫秒时间戳");
    CHECK(out.find("[info] [test] info visible") != std::string::npos,
          "info 行缺少级别或模块名");
    CHECK(out.find("debug hidden") == std::string::npos,
          "info 级别不应输出 debug");
}

/// @brief WARN 级别只输出 warn/error，且行尾带位置
void test_warn_level_and_position()
{
    hng::log::set_level(hng::log::Level::WARN);
    const int fd = begin_capture();
    HNG_LOG_INFO("info hidden");
    const int warn_line = __LINE__ + 1;
    HNG_LOG_WARN("warn visible");
    HNG_LOG_DEBUG("debug hidden");
    const std::string out = strip_trailing_newline(end_capture(fd));

    CHECK(out.find("info hidden") == std::string::npos, "warn 级别不应输出 info");
    CHECK(out.find("debug hidden") == std::string::npos,
          "warn 级别不应输出 debug");
    CHECK(out.find("[warning] [test] warn visible") != std::string::npos,
          "warn 行缺少级别或模块名");
    const std::string suffix = " (test_log.cc:" + std::to_string(warn_line) + ")";
    CHECK(out.size() >= suffix.size() &&
              out.compare(out.size() - suffix.size(), suffix.size(), suffix) == 0,
          "warn 行尾缺少 basename:行号");
}

/// @brief 占位符按 fmt 规则格式化
void test_placeholders()
{
    hng::log::set_level(hng::log::Level::INFO);
    const int fd = begin_capture();
    HNG_LOG_WARN("a={} b={}", 1, "x");
    const std::string out = strip_trailing_newline(end_capture(fd));

    CHECK(out.find("a=1 b=x") != std::string::npos, "占位符未被格式化");
}

/// @brief HNG_LOG_LEVEL 生效并覆盖默认级别
void test_env_level()
{
    ::setenv("HNG_LOG_LEVEL", "error", 1);
    hng::log::init();
    CHECK(hng::log::level() == hng::log::Level::ERROR,
          "HNG_LOG_LEVEL=error 未生效");

    const int fd = begin_capture();
    HNG_LOG_INFO("info hidden");
    HNG_LOG_ERROR("error visible");
    const std::string out = strip_trailing_newline(end_capture(fd));
    ::unsetenv("HNG_LOG_LEVEL");

    CHECK(out.find("info hidden") == std::string::npos,
          "error 级别不应输出 info");
    CHECK(out.find("error visible") != std::string::npos,
          "error 级别应输出 error");
}

/// @brief 非法环境变量回落默认级别并告警
void test_invalid_env_level()
{
    ::setenv("HNG_LOG_LEVEL", "loud", 1);
    const int fd = begin_capture();
    hng::log::init(hng::log::Level::INFO);
    const std::string out = strip_trailing_newline(end_capture(fd));
    ::unsetenv("HNG_LOG_LEVEL");

    CHECK(hng::log::level() == hng::log::Level::INFO, "非法取值应回落默认级别");
    CHECK(out.find("[warning] ") != std::string::npos, "非法取值应写一条 warn");
}

/// @brief enabled() 与当前级别一致
void test_enabled()
{
    hng::log::set_level(hng::log::Level::WARN);
    CHECK(!hng::log::enabled(hng::log::Level::DEBUG), "WARN 级别下 debug 应禁用");
    CHECK(!hng::log::enabled(hng::log::Level::INFO), "WARN 级别下 info 应禁用");
    CHECK(hng::log::enabled(hng::log::Level::WARN), "WARN 级别下 warn 应启用");
    CHECK(hng::log::enabled(hng::log::Level::ERROR), "WARN 级别下 error 应启用");
}

/// @brief DEBUG 级别输出 debug 行
void test_debug_level()
{
    hng::log::set_level(hng::log::Level::DEBUG);
    const int fd = begin_capture();
    HNG_LOG_DEBUG("debug visible");
    const std::string out = strip_trailing_newline(end_capture(fd));

    CHECK(out.find("[debug] [test] debug visible") != std::string::npos,
          "debug 级别应输出 debug 行");
}

}  // namespace

int main()
{
    test_default_info();
    test_warn_level_and_position();
    test_placeholders();
    test_env_level();
    test_invalid_env_level();
    test_enabled();
    test_debug_level();

    hng::log::set_level(hng::log::Level::INFO);
    if (g_fail != 0) {
        std::fprintf(stderr, "TOTAL FAILURES: %d\n", g_fail);
        return 1;
    }
    std::printf("ALL PASS\n");
    return 0;
}
