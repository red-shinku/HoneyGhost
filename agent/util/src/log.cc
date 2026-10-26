/**
 * @file log.cc
 * @brief 统一日志接口的 spdlog 后端实现
 * @details 本文件是唯一包含 spdlog 头的编译单元；sink 为 stderr，级别用原子
 *          变量保存，模块名由调用方传入。
 * @author red_shinku
 * @date 2026.10.26
 */

#include "agent/util/include/log.hpp"

#include <spdlog/sinks/stdout_sinks.h>
#include <spdlog/spdlog.h>

#include <atomic>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>

namespace hng {
namespace log {

namespace {

/// @brief 行格式：毫秒时间戳、级别、消息
constexpr const char* kPattern = "[%Y-%m-%d %H:%M:%S.%e] [%l] %v";

std::atomic<int> g_level{static_cast<int>(Level::INFO)};
std::mutex g_create_mutex;
/// @brief 惰性建立的 logger；只经 std::atomic_load / std::atomic_store 访问
std::shared_ptr<spdlog::logger> g_logger;

spdlog::level::level_enum to_spdlog(Level level) noexcept
{
    switch (level) {
        case Level::DEBUG:
            return spdlog::level::debug;
        case Level::INFO:
            return spdlog::level::info;
        case Level::WARN:
            return spdlog::level::warn;
        case Level::ERROR:
            return spdlog::level::err;
    }
    return spdlog::level::info;
}

const char* level_name(Level level) noexcept
{
    switch (level) {
        case Level::DEBUG:
            return "debug";
        case Level::INFO:
            return "info";
        case Level::WARN:
            return "warn";
        case Level::ERROR:
            return "error";
    }
    return "info";
}

bool equals_ignore_case(std::string_view lhs, std::string_view rhs) noexcept
{
    if (lhs.size() != rhs.size()) {
        return false;
    }
    for (size_t i = 0; i < lhs.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(lhs[i])) !=
            std::tolower(static_cast<unsigned char>(rhs[i]))) {
            return false;
        }
    }
    return true;
}

bool parse_level(const char* text, Level& out) noexcept
{
    const std::string_view value{text};
    if (equals_ignore_case(value, "debug")) {
        out = Level::DEBUG;
        return true;
    }
    if (equals_ignore_case(value, "info")) {
        out = Level::INFO;
        return true;
    }
    if (equals_ignore_case(value, "warn") ||
        equals_ignore_case(value, "warning")) {
        out = Level::WARN;
        return true;
    }
    if (equals_ignore_case(value, "error")) {
        out = Level::ERROR;
        return true;
    }
    return false;
}

/// @brief 环境变量 HNG_LOG_LEVEL 的解析结果
struct ResolvedLevel {
    Level level = Level::INFO;  ///< 实际采用的级别
    std::string raw;            ///< 环境变量的原始取值；未设置时为空
    bool invalid = false;       ///< 取值存在但无法识别
};

/// @brief 按环境变量解析级别
/// @param fallback 环境变量未设置或为空时使用的级别
/// @return 解析结果；取值非法时级别为 fallback 并置 invalid
ResolvedLevel resolve_level(Level fallback)
{
    ResolvedLevel result;
    result.level    = fallback;
    const char* env = std::getenv("HNG_LOG_LEVEL");
    if (env == nullptr) {
        return result;
    }
    result.raw   = env;
    Level parsed = fallback;
    if (parse_level(env, parsed)) {
        result.level = parsed;
    }
    else {
        result.invalid = true;
    }
    return result;
}

std::shared_ptr<spdlog::logger> make_logger()
{
    auto sink   = std::make_shared<spdlog::sinks::stderr_sink_mt>();
    auto logger = std::make_shared<spdlog::logger>(detail::tag, std::move(sink));
    logger->set_pattern(kPattern);
    logger->set_level(
        to_spdlog(static_cast<Level>(g_level.load(std::memory_order_relaxed))));
    return logger;
}

std::shared_ptr<spdlog::logger> logger_instance()
{
    auto logger = std::atomic_load_explicit(&g_logger, std::memory_order_acquire);
    if (logger != nullptr) {
        return logger;
    }

    bool invalid = false;
    std::string raw;
    {
        std::lock_guard<std::mutex> lock(g_create_mutex);
        logger = std::atomic_load_explicit(&g_logger, std::memory_order_relaxed);
        if (logger == nullptr) {
            const ResolvedLevel resolved = resolve_level(Level::INFO);
            invalid                      = resolved.invalid;
            raw                          = resolved.raw;
            g_level.store(static_cast<int>(resolved.level),
                          std::memory_order_relaxed);
            logger = make_logger();
            std::atomic_store_explicit(&g_logger, logger,
                                       std::memory_order_release);
        }
    }
    if (invalid) {
        HNG_LOG_WARN("unrecognized HNG_LOG_LEVEL=\"{}\"; using {}", raw,
                     level_name(level()));
    }
    return logger;
}

const char* file_basename(const char* path) noexcept
{
    if (path == nullptr) {
        return "";
    }
    const char* slash = std::strrchr(path, '/');
    return slash != nullptr ? slash + 1 : path;
}

}  // namespace

void init(Level default_level)
{
    const ResolvedLevel resolved = resolve_level(default_level);
    set_level(resolved.level);
    if (resolved.invalid) {
        HNG_LOG_WARN("unrecognized HNG_LOG_LEVEL=\"{}\"; using {}", resolved.raw,
                     level_name(resolved.level));
    }
}

void set_level(Level level) noexcept
{
    g_level.store(static_cast<int>(level), std::memory_order_relaxed);
    const auto logger =
        std::atomic_load_explicit(&g_logger, std::memory_order_acquire);
    if (logger != nullptr) {
        logger->set_level(to_spdlog(level));
    }
}

Level level() noexcept
{
    return static_cast<Level>(g_level.load(std::memory_order_relaxed));
}

bool enabled(Level level) noexcept
{
    return static_cast<int>(level) >= g_level.load(std::memory_order_relaxed);
}

void write(Level level, const char* tag, const char* file, int line,
           std::string_view message)
{
    const auto logger = logger_instance();

    std::string text;
    text.reserve(message.size() + 32);
    text.push_back('[');
    text.append(tag);
    text.append("] ");
    text.append(message);
    if (level == Level::WARN || level == Level::ERROR) {
        text.append(" (");
        text.append(file_basename(file));
        text.push_back(':');
        text.append(std::to_string(line));
        text.push_back(')');
    }

    logger->log(to_spdlog(level),
                spdlog::string_view_t{text.data(), text.size()});
}

}  // namespace log
}  // namespace hng
