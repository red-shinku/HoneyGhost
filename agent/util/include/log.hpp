/**
 * @file log.hpp
 * @brief 统一日志接口
 * @details 级别只有 debug/info/warn/error 四档，运行期过滤；输出只到 stderr，
 *          行格式为 "[时间] [级别] [模块] 消息"，warn/error 在消息末尾追加
 *          " (文件:行号)"。日志正文用英文，公共头只依赖 fmt。
 * @author red_shinku
 * @date 2026.10.26
 */

#ifndef HNG_UTIL_LOG_HPP_
#define HNG_UTIL_LOG_HPP_

#include <cstdint>
#include <string>
#include <string_view>
#include <utility>

#include <fmt/format.h>

#ifndef HNG_LOG_TAG
#define HNG_LOG_TAG "hng"
#endif

namespace hng {
namespace log {

/**
 * @brief 日志级别
 * @details 数值越大越严重；低于当前级别的日志被丢弃。
 */
enum class Level : uint8_t {
    DEBUG,  ///< 调试现场
    INFO,   ///< 正常进度
    WARN,   ///< 降级但可继续
    ERROR   ///< 失败
};

/**
 * @brief 初始化日志后端并设定级别
 * @param default_level 未设置 HNG_LOG_LEVEL 或取值非法时使用的级别
 * @details 读取环境变量 HNG_LOG_LEVEL，不区分大小写，接受
 *          debug/info/warn/warning/error；取值非法时回落到 default_level，
 *          并在新级别允许时写一条 warn。
 * @note 可重复调用，已有 sink 不重建。
 * @note 若从未调用本函数，首次写日志时惰性建立 stderr sink，并按
 *       HNG_LOG_LEVEL（未设置时 INFO）设定级别。
 */
void init(Level default_level = Level::INFO);

/**
 * @brief 运行期设定级别
 * @param level 新级别；低于该级别的日志被丢弃
 * @note 可从任意线程调用；已建立的 logger 同步更新
 */
void set_level(Level level) noexcept;

/**
 * @brief 当前级别
 * @return 运行期过滤使用的级别
 * @note 可从任意线程调用
 */
Level level() noexcept;

/**
 * @brief 判断某级别是否会被输出
 * @param level 待判断的级别
 * @return 级别不低于当前级别时为 true
 * @note 热路径：单次原子读，不加锁；可从任意线程调用
 */
bool enabled(Level level) noexcept;

/**
 * @brief 写一条日志
 * @param level 级别
 * @param tag 模块名，写入 "[tag] " 前缀
 * @param file 源文件路径；仅 warn/error 追加其 basename 与行号
 * @param line 源文件行号
 * @param message 已格式化的消息
 * @note 由 HNG_LOG_* 宏调用；可从任意线程调用
 */
void write(Level level, const char* tag, const char* file, int line,
           std::string_view message);

namespace detail {

/**
 * @brief 按 fmt 规则格式化日志消息
 * @tparam Args 占位符实参类型
 * @param fmt_str 字面量格式串
 * @param args 占位符实参
 * @return 格式化后的消息
 * @note 只支持字面量格式串，占位符与实参在编译期核对
 */
template <typename... Args>
std::string format(fmt::format_string<Args...> fmt_str, Args&&... args)
{
    return fmt::format(fmt_str, std::forward<Args>(args)...);
}

/// @brief 当前编译单元的日志模块名；由 HNG_LOG_TAG 指定，缺省 "hng"
inline constexpr const char* tag = HNG_LOG_TAG;

}  // namespace detail

/// @brief 写一条 debug 日志；参数为 fmt 字面量格式串与实参
#define HNG_LOG_DEBUG(...)                                                       \
    do {                                                                         \
        if (::hng::log::enabled(::hng::log::Level::DEBUG)) {                     \
            ::hng::log::write(::hng::log::Level::DEBUG, ::hng::log::detail::tag, \
                              __FILE__, __LINE__,                                \
                              ::hng::log::detail::format(__VA_ARGS__));          \
        }                                                                        \
    } while (false)

/// @brief 写一条 info 日志；参数为 fmt 字面量格式串与实参
#define HNG_LOG_INFO(...)                                                       \
    do {                                                                        \
        if (::hng::log::enabled(::hng::log::Level::INFO)) {                     \
            ::hng::log::write(::hng::log::Level::INFO, ::hng::log::detail::tag, \
                              __FILE__, __LINE__,                               \
                              ::hng::log::detail::format(__VA_ARGS__));         \
        }                                                                       \
    } while (false)

/// @brief 写一条 warn 日志；参数为 fmt 字面量格式串与实参
#define HNG_LOG_WARN(...)                                                       \
    do {                                                                        \
        if (::hng::log::enabled(::hng::log::Level::WARN)) {                     \
            ::hng::log::write(::hng::log::Level::WARN, ::hng::log::detail::tag, \
                              __FILE__, __LINE__,                               \
                              ::hng::log::detail::format(__VA_ARGS__));         \
        }                                                                       \
    } while (false)

/// @brief 写一条 error 日志；参数为 fmt 字面量格式串与实参
#define HNG_LOG_ERROR(...)                                                       \
    do {                                                                         \
        if (::hng::log::enabled(::hng::log::Level::ERROR)) {                     \
            ::hng::log::write(::hng::log::Level::ERROR, ::hng::log::detail::tag, \
                              __FILE__, __LINE__,                                \
                              ::hng::log::detail::format(__VA_ARGS__));          \
        }                                                                        \
    } while (false)

}  // namespace log
}  // namespace hng

#endif  // HNG_UTIL_LOG_HPP_
