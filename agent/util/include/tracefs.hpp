/**
 * @file tracefs.hpp
 * @brief tracefs 挂载根与 tracepoint 存在性探测
 * @details 结果不缓存：每次调用都重新访问文件系统，挂载变化按调用时刻生效。
 */

#ifndef HNG_UTIL_TRACEFS_HPP_
#define HNG_UTIL_TRACEFS_HPP_

#include <filesystem>
#include <string_view>

namespace hng::detail {

/**
 * @brief 解析 tracefs 挂载根
 * @param proc_mounts 挂载表路径
 * @return 按 /sys/kernel/tracing、/sys/kernel/debug/tracing、挂载表中
 *         filesystem 为 tracefs 的挂载点顺序，首个带可访问 events 目录的根；
 *         都不满足时返回空 path
 * @note 挂载表中的空格转义不处理：tracefs 的实际挂载点不含空格。
 */
std::filesystem::path find_tracefs_root(
    const std::filesystem::path& proc_mounts = "/proc/mounts");

/**
 * @brief 在给定标准候选下解析 tracefs 挂载根
 * @param tracing 标准挂载点候选一
 * @param tracing_debugfs 标准挂载点候选二
 * @param proc_mounts 挂载表路径
 * @return 候选一、候选二、挂载表中 tracefs 顺序下首个带可访问 events
 *         目录的根；都不满足时返回空 path
 * @note 供注入自定义挂载点的调用方使用；候选顺序与默认重载一致。
 * @see find_tracefs_root
 */
std::filesystem::path find_tracefs_root(
    const std::filesystem::path& tracing,
    const std::filesystem::path& tracing_debugfs,
    const std::filesystem::path& proc_mounts);

/**
 * @brief 判断 tracepoint 是否存在
 * @param root tracefs 根
 * @param group tracepoint 组名
 * @param event tracepoint 事件名
 * @return <root>/events/<group>/<event>/id 是可读普通文件时为 true；
 *         root 为空、组名或事件名为空、路径不可读时均为 false
 */
bool tracepoint_present(const std::filesystem::path& root, std::string_view group,
                        std::string_view event);

}  // namespace hng::detail

#endif  // HNG_UTIL_TRACEFS_HPP_
