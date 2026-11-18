/**
 * @file tracefs.cc
 * @brief tracefs 挂载根与 tracepoint 存在性探测的实现
 */
#include "agent/util/include/tracefs.hpp"

#include <sys/stat.h>
#include <unistd.h>

#include <fstream>
#include <sstream>
#include <string>
#include <system_error>

namespace hng::detail {

namespace {

/// @brief 默认 tracefs 挂载点候选一
constexpr const char* kTracefsRoot        = "/sys/kernel/tracing";

/// @brief 默认 tracefs 挂载点候选二
constexpr const char* kDebugfsTracefsRoot = "/sys/kernel/debug/tracing";

/// @brief path 是否存在、为目录且可读可进入
bool is_accessible_directory(const std::filesystem::path& path)
{
    std::error_code error;
    if (path.empty() || !std::filesystem::is_directory(path, error)) {
        return false;
    }
    return ::access(path.c_str(), R_OK | X_OK) == 0;
}

/// @brief root 是否暴露可访问的 events 目录
bool has_events_dir(const std::filesystem::path& root)
{
    return is_accessible_directory(root / "events");
}

/**
 * @brief 在挂载表中查找首个带 events 目录的 tracefs 挂载点
 * @param proc_mounts 挂载表路径
 * @return 挂载点；没有可用项时为空 path
 */
std::filesystem::path tracefs_from_mounts(
    const std::filesystem::path& proc_mounts)
{
    std::ifstream table(proc_mounts);
    std::string line;
    while (std::getline(table, line)) {
        std::istringstream fields(line);
        std::string device;
        std::string mount_point;
        std::string filesystem;
        if (!(fields >> device >> mount_point >> filesystem)) {
            continue;
        }
        if (filesystem != "tracefs") {
            continue;
        }
        const std::filesystem::path root(mount_point);
        if (has_events_dir(root)) {
            return root;
        }
    }
    return {};
}

}  // namespace

std::filesystem::path find_tracefs_root(const std::filesystem::path& proc_mounts)
{
    return find_tracefs_root(kTracefsRoot, kDebugfsTracefsRoot, proc_mounts);
}

std::filesystem::path find_tracefs_root(
    const std::filesystem::path& tracing,
    const std::filesystem::path& tracing_debugfs,
    const std::filesystem::path& proc_mounts)
{
    if (has_events_dir(tracing)) {
        return tracing;
    }
    if (has_events_dir(tracing_debugfs)) {
        return tracing_debugfs;
    }
    return tracefs_from_mounts(proc_mounts);
}

bool tracepoint_present(const std::filesystem::path& root, std::string_view group,
                        std::string_view event)
{
    if (root.empty() || group.empty() || event.empty()) {
        return false;
    }
    const std::filesystem::path id =
        root / "events" / std::string(group) / std::string(event) / "id";
    struct stat info{};
    if (::stat(id.c_str(), &info) != 0 || !S_ISREG(info.st_mode)) {
        return false;
    }
    return ::access(id.c_str(), R_OK) == 0;
}

}  // namespace hng::detail
