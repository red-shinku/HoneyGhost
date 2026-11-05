/**
 * @file kernel_preflight.cc
 * @brief 目标内核能力检查的实现
 */
#include "agent/assembly/src/kernel_preflight.hpp"

#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <charconv>
#include <fstream>
#include <sstream>
#include <system_error>

namespace hng::detail {

namespace {

/// @brief 探针要求的最低内核版本，形如 "5.8"
std::string minimum_kernel_release()
{
    return std::to_string(kMinKernelMajor) + "." +
           std::to_string(kMinKernelMinor);
}

/**
 * @brief 从 offset 起解析一个十进制无符号整数
 * @param text 待解析文本
 * @param offset 输入输出：解析起点，成功后移到整数之后
 * @param value 输出：解析结果
 * @return 起点处存在可表示的十进制整数时为 true
 */
bool parse_unsigned(std::string_view text, std::size_t& offset, unsigned& value)
{
    if (offset >= text.size()) {
        return false;
    }
    const char* first = text.data() + offset;
    const char* last  = text.data() + text.size();
    const auto parsed = std::from_chars(first, last, value);
    if (parsed.ec != std::errc{} || parsed.ptr == first) {
        return false;
    }
    offset = static_cast<std::size_t>(parsed.ptr - text.data());
    return true;
}

/// @brief path 是否存在且为目录
bool is_directory(const std::string& path)
{
    struct stat info{};
    return ::stat(path.c_str(), &info) == 0 && S_ISDIR(info.st_mode);
}

/**
 * @brief tracefs 是否已挂载且暴露 events 目录
 * @details 先看标准挂载点；再按挂载表识别自定义挂载点，与 libbpf 的查找方式
 *          一致。挂载点中的空格转义不处理：tracefs 的实际挂载点不含空格。
 */
bool tracefs_available(const KernelPaths& paths)
{
    if (is_directory(paths.tracing + "/events") ||
        is_directory(paths.tracing_debugfs + "/events")) {
        return true;
    }
    std::ifstream table(paths.mounts);
    std::string line;
    while (std::getline(table, line)) {
        std::istringstream fields(line);
        std::string device;
        std::string mount_point;
        std::string filesystem;
        if (!(fields >> device >> mount_point >> filesystem)) {
            continue;
        }
        if (filesystem == "tracefs" && is_directory(mount_point + "/events")) {
            return true;
        }
    }
    return false;
}

}  // namespace

bool parse_kernel_release(std::string_view release,
                          KernelVersion& version) noexcept
{
    KernelVersion parsed;
    std::size_t offset = 0;
    if (!parse_unsigned(release, offset, parsed.major)) {
        return false;
    }
    if (offset >= release.size() || release[offset] != '.') {
        return false;
    }
    ++offset;
    if (!parse_unsigned(release, offset, parsed.minor)) {
        return false;
    }
    version = parsed;
    return true;
}

bool kernel_version_supported(KernelVersion version) noexcept
{
    if (version.major != kMinKernelMajor) {
        return version.major > kMinKernelMajor;
    }
    return version.minor >= kMinKernelMinor;
}

bool KernelSupport::ok() const noexcept
{
    return version_ok && btf_ok && tracefs_ok;
}

std::vector<std::string> KernelSupport::failures() const
{
    std::vector<std::string> reasons;
    const std::string minimum = minimum_kernel_release();
    if (release.empty()) {
        reasons.push_back(
            "cannot determine the running kernel release; "
            "kernel " +
            minimum + " or newer is required");
    }
    else if (!release_parsed) {
        reasons.push_back("cannot parse kernel release \"" + release +
                          "\"; kernel " + minimum + " or newer is required");
    }
    else if (!version_ok) {
        reasons.push_back(
            "kernel " + release + " is older than " + minimum +
            "; the probes require ring buffer maps (5.8), "
            "bpf_probe_read_user_str (5.5) and the openat2 tracepoint (5.6)");
    }
    if (!btf_ok) {
        reasons.push_back(paths.btf +
                          " is not readable; CO-RE relocation "
                          "requires the target kernel BTF "
                          "(CONFIG_DEBUG_INFO_BTF)");
    }
    if (!tracefs_ok) {
        reasons.push_back("tracefs is not mounted (no tracefs in " +
                          paths.mounts + "; " + paths.tracing + "/events and " +
                          paths.tracing_debugfs +
                          "/events are absent); tracepoint probes cannot "
                          "attach");
    }
    return reasons;
}

KernelSupport evaluate_kernel_support(const std::string& release,
                                      const KernelPaths& paths)
{
    KernelSupport support;
    support.release        = release;
    support.paths          = paths;
    support.release_parsed = parse_kernel_release(release, support.version);
    support.version_ok =
        support.release_parsed && kernel_version_supported(support.version);
    support.btf_ok     = ::access(paths.btf.c_str(), R_OK) == 0;
    support.tracefs_ok = tracefs_available(paths);
    return support;
}

KernelSupport check_kernel_support(const KernelPaths& paths)
{
    struct utsname name{};
    if (::uname(&name) != 0) {
        return evaluate_kernel_support(std::string{}, paths);
    }
    return evaluate_kernel_support(name.release, paths);
}

}  // namespace hng::detail
