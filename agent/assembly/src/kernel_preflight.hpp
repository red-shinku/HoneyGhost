/**
 * @file kernel_preflight.hpp
 * @brief 探针加载前的目标内核能力检查
 * @details 装配层在启用采集时调用，检查内核版本、BTF 与 tracefs 是否满足
 *          eBPF 探针的加载要求；不满足时由调用方拒绝启动。
 */

#ifndef HNG_ASSEMBLY_KERNEL_PREFLIGHT_HPP_
#define HNG_ASSEMBLY_KERNEL_PREFLIGHT_HPP_

#include <string>
#include <string_view>
#include <vector>

namespace hng::detail {

/// @brief 探针要求的最低内核主版本
inline constexpr unsigned kMinKernelMajor = 5;

/// @brief 探针要求的最低内核次版本
/// @details 下限取 5.8：ring buffer map 自 5.8 起提供；探针使用的
///          bpf_probe_read_user_str（5.5）与 openat2 tracepoint（5.6）
///          均被该下限覆盖。
inline constexpr unsigned kMinKernelMinor = 8;

/// @brief 内核主、次版本号
struct KernelVersion {
    unsigned major = 0;
    unsigned minor = 0;
};

/**
 * @brief 从内核发行串解析主、次版本号
 * @param release 形如 "5.4.0-150-generic" 的发行串
 * @param version 输出：解析出的主、次版本号
 * @return 发行串以 "<十进制>.<十进制>" 开头为 true；否则 version 保持不变
 */
bool parse_kernel_release(std::string_view release,
                          KernelVersion& version) noexcept;

/**
 * @brief 判断内核主、次版本号是否达到探针的最低要求
 * @see kMinKernelMajor, kMinKernelMinor
 */
bool kernel_version_supported(KernelVersion version) noexcept;

/// @brief 能力检查读取的路径；测试可指向伪造的根目录
struct KernelPaths {
    /// CO-RE 重定位读取的目标内核 BTF
    std::string btf = "/sys/kernel/btf/vmlinux";
    /// tracefs 挂载点候选一
    std::string tracing = "/sys/kernel/tracing";
    /// tracefs 挂载点候选二
    std::string tracing_debugfs = "/sys/kernel/debug/tracing";
    /// 挂载表；用于识别非标准挂载点的 tracefs
    std::string mounts = "/proc/mounts";
};

/// @brief 目标内核能力检查结果
struct KernelSupport {
    /// 被检查的内核发行串
    std::string release;
    /// release 解析出的版本号；release_parsed 为 false 时为零值
    KernelVersion version;
    /// release 是否解析成功
    bool release_parsed = false;
    /// 版本是否达到 kMinKernelMajor.kMinKernelMinor
    bool version_ok = false;
    /// BTF 文件是否可读
    bool btf_ok = false;
    /// tracefs 是否已挂载（标准挂载点或挂载表中的 tracefs）
    bool tracefs_ok = false;
    /// 本次检查使用的路径
    KernelPaths paths;

    /// @brief 全部检查是否通过
    bool ok() const noexcept;

    /**
     * @brief 未通过项的说明，每项一句
     * @return 面向运维的失败原因；ok() 为 true 时为空
     */
    std::vector<std::string> failures() const;
};

/**
 * @brief 按给定发行串与路径执行检查
 * @param release 内核发行串
 * @param paths 检查使用的路径
 */
KernelSupport evaluate_kernel_support(const std::string& release,
                                      const KernelPaths& paths);

/**
 * @brief 读取当前内核发行串并执行检查
 * @param paths 检查使用的路径
 * @return 检查结果；uname 失败时 release 为空
 */
KernelSupport check_kernel_support(const KernelPaths& paths = KernelPaths{});

}  // namespace hng::detail

#endif  // HNG_ASSEMBLY_KERNEL_PREFLIGHT_HPP_
