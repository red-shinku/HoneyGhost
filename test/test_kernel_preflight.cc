/**
 * @file test_kernel_preflight.cc
 * @brief 探针加载前内核预检的单元测试
 * @details 覆盖内核发行串解析、版本下限，以及 BTF 与 tracefs 探测；路径
 *          指向临时伪造根目录，不需要 eBPF 权限。
 */

#include "agent/assembly/src/kernel_preflight.hpp"

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>
#include <vector>

namespace {

int g_fail = 0;

#define CHECK(cond, msg)                                                       \
    do {                                                                       \
        if (!(cond)) {                                                         \
            ++g_fail;                                                          \
            std::fprintf(stderr, "[FAIL] %s:%d  %s\n", __FILE__, __LINE__,     \
                         msg);                                                 \
        }                                                                      \
    } while (0)

/// @brief 由 mkdtemp 独占创建的临时目录，析构时整体删除
struct TempRoot {
    std::filesystem::path path;

    TempRoot()
    {
        std::string pattern = (std::filesystem::temp_directory_path() /
                              "hng_kernel_preflight_XXXXXX")
                                  .string();
        if (::mkdtemp(pattern.data()) != nullptr) {
            path = pattern;
        }
    }

    ~TempRoot()
    {
        if (!path.empty()) {
            std::error_code error;
            std::filesystem::remove_all(path, error);
        }
    }
};

/// @brief 写入一个文件
void write_file(const std::filesystem::path& path, const std::string& content)
{
    std::ofstream file(path);
    file << content;
}

/// @brief 在 root 下创建一个内容无关的 BTF 文件
void make_btf(const std::filesystem::path& root)
{
    write_file(root / "btf", "fake btf");
}

void test_parse_release()
{
    using hng::detail::KernelVersion;
    using hng::detail::parse_kernel_release;

    KernelVersion version;
    CHECK(parse_kernel_release("5.4.0-150-generic", version) &&
              version.major == 5 && version.minor == 4,
          "应解析 5.4.0-150-generic");
    CHECK(parse_kernel_release("6.14.0", version) && version.major == 6 &&
              version.minor == 14,
          "应解析 6.14.0");
    CHECK(parse_kernel_release("5.10.0-8-amd64", version) &&
              version.major == 5 && version.minor == 10,
          "次版本号应按十进制解析");
    CHECK(parse_kernel_release("6.18.54.1-microsoft-standard-WSL2", version) &&
              version.major == 6 && version.minor == 18,
          "应忽略发行串尾部");

    version = KernelVersion{9, 9};
    CHECK(!parse_kernel_release("", version), "空串应解析失败");
    CHECK(!parse_kernel_release("linux", version), "无版本号的串应解析失败");
    CHECK(!parse_kernel_release("5", version), "缺少次版本号应解析失败");
    CHECK(!parse_kernel_release("5.", version), "次版本号为空应解析失败");
    CHECK(!parse_kernel_release(".4", version), "缺少主版本号应解析失败");
    CHECK(version.major == 9 && version.minor == 9,
          "解析失败不得改写输出");
}

void test_version_supported()
{
    using hng::detail::kernel_version_supported;

    CHECK(!kernel_version_supported({5, 7}), "5.7 低于下限");
    CHECK(kernel_version_supported({5, 8}), "5.8 为下限");
    CHECK(kernel_version_supported({5, 10}), "5.10 应支持");
    CHECK(kernel_version_supported({6, 0}), "6.0 应支持");
    CHECK(!kernel_version_supported({4, 19}), "4.19 低于下限");
}

void test_evaluate_support()
{
    using namespace hng::detail;

    TempRoot root;
    CHECK(!root.path.empty(), "应创建临时根目录");
    if (root.path.empty()) {
        return;
    }

    std::filesystem::create_directories(root.path / "tracing" / "events");
    make_btf(root.path);
    write_file(root.path / "mounts", "");

    KernelPaths paths;
    paths.btf             = (root.path / "btf").string();
    paths.tracing         = (root.path / "tracing").string();
    paths.tracing_debugfs = (root.path / "debug-tracing").string();
    paths.mounts          = (root.path / "mounts").string();

    const KernelSupport supported = evaluate_kernel_support("6.14.0", paths);
    CHECK(supported.ok(), "6.14 + BTF + tracefs 应通过");
    CHECK(supported.version.major == 6 && supported.version.minor == 14,
          "应记录解析出的版本");
    CHECK(supported.failures().empty(), "通过时失败项应为空");

    const KernelSupport old =
        evaluate_kernel_support("5.4.0-150-generic", paths);
    CHECK(!old.ok() && !old.version_ok, "5.4 应被拒绝");
    const std::vector<std::string> old_reasons = old.failures();
    CHECK(old_reasons.size() == 1, "5.4 只应报告版本一项");
    CHECK(!old_reasons.empty() &&
              old_reasons[0].find("5.4.0-150-generic") != std::string::npos &&
              old_reasons[0].find("5.8") != std::string::npos,
          "失败说明应带发行串与下限");

    const KernelSupport unparsable =
        evaluate_kernel_support("linux-custom", paths);
    CHECK(!unparsable.release_parsed && !unparsable.version_ok,
          "不可解析的发行串应被拒绝");
    const std::vector<std::string> unparsable_reasons = unparsable.failures();
    CHECK(!unparsable_reasons.empty() &&
              unparsable_reasons[0].find("parse") != std::string::npos,
          "失败说明应指出解析失败");

    TempRoot bare;
    CHECK(!bare.path.empty(), "应创建第二个临时根目录");
    if (bare.path.empty()) {
        return;
    }
    std::filesystem::create_directories(bare.path / "debug-tracing" / "events");
    write_file(bare.path / "mounts", "");

    KernelPaths bare_paths;
    bare_paths.btf             = (bare.path / "btf").string();
    bare_paths.tracing         = (bare.path / "tracing").string();
    bare_paths.tracing_debugfs = (bare.path / "debug-tracing").string();
    bare_paths.mounts          = (bare.path / "mounts").string();

    const KernelSupport missing = evaluate_kernel_support("6.14.0", bare_paths);
    CHECK(!missing.ok() && !missing.btf_ok && missing.tracefs_ok,
          "缺少 BTF 时应被拒绝，debugfs tracefs 仍算可用");
    const std::vector<std::string> missing_reasons = missing.failures();
    CHECK(missing_reasons.size() == 1 &&
              missing_reasons[0].find("BTF") != std::string::npos,
          "失败说明应指出 BTF");

    TempRoot no_tracefs;
    CHECK(!no_tracefs.path.empty(), "应创建第三个临时根目录");
    if (no_tracefs.path.empty()) {
        return;
    }
    make_btf(no_tracefs.path);
    write_file(no_tracefs.path / "mounts", "");

    KernelPaths no_tracefs_paths;
    no_tracefs_paths.btf             = (no_tracefs.path / "btf").string();
    no_tracefs_paths.tracing         = (no_tracefs.path / "tracing").string();
    no_tracefs_paths.tracing_debugfs = (no_tracefs.path / "debug").string();
    no_tracefs_paths.mounts          = (no_tracefs.path / "mounts").string();

    const KernelSupport no_tracefs_support =
        evaluate_kernel_support("6.14.0", no_tracefs_paths);
    CHECK(!no_tracefs_support.ok() && !no_tracefs_support.tracefs_ok,
          "未挂载 tracefs 时应被拒绝");
    const std::vector<std::string> no_tracefs_reasons =
        no_tracefs_support.failures();
    CHECK(no_tracefs_reasons.size() == 1 &&
              no_tracefs_reasons[0].find("tracefs") != std::string::npos,
          "失败说明应指出 tracefs");

    TempRoot custom;
    CHECK(!custom.path.empty(), "应创建第四个临时根目录");
    if (custom.path.empty()) {
        return;
    }
    make_btf(custom.path);
    std::filesystem::create_directories(custom.path / "custom-tracefs" /
                                        "events");
    write_file(custom.path / "mounts",
               "tracefs " + (custom.path / "custom-tracefs").string() +
                   " tracefs rw 0 0\n");

    KernelPaths custom_paths;
    custom_paths.btf             = (custom.path / "btf").string();
    custom_paths.tracing         = (custom.path / "tracing").string();
    custom_paths.tracing_debugfs = (custom.path / "debug").string();
    custom_paths.mounts          = (custom.path / "mounts").string();

    const KernelSupport custom_support =
        evaluate_kernel_support("6.14.0", custom_paths);
    CHECK(custom_support.ok(), "挂载表中的自定义 tracefs 应算可用");
}

}  // namespace

int main()
{
    test_parse_release();
    test_version_supported();
    test_evaluate_support();

    if (g_fail != 0) {
        std::fprintf(stderr, "%d check(s) failed\n", g_fail);
        return 1;
    }
    std::printf("all kernel preflight checks passed\n");
    return 0;
}
