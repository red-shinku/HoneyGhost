/**
 * @file test_tracefs.cc
 * @brief tracefs 挂载根与 tracepoint 存在性探测的单元测试
 * @details 用临时目录伪造 events 树与 /proc/mounts，不需要挂载权限。
 */

#include "agent/util/include/tracefs.hpp"

#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>

namespace {

int g_fail = 0;

#define CHECK(cond, msg)                                                         \
    do {                                                                         \
        if (!(cond)) {                                                           \
            ++g_fail;                                                            \
            std::fprintf(stderr, "[FAIL] %s:%d  %s\n", __FILE__, __LINE__, msg); \
        }                                                                        \
    } while (false)

/// @brief 由 mkdtemp 独占创建的临时目录，析构时整体删除
struct TempRoot {
    std::filesystem::path path;

    TempRoot()
    {
        std::string pattern =
            (std::filesystem::temp_directory_path() / "hng_tracefs_XXXXXX")
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

void write_file(const std::filesystem::path& path, const std::string& content)
{
    std::ofstream file(path);
    file << content;
}

/// @brief 在 root 下创建带可访问 events 目录的 tracefs 根
void make_root(const std::filesystem::path& root)
{
    std::filesystem::create_directories(root / "events");
}

/// @brief 在 root 下创建 events/<group>/<event>/id
void make_tracepoint(const std::filesystem::path& root, const std::string& group,
                     const std::string& event)
{
    const std::filesystem::path directory = root / "events" / group / event;
    std::filesystem::create_directories(directory);
    write_file(directory / "id", "1\n");
}

/// @brief root 的 events 目录是否存在且可访问
bool events_accessible(const std::filesystem::path& root)
{
    std::error_code error;
    const std::filesystem::path events = root / "events";
    return std::filesystem::is_directory(events, error) &&
           ::access(events.c_str(), R_OK | X_OK) == 0;
}

void test_candidate_order()
{
    using hng::detail::find_tracefs_root;

    TempRoot temp;
    CHECK(!temp.path.empty(), "应创建临时根目录");
    if (temp.path.empty()) {
        return;
    }
    const std::filesystem::path primary   = temp.path / "primary";
    const std::filesystem::path secondary = temp.path / "secondary";
    const std::filesystem::path custom    = temp.path / "custom";
    const std::filesystem::path mounts    = temp.path / "mounts";
    write_file(mounts, "");

    make_root(primary);
    make_root(secondary);
    CHECK(find_tracefs_root(primary, secondary, mounts) == primary,
          "候选一应优先命中");

    std::filesystem::remove_all(primary / "events");
    CHECK(find_tracefs_root(primary, secondary, mounts) == secondary,
          "候选一缺少 events 时应回落到候选二");

    std::filesystem::remove_all(secondary / "events");
    CHECK(find_tracefs_root(primary, secondary, mounts).empty(),
          "候选都缺少 events 且挂载表为空时应返回空");

    make_root(custom);
    write_file(mounts, "tracefs " + custom.string() + " tracefs rw 0 0\n");
    CHECK(find_tracefs_root(primary, secondary, mounts) == custom,
          "挂载表中的 tracefs 应被识别");

    std::filesystem::remove_all(custom / "events");
    CHECK(find_tracefs_root(primary, secondary, mounts).empty(),
          "挂载点缺少 events 时应返回空");

    // events 是普通文件而非目录时不算可用。
    std::filesystem::create_directories(primary);
    write_file(primary / "events", "not a directory");
    CHECK(find_tracefs_root(primary, secondary, mounts).empty(),
          "events 不是目录时应返回空");
}

void test_mounts_parsing()
{
    using hng::detail::find_tracefs_root;

    TempRoot temp;
    CHECK(!temp.path.empty(), "应创建临时根目录");
    if (temp.path.empty()) {
        return;
    }
    const std::filesystem::path first  = temp.path / "first";
    const std::filesystem::path second = temp.path / "second";
    const std::filesystem::path mounts = temp.path / "mounts";
    make_root(second);
    write_file(mounts, "proc /proc proc rw 0 0\n" + std::string("tracefs ") +
                           first.string() + " tracefs rw 0 0\n" +
                           std::string("tracefs ") + second.string() +
                           " tracefs rw 0 0\n" + "broken line\n");
    CHECK(find_tracefs_root(temp.path / "missing", temp.path / "missing",
                            mounts) == second,
          "应跳过无 events 的 tracefs 挂载点并继续扫描");
}

void test_tracepoint_present()
{
    using hng::detail::tracepoint_present;

    TempRoot temp;
    CHECK(!temp.path.empty(), "应创建临时根目录");
    if (temp.path.empty()) {
        return;
    }
    const std::filesystem::path root = temp.path / "tracefs";
    make_root(root);
    make_tracepoint(root, "syscalls", "sys_enter_openat");

    CHECK(tracepoint_present(root, "syscalls", "sys_enter_openat"),
          "存在 id 文件时应判定为存在");
    CHECK(!tracepoint_present(root, "syscalls", "sys_enter_missing"),
          "缺少事件目录时应判定为不存在");
    CHECK(!tracepoint_present(root, "missing", "sys_enter_openat"),
          "缺少组目录时应判定为不存在");
    CHECK(!tracepoint_present(std::filesystem::path{}, "syscalls",
                              "sys_enter_openat"),
          "root 为空时应判定为不存在");
    CHECK(!tracepoint_present(root, "", "sys_enter_openat"),
          "组名为空时应判定为不存在");
    CHECK(!tracepoint_present(root, "syscalls", ""),
          "事件名为空时应判定为不存在");

    // id 是目录而不是普通文件时不算存在。
    const std::filesystem::path directory_id =
        root / "events" / "syscalls" / "sys_enter_openat2" / "id";
    std::filesystem::create_directories(directory_id);
    CHECK(!tracepoint_present(root, "syscalls", "sys_enter_openat2"),
          "id 不是普通文件时应判定为不存在");
}

/// @brief 默认重载按真实标准路径与挂载表解析，这里按实际环境断言
void test_default_resolution()
{
    using hng::detail::find_tracefs_root;

    const std::filesystem::path primary   = "/sys/kernel/tracing";
    const std::filesystem::path secondary = "/sys/kernel/debug/tracing";
    const bool primary_ok                 = events_accessible(primary);
    const bool secondary_ok               = events_accessible(secondary);

    TempRoot temp;
    CHECK(!temp.path.empty(), "应创建临时根目录");
    if (temp.path.empty()) {
        return;
    }
    const std::filesystem::path custom = temp.path / "custom";
    const std::filesystem::path mounts = temp.path / "mounts";
    make_root(custom);
    write_file(mounts, "tracefs " + custom.string() + " tracefs rw 0 0\n");

    const std::filesystem::path resolved = find_tracefs_root(mounts);
    if (primary_ok) {
        CHECK(resolved == primary, "默认重载应优先返回 /sys/kernel/tracing");
    }
    else if (secondary_ok) {
        CHECK(resolved == secondary,
              "默认重载应回落到 /sys/kernel/debug/tracing");
    }
    else {
        CHECK(resolved == custom, "标准路径都不可用时应返回挂载表中的 tracefs");
        CHECK(find_tracefs_root(temp.path / "missing-mounts").empty(),
              "没有标准路径与挂载项时默认重载应返回空");
    }
}

}  // namespace

int main()
{
    test_candidate_order();
    test_mounts_parsing();
    test_tracepoint_present();
    test_default_resolution();

    if (g_fail != 0) {
        std::fprintf(stderr, "%d check(s) failed\n", g_fail);
        return 1;
    }
    std::printf("all tracefs checks passed\n");
    return 0;
}
