/**
 * @file test_role_cgroup_reader.cc
 * @brief cgroup 递归枚举与 stat 解析的表驱动单元测试
 * @details
 * 覆盖 agent/role_discovery 的 RoleCgroupReader：
 *  - 递归枚举：嵌套子 cgroup、中间层无 cgroup.procs 的子树均被完整枚举；
 *  - 容错：路径不存在 / 非目录、进程在枚举期间退出、cgroup.procs 不可读或内容脏、
 *    子目录消失（以悬空符号链接模拟），均不崩溃且返回已收集结果；
 *  - stat 解析：进程名含空格与括号、字段不足、字段非数字、数值溢出。
 * 全部基于临时目录树 + 注入的假 procfs 根，不依赖特权，也不读真实 cgroup。
 *
 * @author red_shinku
 * @date 2026.9.11
 */

#include "agent/role_discovery/src/role_cgroup_reader.hpp"

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <unistd.h>
#include <vector>

namespace {

int g_fail = 0;

#define CHECK(cond, msg)                                                         \
    do {                                                                         \
        if (!(cond)) {                                                           \
            ++g_fail;                                                            \
            std::fprintf(stderr, "[FAIL] %s:%d  %s\n", __FILE__, __LINE__, msg); \
        }                                                                        \
    } while (0)

namespace fs = std::filesystem;

using hng::Process;
using hng::role::RoleCgroupReader;

/// 临时目录，析构时递归删除
class TempDir {
   public:
    TempDir()
    {
        std::string tmpl =
            (fs::temp_directory_path() / "hng_role_cg_XXXXXX").string();
        std::vector<char> buffer(tmpl.begin(), tmpl.end());
        buffer.push_back('\0');
        if (const char* made = ::mkdtemp(buffer.data())) {
            path_ = made;
        }
    }
    ~TempDir()
    {
        std::error_code ec;
        fs::remove_all(path_, ec);
    }
    TempDir(const TempDir&)            = delete;
    TempDir& operator=(const TempDir&) = delete;

    const fs::path& path() const { return path_; }

   private:
    fs::path path_;
};

/// 构造 /proc/<pid>/stat 的内容：字段 4..21 以 0 填充，字段 22 为 starttime
std::string stat_line(uint32_t pid, const std::string& name,
                      const std::string& start_token)
{
    std::ostringstream out;
    out << pid << " (" << name << ") S";
    for (int field = 4; field <= 21; ++field) {
        out << " 0";
    }
    out << " " << start_token;
    return out.str();
}

/// 在假 procfs 根下写入一个可解析的进程
void mk_proc(const fs::path& proc_root, uint32_t pid, const std::string& name,
             uint64_t start)
{
    fs::create_directories(proc_root / std::to_string(pid));
    std::ofstream(proc_root / std::to_string(pid) / "stat")
        << stat_line(pid, name, std::to_string(start));
}

/// 在 root/rel 下建目录并写入 cgroup.procs；procs 为空串时不创建该文件
void mk_cgroup(const fs::path& root, const std::string& rel,
               const std::string& procs)
{
    const fs::path dir = root / rel;
    fs::create_directories(dir);
    if (!procs.empty()) {
        std::ofstream(dir / "cgroup.procs") << procs;
    }
}

std::string render(const std::vector<Process>& processes)
{
    std::ostringstream out;
    for (const Process& p : processes) {
        out << "{" << p.pid << "," << p.pid_start_time << "} ";
    }
    return out.str();
}

/// 断言枚举结果与期望逐项相等（枚举结果按 pid 升序）
void check_processes(const char* name, const std::vector<Process>& got,
                     const std::vector<Process>& expect)
{
    bool ok = got.size() == expect.size();
    for (std::size_t i = 0; ok && i < got.size(); ++i) {
        ok = got[i].pid == expect[i].pid &&
             got[i].pid_start_time == expect[i].pid_start_time;
    }
    if (!ok) {
        ++g_fail;
        std::fprintf(stderr, "[FAIL] %s\n        实际: %s\n        期望: %s\n",
                     name, render(got).c_str(), render(expect).c_str());
    }
}

// ---- 递归枚举 ----
void run_recursion()
{
    TempDir tmp;
    fs::path root = tmp.path() / "cg";
    fs::path proc = tmp.path() / "proc";

    // unit 自身 + 两层嵌套子 cgroup（Delegate= / 多容器 Pod 的形态）
    mk_cgroup(root, "", "101\n");
    mk_cgroup(root, "child", "102\n");
    mk_cgroup(root, "child/deep", "103\n");
    // 中间层无 cgroup.procs，但其子目录仍须被枚举到
    mk_cgroup(root, "empty-layer", "");
    mk_cgroup(root, "empty-layer/leaf", "104\n");

    mk_proc(proc, 101, "nginx", 1111);
    mk_proc(proc, 102, "nginx worker", 2222);
    mk_proc(proc, 103, "my proc (1)", 3333);
    mk_proc(proc, 104, "sd-pam", 4444);

    check_processes("递归枚举应覆盖全部子孙 cgroup",
                    RoleCgroupReader::read(root, proc),
                    {{101, 1111}, {102, 2222}, {103, 3333}, {104, 4444}});
    // cgroup_path 指向子目录时只枚举该子树
    check_processes("从子目录起枚举",
                    RoleCgroupReader::read(root / "child", proc),
                    {{102, 2222}, {103, 3333}});
}

// ---- 进程所属 cgroup ----
void run_process_cgroup()
{
    TempDir tmp;
    fs::path proc = tmp.path() / "proc";

    // cgroup v2：唯一一行是统一层次
    mk_proc(proc, 501, "nginx", 1111);
    std::ofstream(proc / "501" / "cgroup")
        << "0::/kubepods/besteffort/pod1234/cri-containerd-abc.scope\n";
    std::optional<std::string> path =
        RoleCgroupReader::read_process_cgroup(501, proc);
    CHECK(
        path && *path == "/kubepods/besteffort/pod1234/cri-containerd-abc.scope",
        "应取出统一层次的路径");

    // cgroup v1：各行都带控制器名，没有统一层次可取
    mk_proc(proc, 502, "old", 2222);
    std::ofstream(proc / "502" / "cgroup")
        << "11:cpuset:/\n10:cpu,cpuacct:/system.slice/old.service\n";
    CHECK(!RoleCgroupReader::read_process_cgroup(502, proc).has_value(),
          "只有 v1 行时不应给出路径");

    // 进程已不存在
    CHECK(!RoleCgroupReader::read_process_cgroup(599, proc).has_value(),
          "进程不存在时应为空");

    // 真实环境：本进程的 cgroup 必可取出，且是绝对路径
    std::optional<std::string> self =
        RoleCgroupReader::read_process_cgroup(::getpid());
    CHECK(self.has_value() && !self->empty() && self->front() == '/',
          "本进程的 cgroup 应可取出");
}

// ---- 容错 ----
void run_tolerance()
{
    TempDir tmp;
    fs::path root = tmp.path() / "cg";
    fs::path proc = tmp.path() / "proc";

    mk_cgroup(root, "", "101\n");
    mk_proc(proc, 101, "nginx", 1111);

    // 路径不存在
    CHECK(RoleCgroupReader::read(tmp.path() / "absent", proc).empty(),
          "路径不存在应返回空结果");
    // 路径是普通文件
    std::ofstream(tmp.path() / "a-file") << "not a cgroup";
    CHECK(RoleCgroupReader::read(tmp.path() / "a-file", proc).empty(),
          "路径非目录应返回空结果");

    // 进程在枚举期间退出：cgroup.procs 里有 pid，但 procfs 里已无对应 stat
    mk_cgroup(root, "gone", "102\n");
    // stat 不可解析（内容被截断）等价于读不到
    fs::create_directories(proc / "103");
    std::ofstream(proc / "103" / "stat") << "103 (x) S 1";
    mk_cgroup(root, "truncated", "103\n");
    check_processes("枚举期间退出的进程被跳过",
                    RoleCgroupReader::read(root, proc), {{101, 1111}});

    // cgroup.procs 内容脏：空行、非数字、0、超出 uint32 均被忽略
    mk_cgroup(root, "dirty", "abc\n\n0\n4294967296\n104\n");
    mk_proc(proc, 104, "nginx", 1111);
    check_processes("脏 cgroup.procs 只取合法 pid",
                    RoleCgroupReader::read(root, proc),
                    {{101, 1111}, {104, 1111}});

    // cgroup.procs 是目录，打不开（等价于不可读）
    fs::create_directories(root / "unreadable" / "cgroup.procs");
    check_processes("不可读的 cgroup.procs 不中断枚举",
                    RoleCgroupReader::read(root, proc),
                    {{101, 1111}, {104, 1111}});

    // 子目录消失：以悬空符号链接模拟。链接指向已被删除的目录，对枚举者与
    // "目录在枚举期间被删" 等价，且不跟随符号链接可避免遍历成环
    std::error_code ec;
    fs::create_directory_symlink(tmp.path() / "vanished", root / "gone-dir", ec);
    CHECK(!ec, "应能创建悬空符号链接");
    check_processes("消失的子目录不中断枚举", RoleCgroupReader::read(root, proc),
                    {{101, 1111}, {104, 1111}});
}

// ---- stat 解析 ----
struct StatCase {
    const char* name;
    std::string content;
    bool has_value;
    uint64_t expect;
};

void run_stat_parsing()
{
    const StatCase cases[] = {
        {"普通进程名", stat_line(1234, "nginx", "987654"), true, 987654},
        {"进程名含空格", stat_line(1234, "nginx worker", "987654"), true, 987654},
        {"进程名含括号", stat_line(1234, "sd-pam(1)", "555"), true, 555},
        {"进程名含空格与右括号", stat_line(1234, "a b)c", "777"), true, 777},
        {"进程名含两个右括号", stat_line(1234, "x)y (z", "42"), true, 42},
        {"文件末尾带换行", stat_line(1234, "nginx", "987654") + "\n", true,
         987654},
        {"空内容", "", false, 0},
        {"无右括号", "1234 nginx S 1", false, 0},
        {"字段不足", "1234 (nginx) S 1 2 3", false, 0},
        {"字段 22 非数字", stat_line(1234, "nginx", "abc"), false, 0},
        {"字段 22 为空", stat_line(1234, "nginx", ""), false, 0},
        {"字段 22 溢出 uint64", stat_line(1234, "nginx", "99999999999999999999"),
         false, 0},
    };
    for (const StatCase& c : cases) {
        std::optional<uint64_t> got =
            RoleCgroupReader::parse_start_time(c.content);
        if (got.has_value() != c.has_value || (c.has_value && *got != c.expect)) {
            ++g_fail;
            std::fprintf(
                stderr,
                "[FAIL] parse_start_time(%s): 产出=%d 值=%llu 期望=%d %llu\n",
                c.name, (int)got.has_value(),
                (unsigned long long)(got ? *got : 0), (int)c.has_value,
                (unsigned long long)c.expect);
        }
    }
}

// ---- 真实 cgroup 上的端到端校验（/sys/fs/cgroup 不可用时跳过）----
void run_real_cgroup()
{
    std::error_code ec;
    if (!fs::is_directory("/sys/fs/cgroup", ec)) {
        std::printf("SKIP: /sys/fs/cgroup 不可用\n");
        return;
    }
    std::ifstream cgroup_file("/proc/self/cgroup");
    std::string line;
    if (!std::getline(cgroup_file, line)) {
        std::printf("SKIP: /proc/self/cgroup 不可读\n");
        return;
    }
    // 形态为 "0::/user.slice/..."，取冒号之后的绝对路径接到挂载点上
    const std::size_t pos = line.rfind(':');
    if (pos == std::string::npos) {
        std::printf("SKIP: /proc/self/cgroup 无统一挂载项\n");
        return;
    }
    const fs::path self_cgroup =
        fs::path("/sys/fs/cgroup" + line.substr(pos + 1));
    if (!fs::is_directory(self_cgroup, ec)) {
        std::printf("SKIP: 自身 cgroup 路径 %s 不可用\n", self_cgroup.c_str());
        return;
    }

    const std::vector<Process> processes =
        RoleCgroupReader::read(self_cgroup.string());
    bool found = false;
    for (const Process& p : processes) {
        if (p.pid == static_cast<uint32_t>(::getpid())) {
            found = true;
        }
    }
    CHECK(found, "自身进程应出现在自身 cgroup 的枚举结果中");
}

}  // namespace

/// 相对路径到绝对路径的解析：各源给出的 cgroup 路径相对挂载点
void run_path_resolution()
{
    const std::string& root = RoleCgroupReader::root();
    CHECK(!root.empty(), "挂载点非空");
    CHECK(root.front() == '/', "挂载点为绝对路径");
    CHECK(root.size() == 1 || root.back() != '/', "挂载点不以 '/' 结尾");

    // 相对路径接到挂载点上
    CHECK(RoleCgroupReader::absolute("/system.slice/x.service") ==
              root + "/system.slice/x.service",
          "相对路径接到挂载点上");
    CHECK(RoleCgroupReader::absolute("/") == root + "/", "根相对路径可解析");

    // 已是绝对路径的原样返回
    const std::string already = root + "/system.slice/y.service";
    CHECK(RoleCgroupReader::absolute(already) == already, "绝对路径原样返回");
    CHECK(RoleCgroupReader::absolute(root) == root, "挂载点自身原样返回");

    // 非绝对路径与空串原样返回，不臆造
    CHECK(RoleCgroupReader::absolute("").empty(), "空串原样返回");
    CHECK(RoleCgroupReader::absolute("relative/path") == "relative/path",
          "非绝对路径原样返回");

    // 探测出的挂载点应当真的可枚举
    std::error_code ec;
    if (fs::is_directory(root, ec)) {
        std::ifstream cgroup_file("/proc/self/cgroup");
        std::string line;
        if (std::getline(cgroup_file, line)) {
            const std::size_t pos = line.rfind(':');
            if (pos != std::string::npos) {
                const std::string self_cgroup =
                    RoleCgroupReader::absolute(line.substr(pos + 1));
                std::vector<Process> processes =
                    RoleCgroupReader::read(self_cgroup);
                bool found = false;
                for (const Process& p : processes) {
                    if (p.pid == static_cast<uint32_t>(::getpid())) {
                        found = true;
                    }
                }
                CHECK(found, "自身进程应出现在解析出的自身 cgroup 中");
            }
        }
    }
}

int main()
{
    run_recursion();
    run_process_cgroup();
    run_tolerance();
    run_stat_parsing();
    run_path_resolution();
    run_real_cgroup();
    if (g_fail) {
        std::fprintf(stderr, "TOTAL FAILURES: %d\n", g_fail);
        return 1;
    }
    std::printf("ALL PASS (cgroup reader)\n");
    return 0;
}
