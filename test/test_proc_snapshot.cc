/**
 * @file test_proc_snapshot.cc
 * @brief /proc 快照读取器的单元测试
 * @details
 * 用临时目录伪造 /proc 根，覆盖：
 *  - 正常解析：pid / ppid / starttime / exe，父 starttime 二次解析；
 *  - 僵尸（Z/X）与 PF_KTHREAD 跳过；
 *  - comm 含空格与 ')'；
 *  - 父不在快照中：计 parent_missing，父 starttime 保持 0；
 *  - exe 不可读（链接不存在、非符号链接）为空并计数；
 *  - stat 畸形与 stat 缺失的区别；
 *  - 根目录不可读：proc_available 与 batch.complete 均为 false。
 * @author red_shinku
 * @date 2026.10.25
 */

#include "agent/assembly/src/proc_snapshot.hpp"
#include "agent/control_plane/src/process_manager.hpp"

#include <unistd.h>

#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <utility>
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

/// 临时 /proc 根，析构时整体删除
class FakeProc {
   public:
    FakeProc()
    {
        root_ = std::filesystem::temp_directory_path() /
                ("hng_proc_snapshot_" + std::to_string(::getpid()) + "_" +
                 std::to_string(++counter_));
        std::filesystem::remove_all(root_);
        std::filesystem::create_directories(root_);
    }

    ~FakeProc()
    {
        std::error_code ec;
        std::filesystem::remove_all(root_, ec);
    }

    FakeProc(const FakeProc&)            = delete;
    FakeProc& operator=(const FakeProc&) = delete;

    std::string path() const { return root_.string(); }

    void add_dir(const std::string& name)
    {
        std::filesystem::create_directories(root_ / name);
    }

    void write_file(const std::string& name, const std::string& file,
                    const std::string& content)
    {
        add_dir(name);
        std::ofstream out(root_ / name / file, std::ios::binary);
        out << content;
    }

    void write_stat(const std::string& name, const std::string& content)
    {
        write_file(name, "stat", content);
    }

    void add_exe_link(const std::string& name, const std::string& target)
    {
        add_dir(name);
        std::filesystem::create_symlink(target, root_ / name / "exe");
    }

    void add_exe_file(const std::string& name) { write_file(name, "exe", ""); }

   private:
    std::filesystem::path root_;
    static int counter_;
};

int FakeProc::counter_ = 0;

/// 生成 /proc/<pid>/stat；comm 原样放入括号内
std::string stat_line(uint32_t pid, const std::string& comm, char state,
                      uint32_t ppid, uint64_t flags, uint64_t starttime)
{
    std::vector<std::string> fields(20, "0");
    fields[0]        = std::string(1, state);
    fields[1]        = std::to_string(ppid);
    fields[6]        = std::to_string(flags);
    fields[19]       = std::to_string(starttime);

    std::string line = std::to_string(pid) + " (" + comm + ")";
    for (const std::string& field : fields) {
        line += " ";
        line += field;
    }
    line += "\n";
    return line;
}

const hng::ProcessSeedEntry* find_entry(const hng::ProcessSnapshot& snapshot,
                                        uint32_t pid)
{
    for (const hng::ProcessSeedEntry& entry : snapshot.batch.entries) {
        if (entry.process.pid == pid) {
            return &entry;
        }
    }
    return nullptr;
}

void run_basic()
{
    FakeProc proc_root;
    proc_root.write_stat("1", stat_line(1, "systemd", 'S', 0, 0, 100));
    proc_root.write_stat("2", stat_line(2, "bash", 'S', 1, 0, 200));
    proc_root.add_exe_link("1", "/usr/lib/systemd/systemd");
    proc_root.add_exe_link("2", "/bin/bash");

    ProcessSnapshotReader reader(proc_root.path());
    const hng::ProcessSnapshot snapshot = reader.read();

    CHECK(snapshot.anomalies.proc_available, "/proc 根应可读");
    CHECK(snapshot.batch.complete, "完整目录应标记为完整");
    CHECK(snapshot.anomalies.proc_seen == 2, "应看到两个数字目录");
    CHECK(snapshot.anomalies.zombie_skipped == 0, "不应跳过僵尸");
    CHECK(snapshot.anomalies.kthread_skipped == 0, "不应跳过内核线程");
    CHECK(snapshot.anomalies.stat_parse_failed == 0, "stat 应全部可解析");
    CHECK(snapshot.anomalies.exe_unreadable == 0, "两个 exe 都可读");
    CHECK(snapshot.anomalies.parent_missing == 0, "父进程在快照中");
    CHECK(snapshot.batch.entries.size() == 2, "应有两个条目");

    const hng::ProcessSeedEntry* root = find_entry(snapshot, 1);
    CHECK(root != nullptr, "根进程应存在");
    if (root != nullptr) {
        CHECK(root->process.pid_start_time == 100, "starttime 应取自字段 22");
        CHECK(root->ppid == 0 && root->ppid_start_time == 0, "根没有父进程");
        CHECK(root->exe == "/usr/lib/systemd/systemd", "exe 应取 readlink 结果");
    }

    const hng::ProcessSeedEntry* child = find_entry(snapshot, 2);
    CHECK(child != nullptr, "子进程应存在");
    if (child != nullptr) {
        CHECK(child->process.pid_start_time == 200, "子进程 starttime 应正确");
        CHECK(child->ppid == 1, "ppid 应取自字段 4");
        CHECK(child->ppid_start_time == 100, "父 starttime 应在快照内解析");
        CHECK(child->exe == "/bin/bash", "子进程 exe 应正确");
    }
}

/// 快照直接喂给 PM seed：初始树应与快照一致
void run_seed_from_snapshot()
{
    FakeProc proc_root;
    proc_root.write_stat("1", stat_line(1, "init", 'S', 0, 0, 100));
    proc_root.write_stat("2", stat_line(2, "bash", 'S', 1, 0, 200));
    proc_root.write_stat("3", stat_line(3, "grep", 'S', 2, 0, 300));
    proc_root.add_exe_link("1", "/sbin/init");
    proc_root.add_exe_link("2", "/bin/bash");
    proc_root.add_exe_link("3", "/usr/bin/grep");

    const hng::ProcessSnapshot snapshot =
        ProcessSnapshotReader(proc_root.path()).read();

    ProcessManager manager;
    const ProcessSeedReport report = manager.seed(snapshot.batch);
    CHECK(report.inserted == 3, "快照中的三条都应落地");
    CHECK(report.parent_missing == 0, "快照内父子关系应完整");
    CHECK(manager.state() == hng::ComponentState::READY, "seed 后应为 READY");

    const auto root = manager.lookup(hng::Process{1, 100});
    CHECK(root.has_value() && root->child_count == 1 && root->exe == "/sbin/init",
          "根节点应与快照一致");
    const auto bash = manager.lookup(hng::Process{2, 200});
    CHECK(bash.has_value() && bash->ppid == 1 && bash->ppid_start_time == 100 &&
              bash->child_count == 1 && bash->exe == "/bin/bash",
          "子节点应带上快照解析出的父身份");
    const auto grep = manager.lookup(hng::Process{3, 300});
    CHECK(grep.has_value() && grep->ppid == 2 && grep->ppid_start_time == 200 &&
              grep->child_count == 0,
          "孙节点应与快照一致");
}

void run_skips()
{
    FakeProc proc_root;
    proc_root.write_stat("3", stat_line(3, "zombie", 'Z', 1, 0, 300));
    proc_root.write_stat("4", stat_line(4, "dead", 'X', 1, 0, 400));
    proc_root.write_stat("5", stat_line(5, "kthread", 'S', 2, 0x00200000, 500));
    proc_root.write_stat("6", stat_line(6, "normal", 'S', 1, 0, 600));
    proc_root.add_exe_link("6", "/bin/normal");
    proc_root.add_dir("self");                      // 非数字目录名
    proc_root.write_file("", "uptime", "1 2 3\n");  // 根下的普通文件

    const hng::ProcessSnapshot snapshot =
        ProcessSnapshotReader(proc_root.path()).read();

    CHECK(snapshot.anomalies.proc_seen == 4, "只统计数字目录名");
    CHECK(snapshot.anomalies.zombie_skipped == 2, "Z 与 X 都应跳过");
    CHECK(snapshot.anomalies.kthread_skipped == 1, "PF_KTHREAD 应跳过");
    CHECK(snapshot.anomalies.exe_unreadable == 0, "被跳过的进程不应尝试读取 exe");
    CHECK(snapshot.batch.entries.size() == 1, "只保留普通进程");
    const hng::ProcessSeedEntry* entry = find_entry(snapshot, 6);
    CHECK(entry != nullptr, "普通进程应在结果中");
    CHECK(entry != nullptr && entry->exe == "/bin/normal", "普通进程 exe 应可读");
}

void run_comm_with_space_and_paren()
{
    FakeProc proc_root;
    proc_root.write_stat("7", stat_line(7, "my proc) odd", 'S', 1, 0, 700));
    proc_root.write_stat("8", stat_line(8, "with space", 'S', 7, 0, 800));
    proc_root.add_exe_link("7", "/bin/odd");
    proc_root.add_exe_link("8", "/bin/space");

    const hng::ProcessSnapshot snapshot =
        ProcessSnapshotReader(proc_root.path()).read();

    CHECK(snapshot.anomalies.stat_parse_failed == 0,
          "comm 含空格与 ')' 不应导致解析失败");
    const hng::ProcessSeedEntry* odd = find_entry(snapshot, 7);
    CHECK(odd != nullptr, "comm 含 ')' 的进程应解析出");
    if (odd != nullptr) {
        CHECK(odd->process.pid_start_time == 700,
              "comm 含 ')' 时 starttime 应正确");
        CHECK(odd->ppid == 1, "comm 含 ')' 时 ppid 应正确");
        CHECK(odd->ppid_start_time == 0, "父为 1 但未在快照中");
    }
    const hng::ProcessSeedEntry* space = find_entry(snapshot, 8);
    CHECK(space != nullptr && space->ppid_start_time == 700,
          "comm 含空格时父 starttime 应正确解析");
    CHECK(snapshot.anomalies.parent_missing == 1, "只有 pid 7 的父缺失");
}

void run_parent_missing()
{
    FakeProc proc_root;
    proc_root.write_stat("10", stat_line(10, "root", 'S', 0, 0, 100));
    proc_root.write_stat("11", stat_line(11, "orphan", 'S', 999, 0, 200));
    proc_root.write_stat("12", stat_line(12, "child", 'S', 10, 0, 300));
    proc_root.add_exe_link("10", "/bin/root");
    proc_root.add_exe_link("11", "/bin/orphan");
    proc_root.add_exe_link("12", "/bin/child");

    const hng::ProcessSnapshot snapshot =
        ProcessSnapshotReader(proc_root.path()).read();

    CHECK(snapshot.anomalies.parent_missing == 1, "父不在快照中应计数");
    const hng::ProcessSeedEntry* orphan = find_entry(snapshot, 11);
    CHECK(orphan != nullptr, "父缺失的条目应保留");
    CHECK(orphan != nullptr && orphan->ppid == 999, "ppid 原样保留");
    CHECK(orphan != nullptr && orphan->ppid_start_time == 0,
          "缺失父的 starttime 为 0");
    const hng::ProcessSeedEntry* child = find_entry(snapshot, 12);
    CHECK(child != nullptr && child->ppid_start_time == 100,
          "父在快照中时应填 starttime");
}

void run_exe_unreadable()
{
    FakeProc proc_root;
    proc_root.write_stat("20", stat_line(20, "no-exe", 'S', 0, 0, 100));
    proc_root.write_stat("21", stat_line(21, "plain-exe", 'S', 0, 0, 200));
    proc_root.add_dir("20");       // 没有 exe 链接
    proc_root.add_exe_file("21");  // exe 是普通文件，readlink 失败

    const hng::ProcessSnapshot snapshot =
        ProcessSnapshotReader(proc_root.path()).read();

    CHECK(snapshot.anomalies.exe_unreadable == 2,
          "链接不存在与非符号链接都应计数");
    CHECK(snapshot.batch.entries.size() == 2, "exe 不可读不影响条目落地");
    const hng::ProcessSeedEntry* no_exe = find_entry(snapshot, 20);
    CHECK(no_exe != nullptr && no_exe->exe.empty(), "不可读的 exe 为空");
    const hng::ProcessSeedEntry* plain = find_entry(snapshot, 21);
    CHECK(plain != nullptr && plain->exe.empty(), "非符号链接的 exe 为空");
}

/// 构造 comm 之后第 index 个字段被替换的行
std::string stat_line_override(uint32_t pid, const std::string& comm,
                               std::size_t index, const std::string& value)
{
    std::vector<std::string> fields(20, "0");
    fields[0]        = "S";
    fields[index]    = value;
    std::string line = std::to_string(pid) + " (" + comm + ")";
    for (const std::string& field : fields) {
        line += " ";
        line += field;
    }
    line += "\n";
    return line;
}

void run_malformed_stat()
{
    FakeProc proc_root;
    proc_root.write_stat("30", "30 (no-close S 0 0 0");  // 没有 ')'
    proc_root.write_stat("31", "31 (few) S 0 1 2 3");    // 字段不足
    proc_root.write_stat("32", stat_line_override(32, "bad-ppid", 1, "x"));
    proc_root.write_stat("33", stat_line_override(33, "bad-start", 19, "x"));
    proc_root.add_dir("35");
    std::filesystem::create_directories(std::filesystem::path(proc_root.path()) /
                                        "35" / "stat");  // stat 是目录
    proc_root.add_dir("36");  // 扫描期间退出：stat 不存在
    proc_root.write_stat("37", stat_line(37, "ok", 'S', 0, 0, 700));
    proc_root.add_exe_link("37", "/bin/ok");

    const hng::ProcessSnapshot snapshot =
        ProcessSnapshotReader(proc_root.path()).read();

    CHECK(snapshot.anomalies.proc_seen == 7, "所有数字目录都计入 proc_seen");
    CHECK(snapshot.anomalies.stat_parse_failed == 5,
          "无 ')'、字段不足、非数字字段与读取失败都应计数");
    CHECK(snapshot.batch.entries.size() == 1, "只有合法条目落地");
    CHECK(find_entry(snapshot, 37) != nullptr, "合法条目应保留");
    CHECK(find_entry(snapshot, 36) == nullptr,
          "stat 缺失（扫描期间退出）应静默跳过");
}

void run_root_unavailable()
{
    const std::filesystem::path missing =
        std::filesystem::temp_directory_path() /
        ("hng_proc_missing_" + std::to_string(::getpid()));

    const hng::ProcessSnapshot snapshot =
        ProcessSnapshotReader(missing.string()).read();

    CHECK(!snapshot.anomalies.proc_available, "/proc 根不可读应置 false");
    CHECK(!snapshot.batch.complete, "根不可读时批次不完整");
    CHECK(snapshot.batch.entries.empty(), "根不可读时没有条目");
}

}  // namespace

int main()
{
    run_basic();
    run_seed_from_snapshot();
    run_skips();
    run_comm_with_space_and_paren();
    run_parent_missing();
    run_exe_unreadable();
    run_malformed_stat();
    run_root_unavailable();

    if (g_fail) {
        std::fprintf(stderr, "TOTAL FAILURES: %d\n", g_fail);
        return 1;
    }
    std::printf("ALL PASS\n");
    return 0;
}
