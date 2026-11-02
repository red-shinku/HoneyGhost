#include "agent/assembly/src/proc_snapshot.hpp"

#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace {

constexpr uint64_t kPfKthread = 0x00200000ULL;

/// 目录名是否为纯数字
bool all_digits(const char* text)
{
    if (text == nullptr || *text == '\0') {
        return false;
    }
    for (const char* p = text; *p != '\0'; ++p) {
        if (*p < '0' || *p > '9') {
            return false;
        }
    }
    return true;
}

/// 解析无符号十进制整数；必须整段为数字且不溢出
bool parse_u64(std::string_view text, uint64_t& value)
{
    if (text.empty()) {
        return false;
    }
    for (char c : text) {
        if (c < '0' || c > '9') {
            return false;
        }
    }

    const std::string buffer(text);
    char* end                       = nullptr;
    errno                           = 0;
    const unsigned long long parsed = std::strtoull(buffer.c_str(), &end, 10);
    if (errno != 0 || end != buffer.c_str() + buffer.size()) {
        return false;
    }
    value = static_cast<uint64_t>(parsed);
    return true;
}

/// 读入整个文件；失败时 err 为 errno
bool read_file(const std::string& path, std::string& content, int& err)
{
    content.clear();
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        err = errno;
        return false;
    }

    char buffer[4096];
    for (;;) {
        const ssize_t n = ::read(fd, buffer, sizeof(buffer));
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            err = errno;
            ::close(fd);
            return false;
        }
        if (n == 0) {
            break;
        }
        content.append(buffer, static_cast<std::size_t>(n));
    }
    ::close(fd);
    err = 0;
    return true;
}

/// 读取 exe 链接；失败返回 false 并清空 target
bool read_exe(const std::string& path, std::string& target)
{
    target.clear();
    std::vector<char> buffer(256);
    for (;;) {
        const ssize_t n = ::readlink(path.c_str(), buffer.data(), buffer.size());
        if (n < 0) {
            return false;
        }
        if (static_cast<std::size_t>(n) < buffer.size()) {
            target.assign(buffer.data(), static_cast<std::size_t>(n));
            return true;
        }
        if (buffer.size() >= 65536) {
            return false;
        }
        buffer.resize(buffer.size() * 2);
    }
}

/// stat 中本次需要的字段
struct ParsedStat {
    char state          = 0;
    uint32_t ppid       = 0;
    uint64_t flags      = 0;
    uint64_t start_time = 0;
};

/// 解析 /proc/<pid>/stat；comm 以最后一个 ')' 为界
bool parse_stat(const std::string& content, ParsedStat& out)
{
    const std::size_t close = content.rfind(')');
    if (close == std::string::npos || content.find('(') == std::string::npos) {
        return false;
    }

    std::vector<std::string_view> fields;
    std::size_t i = close + 1;
    while (i < content.size()) {
        while (i < content.size() &&
               (content[i] == ' ' || content[i] == '\t' || content[i] == '\n')) {
            ++i;
        }
        if (i >= content.size()) {
            break;
        }
        const std::size_t begin = i;
        while (i < content.size() && content[i] != ' ' && content[i] != '\t' &&
               content[i] != '\n') {
            ++i;
        }
        fields.emplace_back(content.data() + begin, i - begin);
    }

    // comm 之后字段 3 起算：ppid 下标 1、flags 下标 6、starttime 下标 19
    constexpr std::size_t kFieldCount = 20;
    if (fields.size() < kFieldCount || fields[0].size() != 1) {
        return false;
    }

    std::uint64_t ppid_value  = 0;
    std::uint64_t flags_value = 0;
    std::uint64_t start_time  = 0;
    if (!parse_u64(fields[1], ppid_value) || ppid_value > UINT32_MAX) {
        return false;
    }
    if (!parse_u64(fields[6], flags_value) ||
        !parse_u64(fields[19], start_time)) {
        return false;
    }

    out.state      = fields[0][0];
    out.ppid       = static_cast<uint32_t>(ppid_value);
    out.flags      = flags_value;
    out.start_time = start_time;
    return true;
}

}  // namespace

ProcessSnapshotReader::ProcessSnapshotReader(std::string proc_root)
    : proc_root_(std::move(proc_root))
{
}

hng::ProcessSnapshot ProcessSnapshotReader::read() const
{
    hng::ProcessSnapshot snapshot;

    DIR* dir = ::opendir(proc_root_.c_str());
    if (dir == nullptr) {
        snapshot.anomalies.proc_available = false;
        snapshot.batch.complete           = false;
        return snapshot;
    }

    std::vector<hng::ProcessSeedEntry> entries;
    std::unordered_map<uint32_t, uint64_t> start_times;

    for (;;) {
        errno              = 0;
        const dirent* item = ::readdir(dir);
        if (item == nullptr) {
            if (errno != 0) {
                snapshot.batch.complete = false;
            }
            break;
        }

        const char* name = item->d_name;
        if (!all_digits(name)) {
            continue;
        }
        const uint64_t pid_value = std::strtoull(name, nullptr, 10);
        if (pid_value > UINT32_MAX) {
            continue;
        }
        const uint32_t pid = static_cast<uint32_t>(pid_value);
        ++snapshot.anomalies.proc_seen;

        const std::string base = proc_root_ + "/" + name;
        std::string content;
        int err = 0;
        if (!read_file(base + "/stat", content, err)) {
            if (err != ENOENT) {
                ++snapshot.anomalies.stat_parse_failed;
            }
            continue;
        }

        ParsedStat stat;
        if (!parse_stat(content, stat)) {
            ++snapshot.anomalies.stat_parse_failed;
            continue;
        }
        if (stat.state == 'Z' || stat.state == 'X') {
            ++snapshot.anomalies.zombie_skipped;
            continue;
        }
        if ((stat.flags & kPfKthread) != 0) {
            ++snapshot.anomalies.kthread_skipped;
            continue;
        }

        hng::ProcessSeedEntry entry;
        entry.process.pid            = pid;
        entry.process.pid_start_time = stat.start_time;
        entry.ppid                   = stat.ppid;
        std::string exe;
        if (!read_exe(base + "/exe", exe)) {
            ++snapshot.anomalies.exe_unreadable;
        }
        entry.exe = std::move(exe);

        entries.push_back(std::move(entry));
        start_times.emplace(pid, stat.start_time);
    }
    ::closedir(dir);

    for (hng::ProcessSeedEntry& entry : entries) {
        if (entry.ppid == 0) {
            continue;
        }
        const auto it = start_times.find(entry.ppid);
        if (it == start_times.end()) {
            ++snapshot.anomalies.parent_missing;
            continue;
        }
        entry.ppid_start_time = it->second;
    }

    snapshot.batch.entries = std::move(entries);
    return snapshot;
}
