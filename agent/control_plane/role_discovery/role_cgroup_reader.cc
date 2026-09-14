/**
 * @file role_cgroup_reader.cc
 * @brief cgroup v2 递归枚举与 stat 解析实现
 * @author red_shinku
 * @date 2026.9.11
 */

#include "./include/role_cgroup_reader.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <sstream>

namespace hng {
namespace role {

namespace {

/// /proc/<pid>/stat 中字段 22（starttime）相对最后一个 ')' 之后首个 token 的下标
/// （最后一个 ')' 之后的首个 token 是字段 3 state）
constexpr int kStartTimeTokenIndex = 22 - 3;

/// 严格解析十进制无符号整数：空串、含非数字字符、超出 uint64 均为失败
std::optional<uint64_t> parse_u64(const std::string& text)
{
    if (text.empty()) {
        return std::nullopt;
    }
    uint64_t value = 0;
    for (char c : text) {
        if (c < '0' || c > '9') {
            return std::nullopt;
        }
        const uint64_t digit = static_cast<uint64_t>(c - '0');
        if (value > (UINT64_MAX - digit) / 10) {
            return std::nullopt;
        }
        value = value * 10 + digit;
    }
    return value;
}

/// 严格解析 cgroup.procs 的一行：pid 为正的 uint32
std::optional<uint32_t> parse_pid(const std::string& text)
{
    std::optional<uint64_t> value = parse_u64(text);
    if (!value || *value == 0 || *value > UINT32_MAX) {
        return std::nullopt;
    }
    return static_cast<uint32_t>(*value);
}

/// 读 <dir>/cgroup.procs，追加其中的 pid；文件缺失或不可读时不做任何事
void collect_pids(const std::filesystem::path& dir, std::vector<uint32_t>& out)
{
    std::ifstream procs(dir / "cgroup.procs");
    if (!procs) {
        return;
    }
    std::string line;
    while (std::getline(procs, line)) {
        if (std::optional<uint32_t> pid = parse_pid(line)) {
            out.push_back(*pid);
        }
    }
}

/// 读 <proc_root>/<pid>/stat 得到进程；进程已退出（文件打不开）或 stat
/// 不可解析时为空
std::optional<hng::Process> read_process(const std::string& proc_root,
                                         uint32_t pid)
{
    std::ifstream stat(std::filesystem::path(proc_root) / std::to_string(pid) /
                       "stat");
    if (!stat) {
        return std::nullopt;
    }
    std::ostringstream buffer;
    buffer << stat.rdbuf();
    std::optional<uint64_t> start_time =
        RoleCgroupReader::parse_start_time(buffer.str());
    if (!start_time) {
        return std::nullopt;
    }
    return hng::Process{pid, *start_time};
}

/// 子目录判定：按符号链接自身的类型判断，不下潜符号链接
/// （cgroupfs 无符号链接；不跟随可避免遍历成环）
bool is_real_subdir(const std::filesystem::directory_entry& entry)
{
    std::error_code ec;
    const std::filesystem::file_status status = entry.symlink_status(ec);
    return !ec && std::filesystem::is_directory(status);
}

/// 还原 mountinfo 路径中的八进制转义（如 \040 表示空格）
std::string unescape_mount_field(const std::string& field)
{
    std::string out;
    out.reserve(field.size());
    for (std::size_t i = 0; i < field.size(); ++i) {
        if (field[i] == '\\' && i + 3 < field.size() && field[i + 1] >= '0' &&
            field[i + 1] <= '7' && field[i + 2] >= '0' && field[i + 2] <= '7' &&
            field[i + 3] >= '0' && field[i + 3] <= '7') {
            out.push_back(static_cast<char>((field[i + 1] - '0') * 64 +
                                            (field[i + 2] - '0') * 8 +
                                            (field[i + 3] - '0')));
            i += 3;
            continue;
        }
        out.push_back(field[i]);
    }
    return out;
}

/// 探测 cgroup v2 挂载点：取 mountinfo 中文件系统类型为 cgroup2 的那条
std::string detect_cgroup_root()
{
    std::ifstream mountinfo("/proc/self/mountinfo");
    std::string line;
    while (std::getline(mountinfo, line)) {
        std::istringstream fields(line);
        std::vector<std::string> tokens;
        std::string token;
        while (fields >> token) {
            tokens.push_back(token);
        }
        // 字段：id parent major:minor root 挂载点 选项 ... - 文件系统类型 来源
        if (tokens.size() < 9) {
            continue;
        }
        std::size_t separator = tokens.size();
        for (std::size_t i = 6; i < tokens.size(); ++i) {
            if (tokens[i] == "-") {
                separator = i;
                break;
            }
        }
        if (separator + 1 >= tokens.size()) {
            continue;
        }
        if (tokens[separator + 1] == "cgroup2") {
            std::string mount_point = unescape_mount_field(tokens[4]);
            while (mount_point.size() > 1 && mount_point.back() == '/') {
                mount_point.pop_back();
            }
            return mount_point;
        }
    }
    return "/sys/fs/cgroup";
}

}  // namespace

const std::string& RoleCgroupReader::root()
{
    static const std::string detected = detect_cgroup_root();
    return detected;
}

std::string RoleCgroupReader::absolute(const std::string& cgroup_path)
{
    if (cgroup_path.empty() || cgroup_path.front() != '/') {
        return cgroup_path;
    }
    const std::string& base = root();
    if (cgroup_path == base ||
        cgroup_path.compare(0, base.size() + 1, base + "/") == 0) {
        return cgroup_path;  // 已是绝对路径
    }
    return base + cgroup_path;
}

std::optional<uint64_t> RoleCgroupReader::parse_start_time(
    const std::string& stat_content)
{
    // 字段 2 是进程名，括号包裹且可能含空格与括号，故从最后一个 ')'
    // 之后开始切字段
    const std::size_t rparen = stat_content.rfind(')');
    if (rparen == std::string::npos) {
        return std::nullopt;
    }

    std::istringstream fields(stat_content.substr(rparen + 1));
    std::string token;
    for (int i = 0; i <= kStartTimeTokenIndex; ++i) {
        if (!(fields >> token)) {
            return std::nullopt;  // 字段不足（内容被截断等）
        }
    }
    return parse_u64(token);
}

std::optional<std::string> RoleCgroupReader::read_process_cgroup(
    uint32_t pid, const std::string& proc_root)
{
    std::ifstream cgroup(std::filesystem::path(proc_root) / std::to_string(pid) /
                         "cgroup");
    if (!cgroup) {
        return std::nullopt;
    }

    std::string line;
    while (std::getline(cgroup, line)) {
        // 每行形态 <层级>:<控制器列表>:<路径>。v2 统一层次是层级 0 且控制器
        // 列表为空，即 "0::<路径>"；v1 的行都有控制器名字，据此排除
        const std::size_t hierarchy_end = line.find(':');
        if (hierarchy_end == std::string::npos) {
            continue;
        }
        const std::size_t controllers_end = line.find(':', hierarchy_end + 1);
        if (controllers_end == std::string::npos) {
            continue;
        }
        if (line.compare(0, hierarchy_end, "0") != 0 ||
            controllers_end != hierarchy_end + 1) {
            continue;
        }
        return line.substr(controllers_end + 1);
    }
    return std::nullopt;
}

std::vector<hng::Process> RoleCgroupReader::read(const std::string& cgroup_path,
                                                 const std::string& proc_root)
{
    std::vector<hng::Process> result;

    std::error_code ec;
    if (!std::filesystem::is_directory(cgroup_path, ec) || ec) {
        return result;  // 路径不存在、非目录或不可访问
    }

    std::vector<std::filesystem::path> pending{
        std::filesystem::path(cgroup_path)};
    while (!pending.empty()) {
        const std::filesystem::path dir = pending.back();
        pending.pop_back();

        std::vector<uint32_t> pids;
        collect_pids(dir, pids);
        for (uint32_t pid : pids) {
            if (std::optional<hng::Process> process =
                    read_process(proc_root, pid)) {
                result.push_back(*process);
            }
        }

        std::filesystem::directory_iterator entries(dir, ec);
        if (ec) {
            continue;  // 目录枚举中途被删除或不可读：保留已收集结果
        }
        for (const std::filesystem::directory_entry& entry : entries) {
            if (is_real_subdir(entry)) {
                pending.push_back(entry.path());
            }
        }
    }

    std::sort(result.begin(), result.end(),
              [](const hng::Process& a, const hng::Process& b) {
                  return a.pid != b.pid ? a.pid < b.pid
                                        : a.pid_start_time < b.pid_start_time;
              });
    return result;
}

}  // namespace role
}  // namespace hng
