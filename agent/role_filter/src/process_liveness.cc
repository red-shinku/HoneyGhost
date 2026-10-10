#include "agent/role_filter/src/role_filter_state.hpp"

#include <cerrno>
#include <charconv>
#include <fcntl.h>
#include <sstream>
#include <unistd.h>

namespace hng::detail {
ProcessLiveness proc_liveness(Process p, const std::string& proc_root)
{
    const auto path = proc_root + "/" + std::to_string(p.pid) + "/stat";
    int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return errno == ENOENT || errno == ESRCH
        ? ProcessLiveness::DEAD : ProcessLiveness::UNKNOWN;
    struct Close { int fd; ~Close() { close(fd); } } guard{fd};
    std::string content;
    char buffer[4096];
    while (true) {
        const auto n = read(fd, buffer, sizeof(buffer));
        if (n < 0) {
            if (errno == EINTR) continue;
            return ProcessLiveness::UNKNOWN;
        }
        if (!n) break;
        content.append(buffer, static_cast<std::size_t>(n));
        if (content.size() > 16384) return ProcessLiveness::UNKNOWN;
    }
    // comm 可包含空格和 ')'：从最后一个右括号之后数 stat 字段。
    const auto end = content.rfind(')');
    if (end == std::string::npos) return ProcessLiveness::UNKNOWN;
    std::istringstream fields(content.substr(end + 1));
    std::string value;
    for (int field = 3; field <= 22; ++field) {
        if (!(fields >> value)) return ProcessLiveness::UNKNOWN;
    }
    uint64_t start = 0;
    const auto parsed = std::from_chars(value.data(), value.data() + value.size(), start);
    if (parsed.ec != std::errc() || parsed.ptr != value.data() + value.size()) return ProcessLiveness::UNKNOWN;
    return start == p.pid_start_time ? ProcessLiveness::ALIVE : ProcessLiveness::DEAD;
}
}  // namespace hng::detail
