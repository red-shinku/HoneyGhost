/**
 * @file apparmor_profile.cc
 * @brief 切到运行期 AppArmor profile 的实现
 * @author red_shinku
 * @date 2026.11.10
 */

#include "agent/assembly/src/apparmor_profile.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <string>

#include "agent/util/include/log.hpp"

namespace hng {
namespace detail {

namespace {

/// 调用线程自己的 AppArmor 标签；宿主没有 AppArmor 时不存在
/// @note 必须走 thread-self：/proc/self 指向线程组组长，非组长线程写它会被内核
///       以 EACCES 拒绝
constexpr const char* kAttributePath = "/proc/thread-self/attr/current";
/// 入口 profile 名，与 deploy/docker/apparmor/hng-agent 一致
constexpr const char* kEntryProfile  = "hng-agent";
/// 运行期 profile 名
constexpr const char* kSteadyProfile = "hng-agent-steady";
/// 切换命令；内核按 "命令 参数" 解析
constexpr const char* kChangeCommand = "changeprofile hng-agent-steady";

/// 当前线程是否处于入口 profile
bool in_entry_profile()
{
    char buffer[128] = {};
    const int fd     = ::open(kAttributePath, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return false;
    }
    const ssize_t read_size = ::read(fd, buffer, sizeof(buffer) - 1);
    ::close(fd);
    if (read_size <= 0) {
        return false;
    }
    // 形如 "hng-agent (enforce)"：profile 名到第一个空格为止
    std::string label(buffer, static_cast<std::size_t>(read_size));
    const std::size_t space = label.find(' ');
    if (space != std::string::npos) {
        label.resize(space);
    }
    return label == kEntryProfile;
}

}  // namespace

bool enter_steady_profile()
{
    if (!in_entry_profile()) {
        return true;
    }

    const int fd = ::open(kAttributePath, O_WRONLY | O_CLOEXEC);
    if (fd < 0) {
        HNG_LOG_ERROR("failed to open {}: {}", kAttributePath,
                      std::strerror(errno));
        return false;
    }
    const std::size_t length = std::strlen(kChangeCommand);
    const ssize_t written    = ::write(fd, kChangeCommand, length);
    const int write_error    = errno;
    ::close(fd);
    if (written != static_cast<ssize_t>(length)) {
        HNG_LOG_ERROR("failed to switch to {}: {}", kSteadyProfile,
                      std::strerror(write_error));
        return false;
    }
    HNG_LOG_DEBUG("apparmor profile switched to {}", kSteadyProfile);
    return true;
}

}  // namespace detail
}  // namespace hng
