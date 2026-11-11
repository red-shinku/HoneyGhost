/**
 * @file capability_drop.cc
 * @brief 清空权能的实现
 * @author red_shinku
 * @date 2026.11.10
 */

#include "agent/assembly/src/capability_drop.hpp"

#include <linux/capability.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

#include "agent/util/include/log.hpp"

namespace hng {
namespace detail {

namespace {

/// kernel 接受的最大权能编号
constexpr unsigned kLastCapability = 63;

}  // namespace

bool drop_capabilities()
{
    // 先清 bounding set：此后 execve 也无法把权能带回来。缺 CAP_SETPCAP 时
    // 这些调用失败，降级为只清 effective/permitted/inheritable。
    for (unsigned capability = 0; capability <= kLastCapability; ++capability) {
        (void)::prctl(PR_CAPBSET_DROP, capability, 0, 0, 0);
    }

    struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct data[2]  = {{0, 0, 0}, {0, 0, 0}};
    if (::syscall(SYS_capset, &header, data) != 0) {
        HNG_LOG_ERROR("failed to drop capabilities: {}", std::strerror(errno));
        return false;
    }
    HNG_LOG_DEBUG("capabilities dropped");
    return true;
}

}  // namespace detail
}  // namespace hng
