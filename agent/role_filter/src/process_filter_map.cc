/**
 * @file
 * @brief fd 复制、map ABI 校验及多探针过滤名单同步。
 * @author inless427
 */
#include "agent/role_filter/include/process_filter_map.hpp"
#include "kernel/include/role_filter_types.h"
#include <cerrno>
#include <cstddef>
#include <fcntl.h>
#include <linux/bpf.h>
#include <sys/syscall.h>
#include <unistd.h>

static_assert(sizeof(hng_role_filter_key) == 16);
static_assert(offsetof(hng_role_filter_key, start_time) == 8);

namespace hng::detail {
/** @brief 独占拥有 fd 副本的 Linux bpf syscall 后端。 */
class BpfProcessFilterMap final : public ProcessFilterMap {
   public:
    explicit BpfProcessFilterMap(const std::vector<int>& fds)
    {
        if (fds.empty())
            throw std::system_error(EINVAL, std::generic_category(),
                                    "名单 map fd 为空");
        fds_.reserve(fds.size());
        try {
            for (int fd : fds) {
                int copy = fcntl(fd, F_DUPFD_CLOEXEC, 0);
                if (copy < 0) fail("复制名单 map fd");
                fds_.push_back(copy);
                bpf_map_info info{};
                union bpf_attr attr{};
                attr.info.bpf_fd   = copy;
                attr.info.info_len = sizeof(info);
                attr.info.info     = reinterpret_cast<__u64>(&info);
                if (syscall(SYS_bpf, BPF_OBJ_GET_INFO_BY_FD, &attr,
                            sizeof(attr)) < 0)
                    fail("读取名单 map 信息");
                if (info.type != BPF_MAP_TYPE_HASH ||
                    info.key_size != sizeof(hng_role_filter_key) ||
                    info.value_size != sizeof(__u32) ||
                    info.max_entries != HNG_ROLE_FILTER_MAX_ENTRIES)
                    throw std::system_error(EINVAL, std::generic_category(),
                                            "名单 map ABI 不匹配");
                hng_role_filter_key key{};
                attr          = {};
                attr.map_fd   = copy;
                attr.next_key = reinterpret_cast<__u64>(&key);
                if (syscall(SYS_bpf, BPF_MAP_GET_NEXT_KEY, &attr, sizeof(attr)) ==
                    0)
                    throw std::system_error(EBUSY, std::generic_category(),
                                            "名单 map 必须是新建空表");
                if (errno != ENOENT) fail("检查名单 map 是否为空");
            }
        }
        catch (...) {
            close_all();
            throw;
        }
    }
    ~BpfProcessFilterMap() override { close_all(); }
    std::error_code allow(Process process) noexcept override
    {
        return update(process, true);
    }
    std::error_code erase(Process process) noexcept override
    {
        return update(process, false);
    }

   private:
    [[noreturn]] static void fail(const char* context)
    {
        throw std::system_error(errno, std::generic_category(), context);
    }
    void close_all() noexcept
    {
        for (int fd : fds_) close(fd);
        fds_.clear();
    }
    /** @brief 尝试所有 map，忽略删除不存在条目的错误，并返回首个真实错误。 */
    std::error_code update(Process process, bool allow) noexcept
    {
        if (!process.pid || !process.pid_start_time)
            return {EINVAL, std::generic_category()};
        const hng_role_filter_key key{process.pid, 0, process.pid_start_time};
        const __u32 value = 1;
        std::error_code first;
        for (int fd : fds_) {
            union bpf_attr attr{};
            attr.map_fd = fd;
            attr.key    = reinterpret_cast<__u64>(&key);
            attr.value  = allow ? reinterpret_cast<__u64>(&value) : 0;
            attr.flags  = BPF_ANY;
            if (syscall(SYS_bpf,
                        allow ? BPF_MAP_UPDATE_ELEM : BPF_MAP_DELETE_ELEM, &attr,
                        sizeof(attr)) < 0 &&
                (allow || errno != ENOENT))
                if (!first) first = {errno, std::generic_category()};
        }
        return first;
    }
    std::vector<int> fds_;
};
}  // namespace hng::detail
namespace hng {
std::unique_ptr<ProcessFilterMap> make_bpf_process_filter_map(
    const std::vector<int>& fds)
{
    return std::make_unique<detail::BpfProcessFilterMap>(fds);
}
}  // namespace hng
