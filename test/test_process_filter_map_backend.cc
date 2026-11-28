/**
 * @file
 * @brief 真实 fd 复制与 syscall 替身驱动的 BpfMapWriter 适配器边界测试。
 * @note 仅测试程序包装 syscall；生产实现不含替身。
 */
#include "agent/bpf_loader/include/bpf_map.hpp"
#include "agent/role_filter/include/process_filter_map.hpp"
#include "kernel/include/role_filter_types.h"
#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <fcntl.h>
#include <linux/bpf.h>
#include <stdexcept>
#include <sys/syscall.h>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace {
int checks     = 0;
bool valid_abi = true, initially_empty = true, valid_calls = true;
int fail_update_fd = -1, fail_delete_fd = -1;
int info_calls = 0;
std::vector<int> next_key_fds;
std::unordered_map<int, std::unordered_set<hng::Process>> maps;
void require(bool condition)
{
    ++checks;
    if (!condition) throw std::runtime_error("BPF 后端检查失败");
}
template <class Action>
void rejects(Action action, int expected)
{
    try {
        action();
    }
    catch (const std::system_error& error) {
        require(error.code().value() == expected);
        return;
    }
    require(false);
}
long error(int code)
{
    errno = code;
    return -1;
}
bool is_open(int fd) { return fcntl(fd, F_GETFD) >= 0; }
int lowest_free_fd()
{
    for (int fd = 0; fd < 1024; ++fd)
        if (fcntl(fd, F_GETFD) < 0 && errno == EBADF) return fd;
    return -1;
}
}  // namespace

extern "C" long __wrap_syscall(long number, ...)
{
    va_list args;
    va_start(args, number);
    int command = va_arg(args, int);
    auto* attr  = va_arg(args, union bpf_attr*);
    auto size   = va_arg(args, std::size_t);
    va_end(args);
    if (number != SYS_bpf || attr == nullptr || size != sizeof(*attr)) {
        valid_calls = false;
        return error(EINVAL);
    }
    if (command == BPF_OBJ_GET_INFO_BY_FD) {
        ++info_calls;
        const int fd = static_cast<int>(attr->info.bpf_fd);
        if (fd < 0 || !is_open(fd)) return error(EBADF);
        auto* info        = reinterpret_cast<bpf_map_info*>(attr->info.info);
        *info             = {};
        info->type        = valid_abi ? BPF_MAP_TYPE_HASH : BPF_MAP_TYPE_ARRAY;
        info->key_size    = sizeof(hng_role_filter_key);
        info->value_size  = sizeof(__u32);
        info->max_entries = HNG_ROLE_FILTER_MAX_ENTRIES;
        return 0;
    }
    if (command == BPF_MAP_GET_NEXT_KEY) {
        next_key_fds.push_back(static_cast<int>(attr->map_fd));
        return initially_empty ? error(ENOENT) : 0;
    }
    auto* key = reinterpret_cast<const hng_role_filter_key*>(attr->key);
    if (!key || key->reserved != 0) {
        valid_calls = false;
        return error(EINVAL);
    }
    const int fd = static_cast<int>(attr->map_fd);
    const hng::Process process{key->tgid, key->start_time};
    if (command == BPF_MAP_UPDATE_ELEM) {
        if (fd == fail_update_fd) return error(ENOSPC);
        auto* value = reinterpret_cast<const __u32*>(attr->value);
        if (!value || *value != 1 || attr->flags != BPF_ANY) {
            valid_calls = false;
            return error(EINVAL);
        }
        maps[fd].insert(process);
        return 0;
    }
    if (command == BPF_MAP_DELETE_ELEM) {
        if (fd == fail_delete_fd) return error(EIO);
        return maps[fd].erase(process) ? 0 : error(ENOENT);
    }
    valid_calls = false;
    return error(EINVAL);
}

int main()
{
    try {
        rejects([] { hng::BpfMapView::from_fd(-1); }, EBADF);
        rejects([] { hng::make_bpf_process_filter_map({}); }, EINVAL);

        int pipe_fds[2];
        if (pipe(pipe_fds)) throw std::runtime_error("创建 fd 测试管道失败");
        struct Pipe {
            int* fds;
            ~Pipe()
            {
                for (int i = 0; i < 2; ++i)
                    if (fds[i] >= 0) close(fds[i]);
            }
        } cleanup{pipe_fds};

        valid_abi                      = false;
        const hng::BpfMapView bad_view = hng::BpfMapView::from_fd(pipe_fds[0]);
        const int info_before          = info_calls;
        int expected_copy              = lowest_free_fd();
        rejects([&] { hng::make_bpf_process_filter_map({bad_view}); }, EINVAL);
        require(info_calls == info_before);
        require(expected_copy >= 0 && !is_open(expected_copy));
        require(is_open(pipe_fds[0]) && is_open(pipe_fds[1]));

        valid_abi                         = true;
        const hng::BpfMapView first_view  = hng::BpfMapView::from_fd(pipe_fds[0]);
        const hng::BpfMapView second_view = hng::BpfMapView::from_fd(pipe_fds[1]);
        require(first_view.fd() == pipe_fds[0]);
        require(second_view.fd() == pipe_fds[1]);

        initially_empty = false;
        next_key_fds.clear();
        expected_copy = lowest_free_fd();
        rejects([&] { hng::make_bpf_process_filter_map({first_view}); }, EBUSY);
        require(next_key_fds.size() == 1 && next_key_fds.back() == expected_copy);
        require(expected_copy >= 0 && !is_open(expected_copy));
        initially_empty = true;

        next_key_fds.clear();
        const int factory_info_before = info_calls;
        auto backend =
            hng::make_bpf_process_filter_map({first_view, second_view});
        require(info_calls == factory_info_before);
        require(next_key_fds.size() == 2);
        const int copy0 = next_key_fds[0];
        const int copy1 = next_key_fds[1];
        require(copy0 != pipe_fds[0] && copy1 != pipe_fds[1]);
        require(copy0 != copy1);
        require((fcntl(copy0, F_GETFD) & FD_CLOEXEC) != 0);
        require((fcntl(copy1, F_GETFD) & FD_CLOEXEC) != 0);
        close(pipe_fds[0]);
        pipe_fds[0] = -1;
        close(pipe_fds[1]);
        pipe_fds[1] = -1;
        require(is_open(copy0) && is_open(copy1));

        const hng::Process process{123, 456};
        require(!backend->erase(process));
        fail_update_fd = copy0;
        require(backend->ignore(process).value() == ENOSPC);
        require(!maps[copy0].count(process) && maps[copy1].count(process));
        fail_update_fd = -1;
        require(!backend->ignore(process));
        require(!backend->ignore(process));
        require(maps[copy0].count(process) && maps[copy1].count(process));
        fail_delete_fd = copy0;
        require(backend->erase(process).value() == EIO);
        require(maps[copy0].count(process) && !maps[copy1].count(process));
        fail_delete_fd = -1;
        require(!backend->erase(process));
        require(!backend->erase(process));
        require(backend->ignore({0, 0}).value() == EINVAL);
        require(backend->erase({0, 0}).value() == EINVAL);
        backend.reset();
        require(!is_open(copy0) && !is_open(copy1));
        require(valid_calls);
        std::printf(
            "PASS: process filter map backend, %d checks (syscall mocks)\n",
            checks);
        return 0;
    }
    catch (const std::exception& error) {
        std::fprintf(stderr, "FAIL: %s\n", error.what());
        return 1;
    }
}
