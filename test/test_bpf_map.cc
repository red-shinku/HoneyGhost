/**
 * @file test_bpf_map.cc
 * @brief BpfMapView 与 BpfMapWriter 的 bpf syscall 替身边界测试。
 * @note 仅测试程序包装 syscall；生产实现不含替身。
 */

#include "agent/bpf_loader/include/bpf_map_writer.hpp"

#include <cerrno>
#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <linux/bpf.h>
#include <stdexcept>
#include <sys/syscall.h>
#include <unistd.h>
#include <vector>

namespace {

int checks           = 0;
bool valid_calls     = true;
bool initially_empty = true;
hng::BpfMapSpec map_spec{BPF_MAP_TYPE_HASH, sizeof(std::uint64_t),
                         sizeof(std::uint64_t), 16};
int getnext_fd           = -1;
int last_map_fd          = -1;
std::uint32_t last_flags = 0;
std::vector<std::uint8_t> last_key;
std::vector<std::uint8_t> last_value;
int fail_update_fd    = -1;
int fail_update_errno = ENOSPC;
int fail_delete_fd    = -1;
int fail_delete_errno = EIO;

void require(bool condition)
{
    ++checks;
    if (!condition) {
        throw std::runtime_error("BPF map 检查失败");
    }
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

int lowest_free_fd()
{
    for (int fd = 0; fd < 1024; ++fd) {
        if (::fcntl(fd, F_GETFD) < 0 && errno == EBADF) {
            return fd;
        }
    }
    return -1;
}

bool is_open(int fd) { return ::fcntl(fd, F_GETFD) >= 0; }

void copy_field(const std::uint8_t* source, std::vector<std::uint8_t>& target,
                std::uint32_t size)
{
    target.assign(source, source + size);
}

}  // namespace

extern "C" long __wrap_syscall(long number, ...)
{
    va_list args;
    va_start(args, number);
    const int command = va_arg(args, int);
    auto* attr        = va_arg(args, union bpf_attr*);
    const auto size   = va_arg(args, std::size_t);
    va_end(args);

    if (number != SYS_bpf || attr == nullptr || size != sizeof(*attr)) {
        valid_calls = false;
        return error(EINVAL);
    }

    if (command == BPF_OBJ_GET_INFO_BY_FD) {
        const int fd = static_cast<int>(attr->info.bpf_fd);
        if (fd < 0 || ::fcntl(fd, F_GETFD) < 0) {
            return error(EBADF);
        }
        auto* info = reinterpret_cast<bpf_map_info*>(attr->info.info);
        if (info == nullptr || attr->info.info_len != sizeof(*info)) {
            valid_calls = false;
            return error(EINVAL);
        }
        *info             = {};
        info->type        = map_spec.type;
        info->key_size    = map_spec.key_size;
        info->value_size  = map_spec.value_size;
        info->max_entries = map_spec.max_entries;
        return 0;
    }

    if (command == BPF_MAP_GET_NEXT_KEY) {
        getnext_fd = static_cast<int>(attr->map_fd);
        return initially_empty ? error(ENOENT) : 0;
    }

    if (command == BPF_MAP_UPDATE_ELEM) {
        last_map_fd = static_cast<int>(attr->map_fd);
        last_flags  = attr->flags;
        if (last_map_fd == fail_update_fd) {
            return error(fail_update_errno);
        }
        if (attr->key == 0 || attr->value == 0) {
            valid_calls = false;
            return error(EINVAL);
        }
        copy_field(reinterpret_cast<const std::uint8_t*>(attr->key), last_key,
                   map_spec.key_size);
        copy_field(reinterpret_cast<const std::uint8_t*>(attr->value), last_value,
                   map_spec.value_size);
        return 0;
    }

    if (command == BPF_MAP_DELETE_ELEM) {
        last_map_fd = static_cast<int>(attr->map_fd);
        if (last_map_fd == fail_delete_fd) {
            return error(fail_delete_errno);
        }
        if (attr->key == 0) {
            valid_calls = false;
            return error(EINVAL);
        }
        copy_field(reinterpret_cast<const std::uint8_t*>(attr->key), last_key,
                   map_spec.key_size);
        return 0;
    }

    valid_calls = false;
    return error(EINVAL);
}

int main()
{
    try {
        rejects([] { hng::BpfMapView::from_fd(-1); }, EBADF);

        int pipe_fds[2];
        if (::pipe(pipe_fds) != 0) {
            throw std::runtime_error("创建 fd 测试管道失败");
        }
        struct Pipe {
            int* fds;
            ~Pipe()
            {
                for (int i = 0; i < 2; ++i) {
                    if (fds[i] >= 0) {
                        ::close(fds[i]);
                    }
                }
            }
        } cleanup{pipe_fds};

        const int closed_fd = pipe_fds[1];
        ::close(pipe_fds[1]);
        pipe_fds[1] = -1;
        rejects([&] { hng::BpfMapView::from_fd(closed_fd); }, EBADF);

        hng::BpfMapView view = hng::BpfMapView::from_fd(pipe_fds[0]);
        require(view.fd() == pipe_fds[0]);
        require(view.spec() == map_spec);
        require(view.spec() != hng::BpfMapSpec{});

        hng::BpfMapSpec wrong_spec = map_spec;
        wrong_spec.value_size      = sizeof(std::uint32_t);
        int expected_copy          = lowest_free_fd();
        rejects([&] { hng::BpfMapWriter::create(view, wrong_spec); }, EINVAL);
        require(expected_copy >= 0 && !is_open(expected_copy));

        initially_empty = false;
        expected_copy   = lowest_free_fd();
        rejects(
            [&] {
                hng::BpfMapWriter::create(view, map_spec,
                                          hng::BpfMapWriter::Options{true});
            },
            EBUSY);
        require(expected_copy >= 0 && getnext_fd == expected_copy);
        require(!is_open(expected_copy));
        initially_empty = true;

        expected_copy   = lowest_free_fd();
        auto writer     = hng::BpfMapWriter::create(view, map_spec,
                                                    hng::BpfMapWriter::Options{true});
        require(expected_copy >= 0 && getnext_fd == expected_copy);
        require(is_open(expected_copy));
        require((::fcntl(expected_copy, F_GETFD) & FD_CLOEXEC) != 0);

        const std::uint64_t key   = 42;
        const std::uint64_t value = 1;
        require(!writer->update(&key, &value));
        require(last_map_fd == expected_copy);
        require(last_flags == BPF_ANY);
        require(last_key.size() == sizeof(key) &&
                std::memcmp(last_key.data(), &key, sizeof(key)) == 0);
        require(last_value.size() == sizeof(value) &&
                std::memcmp(last_value.data(), &value, sizeof(value)) == 0);

        const std::uint64_t erase_key = 42;
        require(!writer->erase(&erase_key));
        require(last_map_fd == expected_copy);
        require(last_key.size() == sizeof(erase_key) &&
                std::memcmp(last_key.data(), &erase_key, sizeof(erase_key)) == 0);

        fail_update_fd = expected_copy;
        require(writer->update(&key, &value).value() == ENOSPC);
        fail_update_fd = -1;
        fail_delete_fd = expected_copy;
        require(writer->erase(&key).value() == EIO);
        fail_delete_errno = ENOENT;
        require(writer->erase(&key).value() == ENOENT);
        fail_delete_fd    = -1;
        fail_delete_errno = EIO;

        writer.reset();
        require(!is_open(expected_copy));

        expected_copy = lowest_free_fd();
        auto movable  = hng::BpfMapWriter::create(view, map_spec);
        require(is_open(expected_copy));
        auto moved = std::move(movable);
        require(movable == nullptr);
        require(is_open(expected_copy));
        moved.reset();
        require(!is_open(expected_copy));

        int second_pipe[2];
        if (::pipe(second_pipe) != 0) {
            throw std::runtime_error("创建第二个 fd 测试管道失败");
        }
        struct SecondPipe {
            int* fds;
            ~SecondPipe()
            {
                for (int i = 0; i < 2; ++i) {
                    if (fds[i] >= 0) {
                        ::close(fds[i]);
                    }
                }
            }
        } second_cleanup{second_pipe};
        hng::BpfMapView second_view = hng::BpfMapView::from_fd(second_pipe[0]);
        expected_copy               = lowest_free_fd();
        auto target         = hng::BpfMapWriter::create(second_view, map_spec);
        const int target_fd = expected_copy;
        expected_copy       = lowest_free_fd();
        auto source         = hng::BpfMapWriter::create(view, map_spec);
        const int source_fd = expected_copy;
        require(is_open(target_fd) && is_open(source_fd));
        target = std::move(source);
        require(source == nullptr);
        require(!is_open(target_fd));
        require(is_open(source_fd));
        target.reset();
        require(!is_open(source_fd));

        require(valid_calls);
        std::printf("PASS: BPF map syscall behavior, %d checks\n", checks);
        return 0;
    }
    catch (const std::exception& error) {
        std::fprintf(stderr, "FAIL: %s\n", error.what());
        return 1;
    }
}
