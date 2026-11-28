/**
 * @file test_bpf_map_reader.cc
 * @brief BpfMapReader 的 syscall 与 libbpf 替身边界测试。
 * @note 仅测试程序包装 syscall、bpf_map_lookup_elem 与
 *       libbpf_num_possible_cpus；生产实现不含替身。
 */

#include "agent/bpf_loader/include/bpf_map_reader.hpp"

#include <cerrno>
#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <fcntl.h>
#include <linux/bpf.h>
#include <stdexcept>
#include <sys/syscall.h>
#include <unistd.h>

namespace {

int checks       = 0;
bool valid_calls = true;
hng::BpfMapSpec map_spec{BPF_MAP_TYPE_PERCPU_ARRAY, sizeof(std::uint32_t),
                         sizeof(std::uint64_t), 16};
bool lookup_fail               = false;
int lookup_errno               = ENOENT;
int lookup_calls               = 0;
int lookup_fd                  = -1;
const void* lookup_key         = nullptr;
std::uint64_t scalar_value     = 0;
std::uint64_t percpu_values[8] = {};
bool per_cpu_result            = false;
int cpu_count                  = 1;

void require(bool condition)
{
    ++checks;
    if (!condition) {
        throw std::runtime_error("BPF map reader 检查失败");
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
    if (command != BPF_OBJ_GET_INFO_BY_FD) {
        valid_calls = false;
        return error(EINVAL);
    }

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

extern "C" int __wrap_bpf_map_lookup_elem(int fd, const void* key, void* value)
{
    ++lookup_calls;
    lookup_fd  = fd;
    lookup_key = key;
    if (lookup_fail) {
        errno = lookup_errno;
        return -1;
    }
    if (value == nullptr) {
        valid_calls = false;
        errno       = EINVAL;
        return -1;
    }
    if (per_cpu_result) {
        auto* cells = static_cast<std::uint64_t*>(value);
        for (int cpu = 0; cpu < cpu_count; ++cpu) {
            cells[cpu] = percpu_values[cpu];
        }
    }
    else {
        *static_cast<std::uint64_t*>(value) = scalar_value;
    }
    return 0;
}

extern "C" int __wrap_libbpf_num_possible_cpus() { return cpu_count; }

int main()
{
    try {
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

        hng::BpfMapView view       = hng::BpfMapView::from_fd(pipe_fds[0]);
        hng::BpfMapSpec wrong_spec = map_spec;
        wrong_spec.max_entries     = 8;
        const int mismatch_copy    = lowest_free_fd();
        rejects([&] { hng::BpfMapReader::create(view, wrong_spec); }, EINVAL);
        require(mismatch_copy >= 0 && !is_open(mismatch_copy));

        const int copy = lowest_free_fd();
        auto reader    = hng::BpfMapReader::create(view, map_spec);
        require(copy >= 0 && is_open(copy));

        const std::uint32_t key = 7;
        std::uint64_t value     = 0;
        scalar_value            = 123;
        require(!reader->lookup(&key, &value));
        require(value == 123);
        require(lookup_calls == 1 && lookup_fd == copy);
        require(lookup_key == &key);
        require((::fcntl(copy, F_GETFD) & FD_CLOEXEC) != 0);

        lookup_fail  = true;
        lookup_errno = ENODEV;
        value        = 456;
        require(reader->lookup(&key, &value).value() == ENODEV);
        require(value == 456);
        lookup_fail         = false;

        per_cpu_result      = true;
        cpu_count           = 4;
        percpu_values[0]    = 1;
        percpu_values[1]    = 2;
        percpu_values[2]    = 3;
        percpu_values[3]    = 4;
        std::uint64_t total = 0;
        require(!reader->sum_percpu_u64(&key, total));
        require(total == 10);
        require(lookup_fd == copy);

        lookup_fail  = true;
        lookup_errno = EIO;
        total        = 777;
        require(reader->sum_percpu_u64(&key, total).value() == EIO);
        require(total == 777);
        lookup_fail = false;

        cpu_count   = -ENODEV;
        total       = 777;
        require(reader->sum_percpu_u64(&key, total).value() == ENODEV);
        require(total == 777);
        cpu_count = 1;

        reader.reset();
        require(!is_open(copy));

        const int lookup_before = lookup_calls;
        map_spec = hng::BpfMapSpec{BPF_MAP_TYPE_HASH, sizeof(std::uint32_t),
                                   sizeof(std::uint64_t), 16};
        hng::BpfMapView hash_view = hng::BpfMapView::from_fd(pipe_fds[0]);
        auto hash_reader = hng::BpfMapReader::create(hash_view, map_spec);
        total            = 777;
        require(hash_reader->sum_percpu_u64(&key, total).value() == EINVAL);
        require(total == 777);
        require(lookup_calls == lookup_before);
        hash_reader.reset();

        map_spec =
            hng::BpfMapSpec{BPF_MAP_TYPE_PERCPU_ARRAY, sizeof(std::uint32_t),
                            sizeof(std::uint32_t), 16};
        hng::BpfMapView narrow_view = hng::BpfMapView::from_fd(pipe_fds[0]);
        auto narrow_reader = hng::BpfMapReader::create(narrow_view, map_spec);
        total              = 777;
        require(narrow_reader->sum_percpu_u64(&key, total).value() == EINVAL);
        require(total == 777);
        require(lookup_calls == lookup_before);
        narrow_reader.reset();

        require(valid_calls);
        std::printf("PASS: BPF map reader behavior, %d checks\n", checks);
        return 0;
    }
    catch (const std::exception& error) {
        std::fprintf(stderr, "FAIL: %s\n", error.what());
        return 1;
    }
}
