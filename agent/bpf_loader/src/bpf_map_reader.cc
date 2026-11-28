/**
 * @file bpf_map_reader.cc
 * @brief BpfMapReader 的 libbpf 实现。
 */

#include "agent/bpf_loader/include/bpf_map_reader.hpp"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <unistd.h>

#include <cerrno>
#include <cstddef>
#include <memory>
#include <new>
#include <utility>

namespace hng {

namespace {

/// @brief 析构时关闭 fd 的局部守卫
class FdGuard {
   public:
    explicit FdGuard(int fd) noexcept : fd_(fd) {}

    ~FdGuard()
    {
        if (fd_ >= 0) {
            ::close(fd_);
        }
    }

    FdGuard(const FdGuard&)            = delete;
    FdGuard& operator=(const FdGuard&) = delete;

    int release() noexcept
    {
        const int fd = fd_;
        fd_          = -1;
        return fd;
    }

   private:
    int fd_;
};

bool supports_percpu_sum(std::uint32_t type) noexcept
{
    return type == BPF_MAP_TYPE_PERCPU_ARRAY ||
           type == BPF_MAP_TYPE_PERCPU_HASH ||
           type == BPF_MAP_TYPE_LRU_PERCPU_HASH;
}

}  // namespace

struct BpfMapReader::Impl {
    Impl(int fd, BpfMapSpec spec) noexcept : fd(fd), spec(spec) {}

    ~Impl()
    {
        if (fd >= 0) {
            ::close(fd);
        }
    }

    Impl(const Impl&)            = delete;
    Impl& operator=(const Impl&) = delete;

    int fd;
    BpfMapSpec spec;
};

BpfMapReader::BpfMapReader(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}

BpfMapReader::~BpfMapReader()                                  = default;

BpfMapReader::BpfMapReader(BpfMapReader&&) noexcept            = default;

BpfMapReader& BpfMapReader::operator=(BpfMapReader&&) noexcept = default;

std::unique_ptr<BpfMapReader> BpfMapReader::create(BpfMapView view,
                                                   BpfMapSpec expected)
{
    const int copy = ::fcntl(view.fd(), F_DUPFD_CLOEXEC, 0);
    if (copy < 0) {
        throw std::system_error(errno, std::generic_category(),
                                "duplicate BPF map fd");
    }
    FdGuard guard(copy);

    if (expected != view.spec()) {
        throw std::system_error(EINVAL, std::generic_category(),
                                "BPF map ABI mismatch");
    }

    auto impl = std::make_unique<Impl>(guard.release(), expected);
    return std::unique_ptr<BpfMapReader>(new BpfMapReader(std::move(impl)));
}

std::error_code BpfMapReader::lookup(const void* key, void* value) const noexcept
{
    if (impl_ == nullptr) {
        return {EINVAL, std::generic_category()};
    }
    if (::bpf_map_lookup_elem(impl_->fd, key, value) < 0) {
        return {errno, std::generic_category()};
    }
    return {};
}

std::error_code BpfMapReader::sum_percpu_u64(const void* key,
                                             std::uint64_t& total) const noexcept
{
    if (impl_ == nullptr) {
        return {EINVAL, std::generic_category()};
    }
    if (!supports_percpu_sum(impl_->spec.type) ||
        impl_->spec.value_size != sizeof(std::uint64_t)) {
        return {EINVAL, std::generic_category()};
    }

    const int cpu_count = ::libbpf_num_possible_cpus();
    if (cpu_count <= 0) {
        if (cpu_count == 0) {
            return {EINVAL, std::generic_category()};
        }
        return {-cpu_count, std::generic_category()};
    }

    std::unique_ptr<std::uint64_t[]> values(
        new (std::nothrow) std::uint64_t[static_cast<std::size_t>(cpu_count)]);
    if (values == nullptr) {
        return {ENOMEM, std::generic_category()};
    }
    if (::bpf_map_lookup_elem(impl_->fd, key, values.get()) < 0) {
        return {errno, std::generic_category()};
    }

    std::uint64_t sum = 0;
    for (int cpu = 0; cpu < cpu_count; ++cpu) {
        sum += values[static_cast<std::size_t>(cpu)];
    }
    total = sum;
    return {};
}

}  // namespace hng
