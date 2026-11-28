/**
 * @file bpf_map.cc
 * @brief BpfMapView 与 BpfMapWriter 的 bpf syscall 实现。
 */

#include "agent/bpf_loader/include/bpf_map.hpp"
#include "agent/bpf_loader/include/bpf_map_writer.hpp"

#include <fcntl.h>
#include <linux/bpf.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <utility>
#include <vector>

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

[[noreturn]] void throw_errno(const char* context)
{
    throw std::system_error(errno, std::generic_category(), context);
}

BpfMapSpec read_map_spec(int fd)
{
    if (fd < 0) {
        throw std::system_error(EBADF, std::generic_category(),
                                "invalid BPF map fd");
    }
    bpf_map_info info{};
    union bpf_attr attr{};
    attr.info.bpf_fd   = fd;
    attr.info.info_len = sizeof(info);
    attr.info.info     = reinterpret_cast<__u64>(&info);
    if (::syscall(SYS_bpf, BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr)) < 0) {
        throw_errno("BPF_OBJ_GET_INFO_BY_FD failed");
    }
    return BpfMapSpec{info.type, info.key_size, info.value_size,
                      info.max_entries};
}

}  // namespace

bool BpfMapSpec::operator==(const BpfMapSpec& other) const noexcept
{
    return type == other.type && key_size == other.key_size &&
           value_size == other.value_size && max_entries == other.max_entries;
}

bool BpfMapSpec::operator!=(const BpfMapSpec& other) const noexcept
{
    return !(*this == other);
}

BpfMapView::BpfMapView(int fd, BpfMapSpec spec) noexcept : fd_(fd), spec_(spec) {}

BpfMapView BpfMapView::from_fd(int fd)
{
    return BpfMapView(fd, read_map_spec(fd));
}

int BpfMapView::fd() const noexcept { return fd_; }

const BpfMapSpec& BpfMapView::spec() const noexcept { return spec_; }

struct BpfMapWriter::Impl {
    explicit Impl(int fd) noexcept : fd(fd) {}

    ~Impl()
    {
        if (fd >= 0) {
            ::close(fd);
        }
    }

    Impl(const Impl&)            = delete;
    Impl& operator=(const Impl&) = delete;

    int fd;
};

BpfMapWriter::BpfMapWriter(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}

BpfMapWriter::~BpfMapWriter()                                  = default;

BpfMapWriter::BpfMapWriter(BpfMapWriter&&) noexcept            = default;

BpfMapWriter& BpfMapWriter::operator=(BpfMapWriter&&) noexcept = default;

std::unique_ptr<BpfMapWriter> BpfMapWriter::create(BpfMapView view,
                                                   BpfMapSpec expected,
                                                   Options options)
{
    const int copy = ::fcntl(view.fd(), F_DUPFD_CLOEXEC, 0);
    if (copy < 0) {
        throw_errno("duplicate BPF map fd");
    }
    FdGuard guard(copy);

    if (expected != view.spec()) {
        throw std::system_error(EINVAL, std::generic_category(),
                                "BPF map ABI mismatch");
    }

    if (options.require_empty) {
        std::vector<std::uint8_t> next_key(expected.key_size);
        union bpf_attr attr{};
        attr.map_fd   = copy;
        attr.next_key = reinterpret_cast<__u64>(next_key.data());
        if (::syscall(SYS_bpf, BPF_MAP_GET_NEXT_KEY, &attr, sizeof(attr)) == 0) {
            throw std::system_error(EBUSY, std::generic_category(),
                                    "BPF map is not empty");
        }
        if (errno != ENOENT) {
            throw_errno("BPF_MAP_GET_NEXT_KEY failed");
        }
    }

    auto impl = std::make_unique<Impl>(guard.release());
    return std::unique_ptr<BpfMapWriter>(new BpfMapWriter(std::move(impl)));
}

std::error_code BpfMapWriter::update(const void* key, const void* value) noexcept
{
    if (impl_ == nullptr) {
        return {EINVAL, std::generic_category()};
    }
    union bpf_attr attr{};
    attr.map_fd = impl_->fd;
    attr.key    = reinterpret_cast<__u64>(key);
    attr.value  = reinterpret_cast<__u64>(value);
    attr.flags  = BPF_ANY;
    if (::syscall(SYS_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr)) < 0) {
        return {errno, std::generic_category()};
    }
    return {};
}

std::error_code BpfMapWriter::erase(const void* key) noexcept
{
    if (impl_ == nullptr) {
        return {EINVAL, std::generic_category()};
    }
    union bpf_attr attr{};
    attr.map_fd = impl_->fd;
    attr.key    = reinterpret_cast<__u64>(key);
    if (::syscall(SYS_bpf, BPF_MAP_DELETE_ELEM, &attr, sizeof(attr)) < 0) {
        return {errno, std::generic_category()};
    }
    return {};
}

}  // namespace hng
