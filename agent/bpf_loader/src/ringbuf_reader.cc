/**
 * @file ringbuf_reader.cc
 * @brief RingBufferReader 的 libbpf 实现。
 */

#include "agent/bpf_loader/include/bpf_ringbuf_reader.hpp"

#include <bpf/libbpf.h>
#include <bpf/libbpf_version.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <unistd.h>

#include <cerrno>
#include <cstddef>
#include <memory>
#include <system_error>
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

}  // namespace

struct RingBufferReader::Impl {
    Impl(int fd, Handler handler, void* ctx) noexcept
        : fd(fd), handler(handler), ctx(ctx)
    {
    }

    ~Impl()
    {
        if (buffer != nullptr) {
            ::ring_buffer__free(buffer);
        }
        if (fd >= 0) {
            ::close(fd);
        }
    }

    Impl(const Impl&)            = delete;
    Impl& operator=(const Impl&) = delete;

    static int trampoline(void* context, void* data, std::size_t size) noexcept
    {
        auto* impl = static_cast<Impl*>(context);
        if (impl == nullptr || impl->handler == nullptr) {
            return -EINVAL;
        }
        return impl->handler(impl->ctx, data, size);
    }

    int fd;
    Handler handler;
    void* ctx;
    ::ring_buffer* buffer = nullptr;
};

RingBufferReader::RingBufferReader(std::unique_ptr<Impl> impl)
    : impl_(std::move(impl))
{
}

RingBufferReader::~RingBufferReader()                           = default;

RingBufferReader::RingBufferReader(RingBufferReader&&) noexcept = default;

RingBufferReader& RingBufferReader::operator=(RingBufferReader&&) noexcept =
    default;

std::unique_ptr<RingBufferReader> RingBufferReader::create(BpfMapView ringbuf,
                                                           Handler handler,
                                                           void* ctx)
{
    if (ringbuf.spec().type != BPF_MAP_TYPE_RINGBUF || handler == nullptr) {
        throw std::system_error(EINVAL, std::generic_category(),
                                "invalid ringbuf map or handler");
    }

    const int copy = ::fcntl(ringbuf.fd(), F_DUPFD_CLOEXEC, 0);
    if (copy < 0) {
        throw std::system_error(errno, std::generic_category(),
                                "duplicate ringbuf fd");
    }
    FdGuard guard(copy);

    auto impl = std::make_unique<Impl>(copy, handler, ctx);
    errno     = 0;
    impl->buffer =
        ::ring_buffer__new(impl->fd, &Impl::trampoline, impl.get(), nullptr);
    if (impl->buffer == nullptr) {
        const int error = errno != 0 ? errno : EINVAL;
        impl->fd        = -1;
        throw std::system_error(error, std::generic_category(),
                                "ring_buffer__new failed");
    }
    guard.release();
    return std::unique_ptr<RingBufferReader>(
        new RingBufferReader(std::move(impl)));
}

int RingBufferReader::consume(std::size_t budget) noexcept
{
    if (impl_ == nullptr || impl_->buffer == nullptr) {
        return -EINVAL;
    }
#if defined(LIBBPF_MAJOR_VERSION) && defined(LIBBPF_MINOR_VERSION) && \
    (LIBBPF_MAJOR_VERSION > 1 ||                                      \
     (LIBBPF_MAJOR_VERSION == 1 && LIBBPF_MINOR_VERSION >= 5))
    return ::ring_buffer__consume_n(impl_->buffer, budget);
#else
    (void)budget;
    return ::ring_buffer__consume(impl_->buffer);
#endif
}

int RingBufferReader::epoll_fd() const noexcept
{
    if (impl_ == nullptr || impl_->buffer == nullptr) {
        return -1;
    }
    return ::ring_buffer__epoll_fd(impl_->buffer);
}

}  // namespace hng
