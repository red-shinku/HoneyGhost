/**
 * @file test_bpf_ringbuf_reader.cc
 * @brief RingBufferReader 的回调、预算、epoll fd 与 fd 释放测试。
 * @note libbpf ringbuf 与 map info syscall 均走替身，无特权。
 */
#include "agent/bpf_loader/include/bpf_ringbuf_reader.hpp"
#include "test/fixtures/bpf_loader_stub.hpp"

#include <fcntl.h>
#include <linux/bpf.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cerrno>
#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>
#include <system_error>

namespace {

int checks = 0;
#define REQUIRE(expression)                                                   \
    do {                                                                      \
        ++checks;                                                             \
        if (!(expression))                                                    \
            throw std::runtime_error(std::string(#expression) + " at line " + \
                                     std::to_string(__LINE__));               \
    } while (false)

int backing_fd = -1;

struct HandlerContext {
    int calls        = 0;
    const void* data = nullptr;
    std::size_t size = 0;
    int result       = 0;
};

int handler(void* context, const void* data, std::size_t size) noexcept
{
    auto* state = static_cast<HandlerContext*>(context);
    ++state->calls;
    state->data = data;
    state->size = size;
    return state->result;
}

template <class Action>
void rejects(Action action, int expected)
{
    try {
        action();
    }
    catch (const std::system_error& error) {
        REQUIRE(error.code().value() == expected);
        return;
    }
    REQUIRE(false);
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

void reset_ringstub()
{
    hng_test_live_rings        = 0;
    hng_test_ring_failure      = false;
    hng_test_ring_calls        = 0;
    hng_test_consume_calls     = 0;
    hng_test_consume_successes = 0;
    hng_test_consume_error     = -EIO;
    hng_test_consume_budget    = 0;
    hng_test_deliver_payload   = false;
    hng_test_payload           = nullptr;
    hng_test_payload_size      = 0;
    hng_test_callback_result   = 0;
    hng_test_last_ring         = nullptr;
    hng_test_rings.clear();
    hng_test_map_specs.clear();
}

void verify_consume_and_cleanup()
{
    reset_ringstub();
    constexpr int ring_fd = 500;
    hng_test_register_map(ring_fd, hng_test_ringbuf_map_spec());
    hng::BpfMapView view = hng::BpfMapView::from_fd(ring_fd);

    HandlerContext context;
    auto reader = hng::RingBufferReader::create(view, &handler, &context);
    REQUIRE(hng_test_ring_calls == 1);
    REQUIRE(hng_test_live_rings == 1);
    REQUIRE(hng_test_last_ring != nullptr);
    const int duplicate_fd = hng_test_last_ring->map_fd;
    REQUIRE(duplicate_fd >= 0);
    REQUIRE(is_open(duplicate_fd));
    REQUIRE((::fcntl(duplicate_fd, F_GETFD) & FD_CLOEXEC) != 0);
    REQUIRE(reader->epoll_fd() == hng_test_last_ring->epoll_fd);
    REQUIRE(reader->epoll_fd() >= 0);

    REQUIRE(reader->consume(0) == 0);
    REQUIRE(hng_test_consume_calls == 1);
    REQUIRE(hng_test_consume_budget == 0);
    REQUIRE(context.calls == 0);

    std::uint64_t payload    = 0x1122334455667788ULL;
    hng_test_deliver_payload = true;
    hng_test_payload         = &payload;
    hng_test_payload_size    = sizeof(payload);
    REQUIRE(reader->consume(7) == 1);
    REQUIRE(hng_test_consume_calls == 2);
    REQUIRE(hng_test_consume_budget == 7);
    REQUIRE(context.calls == 1);
    REQUIRE(context.data == &payload);
    REQUIRE(context.size == sizeof(payload));

    context.result = -EINTR;
    REQUIRE(reader->consume(1) == -EINTR);
    REQUIRE(hng_test_callback_result == -EINTR);
    context.result             = 0;

    hng_test_deliver_payload   = false;
    hng_test_consume_successes = 0;
    hng_test_consume_error     = -EIO;
    REQUIRE(reader->consume(1) == -EIO);

    REQUIRE(is_open(duplicate_fd));
    reader.reset();
    REQUIRE(!is_open(duplicate_fd));
    REQUIRE(hng_test_live_rings == 0);
    REQUIRE(hng_test_last_ring == nullptr);
}

void verify_create_failures()
{
    reset_ringstub();
    constexpr int hash_fd = 501;
    hng_test_register_map(hash_fd, hng_test_map_spec{BPF_MAP_TYPE_HASH, 4, 8, 1});
    hng::BpfMapView hash_view = hng::BpfMapView::from_fd(hash_fd);
    HandlerContext context;
    rejects(
        [&] {
            (void)hng::RingBufferReader::create(hash_view, &handler, &context);
        },
        EINVAL);
    REQUIRE(hng_test_ring_calls == 0);

    constexpr int ring_fd = 502;
    hng_test_register_map(ring_fd, hng_test_ringbuf_map_spec());
    hng::BpfMapView ring_view = hng::BpfMapView::from_fd(ring_fd);
    rejects(
        [&] {
            (void)hng::RingBufferReader::create(ring_view, nullptr, &context);
        },
        EINVAL);
    REQUIRE(hng_test_ring_calls == 0);

    const int expected_copy = lowest_free_fd();
    hng_test_ring_failure   = true;
    rejects(
        [&] {
            (void)hng::RingBufferReader::create(ring_view, &handler, &context);
        },
        EINVAL);
    REQUIRE(hng_test_ring_calls == 1);
    REQUIRE(expected_copy >= 0 && !is_open(expected_copy));
    REQUIRE(hng_test_live_rings == 0);
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

    if (number != SYS_bpf || command != BPF_OBJ_GET_INFO_BY_FD ||
        attr == nullptr || size != sizeof(*attr)) {
        errno = EINVAL;
        return -1;
    }
    const int fd                  = static_cast<int>(attr->info.bpf_fd);
    const hng_test_map_spec* spec = hng_test_find_map_spec(fd);
    if (spec == nullptr || attr->info.info_len != sizeof(bpf_map_info)) {
        errno = EBADF;
        return -1;
    }
    auto* info = reinterpret_cast<bpf_map_info*>(attr->info.info);
    if (info == nullptr) {
        errno = EINVAL;
        return -1;
    }
    *info             = {};
    info->type        = spec->type;
    info->key_size    = spec->key_size;
    info->value_size  = spec->value_size;
    info->max_entries = spec->max_entries;
    return 0;
}

extern "C" int __real_fcntl(int fd, int command, ...);

extern "C" int __wrap_fcntl(int fd, int command, ...)
{
    if (command != F_DUPFD_CLOEXEC) {
        return __real_fcntl(fd, command);
    }
    if (hng_test_find_map_spec(fd) == nullptr || backing_fd < 0) {
        errno = EBADF;
        return -1;
    }
    return __real_fcntl(backing_fd, F_DUPFD_CLOEXEC, 0);
}

int main()
{
    try {
        backing_fd = ::open("/dev/null", O_RDONLY | O_CLOEXEC);
        REQUIRE(backing_fd >= 0);
        verify_consume_and_cleanup();
        verify_create_failures();
        ::close(backing_fd);
        REQUIRE(hng_test_live_rings == 0);
        std::printf("PASS: bpf ringbuf reader, %d checks\n", checks);
        return 0;
    }
    catch (const std::exception& error) {
        if (backing_fd >= 0) {
            ::close(backing_fd);
        }
        std::fprintf(stderr, "FAIL: %s\n", error.what());
        return 1;
    }
}
