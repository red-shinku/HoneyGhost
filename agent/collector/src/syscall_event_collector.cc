/**
 * @file syscall_event_collector.cc
 * @brief 系统调用事件采集线：ringbuf 资源、探针挂载与按预算消费。
 */
#include "agent/collector/src/collector.hpp"
#include "kernel/syscalls.skel.h"

#include <bpf/libbpf_version.h>

#include <cerrno>
#include <cstring>
#include <new>
#include <type_traits>
#include <utility>

namespace hng::detail {
/** @brief 按声明的逆序销毁成员：先 ringbuf，再探针骨架。 */
struct SyscallCollectorState {
    std::unique_ptr<::syscalls_collector,
                    decltype(&::syscalls_collector__destroy)>
        skeleton{nullptr, &::syscalls_collector__destroy};
    std::unique_ptr<::ring_buffer, decltype(&::ring_buffer__free)> buffer{
        nullptr, &::ring_buffer__free};
    bool attached = false;  ///< attach() 已成功挂载探针
    bool ready    = false;  ///< ringbuf 已可被 consume() 消费
    int reserve_failures_fd = -1;  ///< 内核 ringbuf 预留失败计数 map
};
}  // namespace hng::detail

SyscallEventCollector::SyscallEventCollector(
    hng::EventChannelWriter<syscall_event>& sink)
    : syscall_sink(sink)
{
}

SyscallEventCollector::~SyscallEventCollector() = default;

/**
 * @brief 将借用的载荷按已知 ABI 大小复制入队，不保留 ringbuf 指针。
 * @note memcpy 不要求载荷地址满足事件类型的对齐要求，也不假定字符数组以
 * NUL 结束。通道满时沿用原有丢弃行为，丢弃计数在通道内；返回 0 让 libbpf
 * 继续消费后续事件。
 */
int SyscallEventCollector::handle_rb_event(void* ctx, void* data,
                                           std::size_t data_sz) noexcept
{
    static_assert(std::is_trivially_copyable_v<syscall_event>);
    if (!ctx || !data || data_sz < sizeof(syscall_event)) {
        return -EINVAL;
    }
    syscall_event event;
    std::memcpy(&event, data, sizeof(event));
    auto* self = static_cast<SyscallEventCollector*>(ctx);
    self->syscall_sink.push(event);
    self->mark_consumed();
    return 0;
}

bool SyscallEventCollector::prepare()
{
    if (state_) {
        return false;
    }
    // 只在准备时分配私有状态；失败路径由局部拥有者自动回收。
    std::unique_ptr<hng::detail::SyscallCollectorState> candidate(
        new (std::nothrow) hng::detail::SyscallCollectorState);
    if (!candidate) {
        return false;
    }
    candidate->skeleton.reset(syscalls_collector__open_and_load());
    if (!candidate->skeleton) {
        return false;
    }
    const int events_fd = bpf_map__fd(candidate->skeleton->maps.syscall_events);
    const int failures_fd =
        bpf_map__fd(candidate->skeleton->maps.reserve_failures);
    if (events_fd < 0 || failures_fd < 0 ||
        bpf_map__fd(candidate->skeleton->maps.hng_role_filter) < 0) {
        return false;
    }
    candidate->reserve_failures_fd = failures_fd;
    candidate->buffer.reset(
        ring_buffer__new(events_fd, handle_rb_event, this, nullptr));
    if (!candidate->buffer) {
        return false;
    }
    state_ = std::move(candidate);
    return true;
}

bool SyscallEventCollector::attach()
{
    if (!state_ || state_->attached) {
        return false;
    }
    if (syscalls_collector__attach(state_->skeleton.get())) {
        return false;
    }
    state_->attached = true;
    state_->ready    = true;
    mark_attached(true);
    return true;
}

bool SyscallEventCollector::init()
{
    if (!prepare()) {
        return false;
    }
    if (!attach()) {
        state_.reset();
        return false;
    }
    return true;
}

void SyscallEventCollector::detach()
{
    if (!state_ || !state_->attached) {
        return;
    }
    syscalls_collector__detach(state_->skeleton.get());
    state_->attached = false;
    mark_attached(false);
}

int SyscallEventCollector::consume(std::size_t budget)
{
    if (!state_ || !state_->ready) {
        return 0;
    }
#if defined(LIBBPF_MAJOR_VERSION) && defined(LIBBPF_MINOR_VERSION) && \
    (LIBBPF_MAJOR_VERSION > 1 ||                                      \
     (LIBBPF_MAJOR_VERSION == 1 && LIBBPF_MINOR_VERSION >= 5))
    const int consumed = ring_buffer__consume_n(state_->buffer.get(), budget);
#else
    (void)budget;
    const int consumed = ring_buffer__consume(state_->buffer.get());
#endif
    if (consumed < 0) {
        mark_consume_error();
    }
    return consumed;
}

int SyscallEventCollector::epoll_fd() const noexcept
{
    if (!state_ || !state_->ready) {
        return -1;
    }
    return ring_buffer__epoll_fd(state_->buffer.get());
}

int SyscallEventCollector::role_filter_map_fd() const noexcept
{
    return state_ ? bpf_map__fd(state_->skeleton->maps.hng_role_filter) : -1;
}

int SyscallEventCollector::reserve_failures_fd() const noexcept
{
    return state_ ? state_->reserve_failures_fd : -1;
}

const char* SyscallEventCollector::name() const noexcept { return "syscall"; }

hng::CollectorLineStats SyscallEventCollector::stats() const
{
    hng::CollectorLineStats snapshot;
    snapshot.line            = name();
    snapshot.consumed        = consumed();
    snapshot.consume_errors  = consume_errors();
    snapshot.channel_dropped = syscall_sink.dropped();
    snapshot.channel_rejected = syscall_sink.rejected();
    snapshot.attached = attached();
    snapshot.polling  = polling();
    return snapshot;
}
