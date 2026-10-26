/**
 * @file syscall_event_collector.cc
 * @brief 原始事件采集、探针资源管理与过滤 map fd 接口。
 */
#include "agent/collector/include/collector.hpp"
#include "kernel/syscalls.skel.h"

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
};
}  // namespace hng::detail

SyscallEventCollector::SyscallEventCollector(
    hng::SPSC_Queue<syscall_event>& queue)
    : syscall_rawevent_queue(queue)
{
}

SyscallEventCollector::~SyscallEventCollector() = default;

/**
 * @brief 将借用的载荷按已知 ABI 大小复制入队，不保留 ringbuf 指针。
 * @note memcpy 不要求载荷地址满足事件类型的对齐要求，也不假定字符数组以 NUL
 * 结束。 队列满时沿用原有丢弃行为；返回 0 让 libbpf 继续消费后续事件。
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
    self->syscall_rawevent_queue.push(event);
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
    if (events_fd < 0 ||
        bpf_map__fd(candidate->skeleton->maps.hng_role_filter) < 0) {
        return false;
    }
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

void SyscallEventCollector::collect()
{
    if (!state_ || !state_->attached) {
        return;
    }
    while (ring_buffer__poll(state_->buffer.get(), 300) >= 0) {
    }
}

int SyscallEventCollector::role_filter_map_fd() const noexcept
{
    return state_ ? bpf_map__fd(state_->skeleton->maps.hng_role_filter) : -1;
}
