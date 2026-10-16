/**
 * @file
 * @brief 原始事件采集、探针资源管理与过滤 map fd 接口。
 */
#include "agent/collector/include/collector.hpp"
#include <cerrno>

SyscallEventCollector::SyscallEventCollector(hng::SPSC_Queue<struct syscall_event>& queue)
    : syscall_rawevent_queue(queue), syscalls_collector(nullptr), rb(nullptr) {}

SyscallEventCollector::~SyscallEventCollector()
{
    if (rb) ring_buffer__free(rb);
    if (syscalls_collector) syscalls_collector__destroy(syscalls_collector);
}

/**
 * @brief 将借用的 ringbuf 载荷复制到原始事件队列。
 * @param[in] ctx 注册回调的采集器指针。
 * @param[in] data ringbuf 提供的事件载荷。
 * @param[in] data_sz 载荷字节数。
 * @return 参数非法或载荷不足时返回 -EINVAL，否则返回 0。
 * @note 队列满时沿用原有丢弃行为，不将 ringbuf 借用指针保存到队列。
 */
int SyscallEventCollector::handle_rb_event(void* ctx, void* data, size_t data_sz)
{
    if (!ctx || !data || data_sz < sizeof(struct syscall_event)) return -EINVAL;
    auto* self = static_cast<SyscallEventCollector*>(ctx);
    self->syscall_rawevent_queue.push(*static_cast<const struct syscall_event*>(data));
    return 0;
}

bool SyscallEventCollector::init()
{
    if (syscalls_collector) return false;
    auto* candidate = syscalls_collector__open_and_load();
    if (!candidate) return false;
    if (syscalls_collector__attach(candidate)) {
        syscalls_collector__destroy(candidate);
        return false;
    }
    auto* buffer = ring_buffer__new(bpf_map__fd(candidate->maps.syscall_events),
                                   handle_rb_event, this, nullptr);
    if (!buffer) {
        syscalls_collector__destroy(candidate);
        return false;
    }
    syscalls_collector = candidate;
    rb = buffer;
    return true;
}

void SyscallEventCollector::collect()
{
    if (!rb) return;
    while (true) {
        int error = ring_buffer__poll(rb, 300);
        if (error < 0) break;
    }
}

int SyscallEventCollector::role_filter_map_fd() const noexcept
{
    return syscalls_collector ? bpf_map__fd(syscalls_collector->maps.hng_role_filter) : -1;
}
