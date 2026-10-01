#include "agent/collector/include/collector.hpp"
#include "kernel/include/syscalls_type.h"

SyscallEventCollector::SyscallEventCollector(
    hng::SPSC_Queue<struct syscall_event>& queue)
    : syscall_rawevent_queue(queue), syscalls_collector(NULL), rb(NULL)
{
}

SyscallEventCollector::~SyscallEventCollector()
{
    syscalls_collector__destroy(syscalls_collector);
    ring_buffer__free(rb);
}

int SyscallEventCollector::handle_rb_event(void* ctx, void* data, size_t data_sz)
{
    if (data_sz < sizeof(struct syscall_event)) {
        return -1;
    }
    // void* -> syscall_event*
    struct syscall_event* ev    = (struct syscall_event*)data;
    // 从 ctx 解析 this 指针
    SyscallEventCollector* self = static_cast<SyscallEventCollector*>(ctx);

    self->syscall_rawevent_queue.push(*ev);
    return 0;
}

bool SyscallEventCollector::init()
{
    int err;
    syscalls_collector = syscalls_collector__open_and_load();
    if (!syscalls_collector) {
        return false;
    }
    err = syscalls_collector__attach(syscalls_collector);
    if (err) {
        return false;
    }
    // 将 this 指针作为 ctx 注册到回调函数中，调用回调函数时解析 ctx 获取 this
    rb = ring_buffer__new(bpf_map__fd(syscalls_collector->maps.syscall_events),
                          handle_rb_event, this, NULL);
    if (!rb) {
        return false;
    }
    return true;
}

void SyscallEventCollector::collect()
{
    while (true) {
        int err = ring_buffer__poll(rb, 300);
        // TODO: 错误处理与退出处理
    }
}