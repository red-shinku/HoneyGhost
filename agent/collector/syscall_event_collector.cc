#include "collector.hpp"
#include "../kernel/include/syscalls_type.h"

SyscallEventCollector::SyscallEventCollector(RawEventQueue& queue)
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
    struct syscall_event* ev = (struct syscall_event*)data;
    syscall_rawevent_queue.push(*ev);
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
    rb = ring_buffer__new(bpf_map__fd(syscalls_collector->maps.syscall_events), handle_rb_event, NULL, NULL);
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