/**
 * @file file_event_collector.cc
 * @brief 原始事件采集、探针资源管理与过滤 map fd 接口。
 */
#include "agent/collector/include/collector.hpp"
#include "kernel/files.skel.h"

#include <cerrno>
#include <cstring>
#include <new>
#include <type_traits>
#include <utility>

namespace hng::detail {
/** @brief 按声明的逆序销毁成员：先 ringbuf，再探针骨架。 */
struct FileCollectorState {
    std::unique_ptr<::files_collector, decltype(&::files_collector__destroy)>
        skeleton{nullptr, &::files_collector__destroy};
    std::unique_ptr<::ring_buffer, decltype(&::ring_buffer__free)>
        buffer{nullptr, &::ring_buffer__free};
};
}  // namespace hng::detail

FileEventCollector::FileEventCollector(hng::SPSC_Queue<file_access_data>& queue)
    : file_rawevent_queue(queue) {}

FileEventCollector::~FileEventCollector() = default;

/**
 * @brief 将借用的载荷按已知 ABI 大小复制入队，不保留 ringbuf 指针。
 * @note memcpy 不要求载荷地址满足事件类型的对齐要求，也不假定字符数组以 NUL 结束。
 *       队列满时沿用原有丢弃行为；返回 0 让 libbpf 继续消费后续事件。
 */
int FileEventCollector::handle_rb_event(void* ctx, void* data, std::size_t data_sz) noexcept
{
    static_assert(std::is_trivially_copyable_v<file_access_data>);
    if (!ctx || !data || data_sz < sizeof(file_access_data)) {
        return -EINVAL;
    }
    file_access_data event;
    std::memcpy(&event, data, sizeof(event));
    auto* self = static_cast<FileEventCollector*>(ctx);
    self->file_rawevent_queue.push(event);
    return 0;
}

bool FileEventCollector::init()
{
    if (state_) {
        return false;
    }
    // 只在初始化时分配私有状态；失败路径由局部拥有者自动回收。
    std::unique_ptr<hng::detail::FileCollectorState> candidate(
        new (std::nothrow) hng::detail::FileCollectorState);
    if (!candidate) {
        return false;
    }
    candidate->skeleton.reset(files_collector__open_and_load());
    if (!candidate->skeleton) {
        return false;
    }
    const int events_fd = bpf_map__fd(candidate->skeleton->maps.file_access_events);
    if (events_fd < 0 || bpf_map__fd(candidate->skeleton->maps.hng_role_filter) < 0) {
        return false;
    }
    if (files_collector__attach(candidate->skeleton.get())) {
        return false;
    }
    candidate->buffer.reset(ring_buffer__new(events_fd, handle_rb_event, this, nullptr));
    if (!candidate->buffer) {
        return false;
    }
    state_ = std::move(candidate);
    return true;
}

void FileEventCollector::collect()
{
    if (!state_) {
        return;
    }
    while (ring_buffer__poll(state_->buffer.get(), 300) >= 0) {}
}

int FileEventCollector::role_filter_map_fd() const noexcept
{
    return state_ ? bpf_map__fd(state_->skeleton->maps.hng_role_filter) : -1;
}
