/**
 * @file file_event_collector.cc
 * @brief 文件事件采集线：ringbuf 资源、探针挂载与按预算消费。
 */
#include "agent/collector/src/collector.hpp"
#include "kernel/files.skel.h"

#include <bpf/libbpf_version.h>

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
    std::unique_ptr<::ring_buffer, decltype(&::ring_buffer__free)> buffer{
        nullptr, &::ring_buffer__free};
    bool attached = false;  ///< attach() 已成功挂载探针
    bool ready    = false;  ///< ringbuf 已可被 consume() 消费
};
}  // namespace hng::detail

FileEventCollector::FileEventCollector(
    hng::EventChannelWriter<file_access_data>& sink)
    : file_sink(sink)
{
}

FileEventCollector::~FileEventCollector() = default;

/**
 * @brief 将借用的载荷按已知 ABI 大小复制入队，不保留 ringbuf 指针。
 * @note memcpy 不要求载荷地址满足事件类型的对齐要求，也不假定字符数组以
 * NUL 结束。通道满时沿用原有丢弃行为，丢弃计数在通道内；返回 0 让 libbpf
 * 继续消费后续事件。
 */
int FileEventCollector::handle_rb_event(void* ctx, void* data,
                                        std::size_t data_sz) noexcept
{
    static_assert(std::is_trivially_copyable_v<file_access_data>);
    if (!ctx || !data || data_sz < sizeof(file_access_data)) {
        return -EINVAL;
    }
    file_access_data event;
    std::memcpy(&event, data, sizeof(event));
    auto* self = static_cast<FileEventCollector*>(ctx);
    self->file_sink.push(event);
    return 0;
}

bool FileEventCollector::prepare()
{
    if (state_) {
        return false;
    }
    // 只在准备时分配私有状态；失败路径由局部拥有者自动回收。
    std::unique_ptr<hng::detail::FileCollectorState> candidate(
        new (std::nothrow) hng::detail::FileCollectorState);
    if (!candidate) {
        return false;
    }
    candidate->skeleton.reset(files_collector__open_and_load());
    if (!candidate->skeleton) {
        return false;
    }
    const int events_fd =
        bpf_map__fd(candidate->skeleton->maps.file_access_events);
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

bool FileEventCollector::attach()
{
    if (!state_ || state_->attached) {
        return false;
    }
    if (files_collector__attach(state_->skeleton.get())) {
        return false;
    }
    state_->attached = true;
    state_->ready    = true;
    return true;
}

bool FileEventCollector::init()
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

void FileEventCollector::detach()
{
    if (!state_ || !state_->attached) {
        return;
    }
    files_collector__detach(state_->skeleton.get());
    state_->attached = false;
}

int FileEventCollector::consume(std::size_t budget)
{
    if (!state_ || !state_->ready) {
        return 0;
    }
#if defined(LIBBPF_MAJOR_VERSION) && defined(LIBBPF_MINOR_VERSION) && \
    (LIBBPF_MAJOR_VERSION > 1 ||                                      \
     (LIBBPF_MAJOR_VERSION == 1 && LIBBPF_MINOR_VERSION >= 5))
    return ring_buffer__consume_n(state_->buffer.get(), budget);
#else
    (void)budget;
    return ring_buffer__consume(state_->buffer.get());
#endif
}

int FileEventCollector::epoll_fd() const noexcept
{
    if (!state_ || !state_->ready) {
        return -1;
    }
    return ring_buffer__epoll_fd(state_->buffer.get());
}

int FileEventCollector::role_filter_map_fd() const noexcept
{
    return state_ ? bpf_map__fd(state_->skeleton->maps.hng_role_filter) : -1;
}
