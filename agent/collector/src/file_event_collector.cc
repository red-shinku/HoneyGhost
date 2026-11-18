/**
 * @file file_event_collector.cc
 * @brief 文件事件采集线：ringbuf 资源、探针挂载与按预算消费。
 */
#include "agent/collector/src/collector.hpp"
#include "agent/collector/src/probe_attach.hpp"
#include "agent/util/include/tracefs.hpp"
#include "kernel/files.skel.h"

#include <bpf/libbpf_version.h>

#include <cerrno>
#include <cstring>
#include <new>
#include <type_traits>
#include <utility>
#include <vector>

namespace hng::detail {
/** @brief 按声明的逆序销毁成员：先链接，再 ringbuf，最后探针骨架。 */
struct FileCollectorState {
    std::unique_ptr<::files_collector, decltype(&::files_collector__destroy)>
        skeleton{nullptr, &::files_collector__destroy};
    std::unique_ptr<::ring_buffer, decltype(&::ring_buffer__free)> buffer{
        nullptr, &::ring_buffer__free};
    std::vector<::bpf_link*> links;   ///< 已挂载探针的链接，由本状态持有
    bool attached           = false;  ///< attach() 已成功挂载探针
    bool ready              = false;  ///< ringbuf 已可被 consume() 消费
    int reserve_failures_fd = -1;     ///< 内核 ringbuf 预留失败计数 map

    ~FileCollectorState()
    {
        for (::bpf_link* link : links) {
            ::bpf_link__destroy(link);
        }
    }
};
}  // namespace hng::detail

FileEventCollector::FileEventCollector(
    hng::EventChannelWriter<file_access_data>& sink,
    std::filesystem::path tracefs_root)
    : file_sink(sink), tracefs_root_(std::move(tracefs_root))
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
    self->mark_consumed();
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
    candidate->skeleton.reset(files_collector__open());
    if (!candidate->skeleton) {
        return false;
    }
    const std::filesystem::path tracefs_root =
        tracefs_root_.empty() ? hng::detail::find_tracefs_root() : tracefs_root_;
    const int skipped = hng::detail::skip_missing_tracepoints(
        candidate->skeleton->obj, tracefs_root);
    if (files_collector__load(candidate->skeleton.get()) != 0) {
        return false;
    }
    const int events_fd =
        bpf_map__fd(candidate->skeleton->maps.file_access_events);
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
    mark_skipped_probes(static_cast<std::uint64_t>(skipped));
    state_ = std::move(candidate);
    return true;
}

bool FileEventCollector::attach()
{
    if (!state_ || state_->attached) {
        return false;
    }
    const int failures =
        hng::detail::attach_programs(state_->skeleton->obj, state_->links);
    if (failures > 0) {
        mark_attach_failed(static_cast<std::uint64_t>(failures));
    }
    if (failures > 0 && state_->links.empty()) {
        return false;
    }
    state_->attached = true;
    state_->ready    = true;
    mark_attached(true);
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
    for (::bpf_link* link : state_->links) {
        ::bpf_link__destroy(link);
    }
    state_->links.clear();
    state_->attached = false;
    mark_attached(false);
}

int FileEventCollector::consume(std::size_t budget)
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

int FileEventCollector::reserve_failures_fd() const noexcept
{
    return state_ ? state_->reserve_failures_fd : -1;
}

const char* FileEventCollector::name() const noexcept { return "file"; }

hng::CollectorLineStats FileEventCollector::stats() const
{
    hng::CollectorLineStats snapshot;
    snapshot.line             = name();
    snapshot.consumed         = consumed();
    snapshot.consume_errors   = consume_errors();
    snapshot.channel_dropped  = file_sink.dropped();
    snapshot.channel_rejected = file_sink.rejected();
    snapshot.skipped_probes   = skipped_probes();
    snapshot.attach_failed    = attach_failed();
    snapshot.attached         = attached();
    snapshot.polling          = polling();
    return snapshot;
}
