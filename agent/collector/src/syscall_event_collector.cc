/**
 * @file syscall_event_collector.cc
 * @brief 系统调用事件采集线：ringbuf 资源、探针挂载与按预算消费。
 */
#include "agent/collector/src/collector.hpp"
#include "agent/collector/src/probe_attach.hpp"
#include "agent/util/include/tracefs.hpp"
#include "kernel/syscalls.skel.h"

#include <bpf/libbpf_version.h>

#include <cerrno>
#include <cstring>
#include <new>
#include <type_traits>
#include <utility>
#include <vector>

namespace hng::detail {
/** @brief 按声明的逆序销毁成员：先链接，再 ringbuf，最后探针骨架。 */
struct SyscallCollectorState {
    std::unique_ptr<::syscalls_collector,
                    decltype(&::syscalls_collector__destroy)>
        skeleton{nullptr, &::syscalls_collector__destroy};
    std::unique_ptr<::ring_buffer, decltype(&::ring_buffer__free)> buffer{
        nullptr, &::ring_buffer__free};
    std::vector<::bpf_link*> links;   ///< 已挂载探针的链接，由本状态持有
    bool attached           = false;  ///< attach() 已成功挂载探针
    bool ready              = false;  ///< ringbuf 已可被 consume() 消费
    int reserve_failures_fd = -1;     ///< 内核 ringbuf 预留失败计数 map
    int pending_lost_fd     = -1;     ///< 内核暂存条目丢失计数 map

    ~SyscallCollectorState()
    {
        for (::bpf_link* link : links) {
            ::bpf_link__destroy(link);
        }
    }
};
}  // namespace hng::detail

SyscallEventCollector::SyscallEventCollector(
    hng::EventChannelWriter<syscall_event>& sink,
    std::filesystem::path tracefs_root)
    : syscall_sink(sink), tracefs_root_(std::move(tracefs_root))
{
}

SyscallEventCollector::~SyscallEventCollector() = default;

/**
 * @brief 按 subtype 解析一条 ringbuf 记录并放入输出通道。
 * @param[in] ctx 采集器自身。
 * @param[in] data ringbuf 记录：事件头 + 该 subtype 的定长载荷。
 * @param[in] data_sz 记录长度。
 * @return 头或长度非法时也返回 0，让 libbpf 继续消费后续记录；仅参数为空
 *         指针时返回 -EINVAL。
 * @note 记录长度必须恰好等于头加该 subtype 的载荷；未知 subtype、长度不符
 *       或不足一个头都计入 malformed 并丢弃。
 * @note 载荷按字节复制进清零后的本地 syscall_event，不保留 ringbuf 指针，
 *       也不假定字符数组以 NUL 结束。通道满时丢弃计数由通道累计。
 */
int SyscallEventCollector::handle_rb_event(void* ctx, void* data,
                                           std::size_t data_sz) noexcept
{
    static_assert(std::is_trivially_copyable_v<syscall_event>);
    if (!ctx || !data) {
        return -EINVAL;
    }
    auto* self = static_cast<SyscallEventCollector*>(ctx);
    if (data_sz < sizeof(struct syscall_event_head)) {
        self->mark_malformed();
        return 0;
    }
    struct syscall_event_head head;
    std::memcpy(&head, data, sizeof(head));
    const std::size_t record_size = hng::detail::SyscallRecordSize(head.subtype);
    if (record_size == 0 || data_sz != record_size) {
        self->mark_malformed();
        return 0;
    }
    const std::size_t payload_size = record_size - sizeof(head);
    syscall_event event{};
    std::memcpy(&event.hdr, data, sizeof(event.hdr));
    std::memcpy(reinterpret_cast<char*>(&event) + sizeof(event.hdr),
                static_cast<const char*>(data) + sizeof(event.hdr), payload_size);
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
    candidate->skeleton.reset(syscalls_collector__open());
    if (!candidate->skeleton) {
        return false;
    }
    const std::filesystem::path tracefs_root =
        tracefs_root_.empty() ? hng::detail::find_tracefs_root() : tracefs_root_;
    const int skipped = hng::detail::skip_missing_tracepoints(
        candidate->skeleton->obj, tracefs_root);
    if (syscalls_collector__load(candidate->skeleton.get()) != 0) {
        return false;
    }
    const int events_fd = bpf_map__fd(candidate->skeleton->maps.syscall_events);
    const int failures_fd =
        bpf_map__fd(candidate->skeleton->maps.reserve_failures);
    const int pending_lost_fd =
        bpf_map__fd(candidate->skeleton->maps.pending_lost);
    if (events_fd < 0 || failures_fd < 0 || pending_lost_fd < 0 ||
        bpf_map__fd(candidate->skeleton->maps.hng_role_filter) < 0) {
        return false;
    }
    candidate->reserve_failures_fd = failures_fd;
    candidate->pending_lost_fd     = pending_lost_fd;
    candidate->buffer.reset(
        ring_buffer__new(events_fd, handle_rb_event, this, nullptr));
    if (!candidate->buffer) {
        return false;
    }
    mark_skipped_probes(static_cast<std::uint64_t>(skipped));
    state_ = std::move(candidate);
    return true;
}

bool SyscallEventCollector::attach()
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
    for (::bpf_link* link : state_->links) {
        ::bpf_link__destroy(link);
    }
    state_->links.clear();
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

int SyscallEventCollector::pending_lost_fd() const noexcept
{
    return state_ ? state_->pending_lost_fd : -1;
}

const char* SyscallEventCollector::name() const noexcept { return "syscall"; }

hng::CollectorLineStats SyscallEventCollector::stats() const
{
    hng::CollectorLineStats snapshot;
    snapshot.line             = name();
    snapshot.consumed         = consumed();
    snapshot.consume_errors   = consume_errors();
    snapshot.malformed        = malformed();
    snapshot.channel_dropped  = syscall_sink.dropped();
    snapshot.channel_rejected = syscall_sink.rejected();
    snapshot.skipped_probes   = skipped_probes();
    snapshot.attach_failed    = attach_failed();
    snapshot.attached         = attached();
    snapshot.polling          = polling();
    return snapshot;
}
