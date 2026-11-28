/**
 * @file syscall_event_collector.cc
 * @brief 系统调用事件采集线：ringbuf 消费与按 subtype 解析记录。
 */
#include "agent/collector/src/collector.hpp"

#include "agent/bpf_loader/include/bpf_map_reader.hpp"
#include "agent/bpf_loader/include/bpf_ringbuf_reader.hpp"

#include <cerrno>
#include <cstdint>
#include <cstring>
#include <memory>
#include <type_traits>
#include <utility>

namespace hng::detail {
/** @brief 系统调用采集线持有的 ringbuf 与统计 map 资源。 */
struct SyscallCollectorState {
    std::unique_ptr<RingBufferReader> ring;
    std::unique_ptr<BpfMapReader> reserve_failures;
    std::unique_ptr<BpfMapReader> pending_lost;
};
}  // namespace hng::detail

SyscallEventCollector::SyscallEventCollector(
    hng::EventChannelWriter<syscall_event>& sink, hng::SyscallProbeMaps maps)
    : syscall_sink(sink), maps_(std::move(maps))
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
int SyscallEventCollector::handle_rb_event(void* ctx, const void* data,
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

    try {
        auto ring = hng::RingBufferReader::create(
            maps_.events_ringbuf(), &SyscallEventCollector::handle_rb_event,
            this);
        const hng::BpfMapView reserve_view = maps_.reserve_failures_map();
        auto reserve_failures =
            hng::BpfMapReader::create(reserve_view, reserve_view.spec());
        const hng::BpfMapView pending_view = maps_.pending_lost_map();
        auto pending_lost =
            hng::BpfMapReader::create(pending_view, pending_view.spec());

        auto candidate  = std::make_unique<hng::detail::SyscallCollectorState>();
        candidate->ring = std::move(ring);
        candidate->reserve_failures = std::move(reserve_failures);
        candidate->pending_lost     = std::move(pending_lost);
        state_                      = std::move(candidate);
        return true;
    }
    catch (...) {
        return false;
    }
}

int SyscallEventCollector::consume(std::size_t budget)
{
    if (!state_) {
        return 0;
    }
    const int consumed = state_->ring->consume(budget);
    if (consumed < 0) {
        mark_consume_error();
    }
    return consumed;
}

int SyscallEventCollector::epoll_fd() const noexcept
{
    if (!state_) {
        return -1;
    }
    return state_->ring->epoll_fd();
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
    snapshot.attached         = attached();
    snapshot.polling          = polling();

    if (state_) {
        const std::uint32_t key = 0;
        std::uint64_t total     = 0;
        if (state_->reserve_failures != nullptr &&
            !state_->reserve_failures->sum_percpu_u64(&key, total)) {
            snapshot.reserve_failures = total;
        }
        total = 0;
        if (state_->pending_lost != nullptr &&
            !state_->pending_lost->sum_percpu_u64(&key, total)) {
            snapshot.pending_lost = total;
        }
    }
    return snapshot;
}
