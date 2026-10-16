/**
 * @file
 * @brief 原始事件采集、探针资源管理与过滤 map fd 接口。
 */
#include "agent/collector/include/collector.hpp"
#include <cerrno>

NetworkEventCollector::NetworkEventCollector(hng::SPSC_Queue<struct network_data>& queue)
    : network_rawevent_queue(queue), networks_collector(nullptr), rb(nullptr) {}

NetworkEventCollector::~NetworkEventCollector()
{
    if (rb) ring_buffer__free(rb);
    if (networks_collector) networks_collector__destroy(networks_collector);
}

/**
 * @brief 将借用的 ringbuf 载荷复制到原始事件队列。
 * @param[in] ctx 注册回调的采集器指针。
 * @param[in] data ringbuf 提供的事件载荷。
 * @param[in] data_sz 载荷字节数。
 * @return 参数非法或载荷不足时返回 -EINVAL，否则返回 0。
 * @note 队列满时沿用原有丢弃行为，不将 ringbuf 借用指针保存到队列。
 */
int NetworkEventCollector::handle_rb_event(void* ctx, void* data, size_t data_sz)
{
    if (!ctx || !data || data_sz < sizeof(struct network_data)) return -EINVAL;
    auto* self = static_cast<NetworkEventCollector*>(ctx);
    self->network_rawevent_queue.push(*static_cast<const struct network_data*>(data));
    return 0;
}

bool NetworkEventCollector::init()
{
    if (networks_collector) return false;
    auto* candidate = networks_collector__open_and_load();
    if (!candidate) return false;
    if (networks_collector__attach(candidate)) {
        networks_collector__destroy(candidate);
        return false;
    }
    auto* buffer = ring_buffer__new(bpf_map__fd(candidate->maps.network_events),
                                   handle_rb_event, this, nullptr);
    if (!buffer) {
        networks_collector__destroy(candidate);
        return false;
    }
    networks_collector = candidate;
    rb = buffer;
    return true;
}

void NetworkEventCollector::collect()
{
    if (!rb) return;
    while (true) {
        int error = ring_buffer__poll(rb, 300);
        if (error < 0) break;
    }
}

int NetworkEventCollector::role_filter_map_fd() const noexcept
{
    return networks_collector ? bpf_map__fd(networks_collector->maps.hng_role_filter) : -1;
}
