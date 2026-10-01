#include "agent/collector/include/collector.hpp"
#include "kernel/include/networks_type.h"

NetworkEventCollector(hng::SPSC_Queue<struct network_data>& queue)
    : network_rawevent_queue(queue), networks_collector(NULL), rb(NULL)
{
}

~NetworkEventCollector() {}

static int NetworkEventCollector::handle_rb_event(void* ctx, void* data,
                                                  size_t data_sz)
{
    if (data_sz < sizeof(struct network_data)) {
        return -1;
    }
    struct network_data* ev     = (struct network_data*)data;
    NetworkEventCollector* self = static_cast<NetworkEventCollector*>(ctx);
    self->network_rawevent_queue.push(*ev);
    return 0;
}

bool NetworkEventCollector::init()
{
    int err;
    networks_collector = networks_collector__open_and_load();
    if (!networks_collector) {
        return false;
    }
    err = networks_collector__attach();
    if (err) {
        return false;
    }
    rb = ring_buffer__new(bpf_map__fd(networks_collector->maps.network_data),
                          handle_rb_event, this, NULL);
    if (!rb) {
        return false;
    }
    return true;
}

void NetworkEventCollector::collect()
{
    while (true) {
        int err = ring_buffer__poll(rb, 300);
        // TODO: 错误处理与退出处理
        if (err == -EINTR) {
            break;
        }
        if (err < 0) {
            break;
        }
    }
}
