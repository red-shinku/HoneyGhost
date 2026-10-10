// 以骨架替身检查真实采集器源码和 map fd 对接；不声称加载过内核探针。
#include "agent/collector/include/collector.hpp"
#include <cstdio>
#include <stdexcept>

void require(bool condition) { if (!condition) throw std::runtime_error("collector map 对接检查失败"); }

template<class Collector, class Event>
void verify(int fd)
{
    hng::SPSC_Queue<Event> queue(4);
    {
        Collector collector(queue);
        require(collector.role_filter_map_fd() == -1);
        require(collector.init()); require(collector.role_filter_map_fd() == fd);
        require(!collector.init()); collector.collect();
    }
    require(hng_test_live_skeletons == 0); require(hng_test_live_rings == 0);
    hng_test_attach_failure = true;
    { Collector collector(queue); require(!collector.init()); }
    hng_test_attach_failure = false;
    require(hng_test_live_skeletons == 0);
    hng_test_ring_failure = true;
    { Collector collector(queue); require(!collector.init()); }
    hng_test_ring_failure = false;
    require(hng_test_live_skeletons == 0); require(hng_test_live_rings == 0);
}

int main()
{
    try {
        verify<FileEventCollector, file_access_data>(101);
        verify<SyscallEventCollector, syscall_event>(201);
        verify<NetworkEventCollector, network_data>(301);
        std::puts("PASS: collector filter fd, initialization, cleanup (skeleton mocks)");
        return 0;
    } catch (const std::exception& e) { std::fprintf(stderr, "FAIL: %s\n", e.what()); return 1; }
}
