/**
 * @file
 * @brief 真实采集器源码的初始化、回调复制、错误回收及过滤 fd 测试。
 * @note 使用骨架替身，不代表已在真实内核中加载探针。
 */
#include "agent/collector/include/collector.hpp"
#include <cstdio>
#include <stdexcept>

namespace {
int checks = 0;
void require(bool value)
{
    ++checks;
    if (!value) throw std::runtime_error("采集器过滤接口检查失败");
}

template<class Collector, class Event>
void verify(int fd)
{
    hng::SPSC_Queue<Event> queue(4);
    {
        Collector collector(queue);
        require(collector.role_filter_map_fd() == -1);
        collector.collect();
        hng_test_open_failure = true;
        require(!collector.init());
        hng_test_open_failure = false;
        hng_test_attach_failure = true;
        require(!collector.init());
        require(hng_test_live_skeletons == 0);
        hng_test_attach_failure = false;
        hng_test_ring_failure = true;
        require(!collector.init());
        require(hng_test_live_skeletons == 0);
        hng_test_ring_failure = false;
        require(collector.init());
        require(collector.role_filter_map_fd() == fd);
        require(!collector.init());
        require(hng_test_live_skeletons == 1 && hng_test_live_rings == 1);
        Event event{};
        hng_test_payload = &event;
        hng_test_payload_size = sizeof(Event) - 1;
        collector.collect();
        require(hng_test_callback_result == -EINVAL && queue.empty());
        hng_test_payload_size = sizeof(Event);
        collector.collect();
        require(hng_test_callback_result == 0);
        Event received{};
        require(queue.pop(received) && queue.empty());
        hng_test_payload = nullptr;
    }
    require(hng_test_live_skeletons == 0 && hng_test_live_rings == 0);
    require(!hng_test_bad_cleanup_order);
}
}

int main()
{
    try {
        verify<FileEventCollector, file_access_data>(101);
        verify<SyscallEventCollector, syscall_event>(201);
        verify<NetworkEventCollector, network_data>(301);
        std::printf("PASS: collector filter map, %d checks (skeleton mocks)\n", checks);
        return 0;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "FAIL: %s\n", error.what());
        return 1;
    }
}
