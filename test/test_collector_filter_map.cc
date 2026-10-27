/**
 * @file test_collector_filter_map.cc
 * @brief 用真实采集器源码验证初始化事务、回调边界、map fd、消费与资源回收。
 * @note 使用骨架替身，不代表真实内核加载验证。
 */
#include "agent/collector/include/collector.hpp"
#include "test/fixtures/collector_skeleton_stub.hpp"

#include <array>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>
#include <type_traits>

namespace {
int checks = 0;
#define REQUIRE(expression)                                                   \
    do {                                                                      \
        ++checks;                                                             \
        if (!(expression))                                                    \
            throw std::runtime_error(std::string(#expression) + " at line " + \
                                     std::to_string(__LINE__));               \
    } while (false)

void reset_consume()
{
    hng_test_consume_calls     = 0;
    hng_test_consume_successes = 0;
    hng_test_consume_error     = -EIO;
    hng_test_consume_budget    = 0;
    hng_test_deliver_payload   = false;
    hng_test_payload           = nullptr;
    hng_test_payload_size      = 0;
}

// 为有字符数组的事件构造不含 NUL 的完整字段，并保留有效的 syscall 枚举值。
template <class Event>
Event sample()
{
    Event event{};
    if constexpr (std::is_same_v<Event, file_access_data>) {
        event.head.pid = 123;
        std::memset(event.comm, 'c', sizeof(event.comm));
        std::memset(event.filename, 'f', sizeof(event.filename));
        event.flags          = 0x1234;
        event.is_innamespace = 1;
    }
    else if constexpr (std::is_same_v<Event, syscall_event>) {
        event.hdr.head.pid = 456;
        event.hdr.name     = SYSCALL_EVENT_EXECVE;
        event.hdr.type     = EXEC_EVENT;
        std::memset(event.exec_event.filename, 'x',
                    sizeof(event.exec_event.filename));
        std::memset(event.exec_event.argv0, 'a', sizeof(event.exec_event.argv0));
        std::memset(event.exec_event.argv1, 'b', sizeof(event.exec_event.argv1));
        event.exec_event.flags = 7;
    }
    else {
        event.head.pid  = 789;
        event.family    = 10;
        event.dst_ip[3] = 42;
        event.src_port  = 80;
        event.dst_port  = 443;
        event.protocol  = 6;
    }
    return event;
}

template <class Event>
bool same_event(const Event& left, const Event& right)
{
    // 比较字段，不依赖编译器是否复制结构体填充字节。
    if constexpr (std::is_same_v<Event, file_access_data>) {
        return left.head.pid == right.head.pid && left.flags == right.flags &&
               left.is_innamespace == right.is_innamespace &&
               std::memcmp(left.comm, right.comm, sizeof(left.comm)) == 0 &&
               std::memcmp(left.filename, right.filename,
                           sizeof(left.filename)) == 0;
    }
    else if constexpr (std::is_same_v<Event, syscall_event>) {
        return left.hdr.head.pid == right.hdr.head.pid &&
               left.hdr.name == right.hdr.name &&
               left.hdr.type == right.hdr.type &&
               left.exec_event.flags == right.exec_event.flags &&
               std::memcmp(left.exec_event.filename, right.exec_event.filename,
                           sizeof(left.exec_event.filename)) == 0 &&
               std::memcmp(left.exec_event.argv0, right.exec_event.argv0,
                           sizeof(left.exec_event.argv0)) == 0 &&
               std::memcmp(left.exec_event.argv1, right.exec_event.argv1,
                           sizeof(left.exec_event.argv1)) == 0;
    }
    else {
        return left.head.pid == right.head.pid && left.family == right.family &&
               std::memcmp(left.dst_ip, right.dst_ip, sizeof(left.dst_ip)) == 0 &&
               left.src_port == right.src_port &&
               left.dst_port == right.dst_port && left.protocol == right.protocol;
    }
}

template <class Collector, class Event>
void verify()
{
    hng::SPSC_Queue<Event> queue(4);
    reset_consume();
    // prepare 只加载骨架、建 ringbuf 并取 map fd；探针未挂载前不消费。
    {
        Collector collector(queue);
        REQUIRE(collector.role_filter_map_fd() == -1);
        REQUIRE(collector.epoll_fd() == -1);
        REQUIRE(collector.consume(1) == 0);
        REQUIRE(hng_test_consume_calls == 0);
        REQUIRE(!collector.attach());

        hng_test_open_failure = true;
        REQUIRE(!collector.prepare());
        hng_test_open_failure = false;
        hng_test_ring_failure = true;
        REQUIRE(!collector.prepare());
        hng_test_ring_failure = false;
        REQUIRE(collector.role_filter_map_fd() == -1);
        REQUIRE(hng_test_live_skeletons == 0 && hng_test_live_rings == 0);

        const int attaches_before = hng_test_attach_calls;
        REQUIRE(collector.prepare());
        const int fd = collector.role_filter_map_fd();
        REQUIRE(fd == hng_test_last_filter_fd && fd >= 0);
        REQUIRE(hng_test_live_skeletons == 1 && hng_test_live_rings == 1);
        REQUIRE(hng_test_attach_calls == attaches_before);
        REQUIRE(collector.epoll_fd() == -1);
        REQUIRE(collector.consume(1) == 0);
        REQUIRE(hng_test_consume_calls == 0);

        // 重复 prepare、以及已准备未挂载时的 init 都不得改动已准备状态。
        REQUIRE(!collector.prepare());
        REQUIRE(!collector.init());
        REQUIRE(collector.role_filter_map_fd() == fd);
        REQUIRE(hng_test_attach_calls == attaches_before);
        REQUIRE(hng_test_live_skeletons == 1 && hng_test_live_rings == 1);

        REQUIRE(collector.attach());
        REQUIRE(hng_test_attach_calls == attaches_before + 1);
        REQUIRE(!collector.attach());
        REQUIRE(!collector.init());
        REQUIRE(collector.role_filter_map_fd() == fd);
        REQUIRE(collector.epoll_fd() >= 0);

        reset_consume();
        hng_test_consume_successes = 1;
        REQUIRE(collector.consume(7) == 1);
        REQUIRE(hng_test_consume_calls == 1);
        REQUIRE(hng_test_consume_budget == 7);

        reset_consume();
        REQUIRE(collector.consume(1) == -EIO);
        REQUIRE(hng_test_consume_calls == 1);

        // detach 只停止新事件，ringbuf 仍可继续排空。
        const int detaches_before = hng_test_detach_calls;
        collector.detach();
        REQUIRE(hng_test_detach_calls == detaches_before + 1);
        collector.detach();
        REQUIRE(hng_test_detach_calls == detaches_before + 1);
        reset_consume();
        hng_test_consume_successes = 1;
        REQUIRE(collector.consume(1) == 1);
        REQUIRE(hng_test_consume_calls == 1);
    }
    REQUIRE(hng_test_live_skeletons == 0 && hng_test_live_rings == 0);
    REQUIRE(!hng_test_bad_cleanup_order);

    // 独立 attach 失败保留已准备资源，重试成功；析构仍回收全部资源。
    {
        Collector collector(queue);
        REQUIRE(collector.prepare());
        const int fd = collector.role_filter_map_fd();
        REQUIRE(fd == hng_test_last_filter_fd);
        reset_consume();
        hng_test_attach_failure = true;
        REQUIRE(!collector.attach());
        REQUIRE(collector.role_filter_map_fd() == fd);
        REQUIRE(collector.consume(1) == 0);
        REQUIRE(hng_test_consume_calls == 0);
        REQUIRE(hng_test_live_skeletons == 1 && hng_test_live_rings == 1);
        hng_test_attach_failure = false;
        REQUIRE(collector.attach());
        REQUIRE(collector.role_filter_map_fd() == fd);
    }
    REQUIRE(hng_test_live_skeletons == 0 && hng_test_live_rings == 0);
    REQUIRE(!hng_test_bad_cleanup_order);

    {
        Collector collector(queue);
        REQUIRE(collector.role_filter_map_fd() == -1);
        REQUIRE(collector.consume(1) == 0);
        REQUIRE(hng_test_consume_calls == 0);
        hng_test_open_failure = true;
        REQUIRE(!collector.init());
        REQUIRE(hng_test_live_skeletons == 0 && hng_test_live_rings == 0);
        REQUIRE(collector.role_filter_map_fd() == -1);
        hng_test_open_failure      = false;

        const int attaches_before  = hng_test_attach_calls;
        hng_test_event_fd_override = -EBADF;
        REQUIRE(!collector.init());
        REQUIRE(hng_test_attach_calls == attaches_before);
        REQUIRE(hng_test_live_skeletons == 0 && hng_test_live_rings == 0);
        REQUIRE(collector.role_filter_map_fd() == -1);
        hng_test_event_fd_override.reset();
        hng_test_filter_fd_override = -EBADF;
        REQUIRE(!collector.init());
        REQUIRE(hng_test_attach_calls == attaches_before);
        REQUIRE(hng_test_live_skeletons == 0 && hng_test_live_rings == 0);
        REQUIRE(collector.role_filter_map_fd() == -1);
        hng_test_filter_fd_override.reset();

        hng_test_attach_failure = true;
        REQUIRE(!collector.init());
        REQUIRE(hng_test_live_skeletons == 0 && hng_test_live_rings == 0);
        REQUIRE(collector.role_filter_map_fd() == -1);
        hng_test_attach_failure = false;
        hng_test_ring_failure   = true;
        REQUIRE(!collector.init());
        REQUIRE(hng_test_live_skeletons == 0 && hng_test_live_rings == 0);
        REQUIRE(collector.role_filter_map_fd() == -1);
        hng_test_ring_failure = false;

        REQUIRE(collector.init());
        const int fd = collector.role_filter_map_fd();
        REQUIRE(fd == hng_test_last_filter_fd);
        REQUIRE(hng_test_last_ring->map_fd == hng_test_last_event_fd);
        const int opens_before = hng_test_open_calls;
        REQUIRE(!collector.init());
        REQUIRE(hng_test_open_calls == opens_before);
        REQUIRE(collector.role_filter_map_fd() == fd);
        REQUIRE(hng_test_live_skeletons == 1 && hng_test_live_rings == 1);

        auto* ring  = hng_test_last_ring;
        Event event = sample<Event>();
        REQUIRE(ring->callback(nullptr, &event, sizeof(event)) == -EINVAL);
        REQUIRE(ring->callback(ring->context, nullptr, sizeof(event)) == -EINVAL);
        REQUIRE(ring->callback(ring->context, &event, 0) == -EINVAL);
        REQUIRE(ring->callback(ring->context, &event, sizeof(event) - 1) ==
                -EINVAL);
        REQUIRE(queue.empty());

        alignas(Event) std::array<unsigned char, sizeof(Event) + 9> payload{};
        std::memcpy(payload.data() + 1, &event, sizeof(event));
        reset_consume();
        hng_test_deliver_payload = true;
        hng_test_payload         = payload.data() + 1;
        hng_test_payload_size    = sizeof(event);
        REQUIRE(collector.consume(1) == 1);
        REQUIRE(hng_test_callback_result == 0 && hng_test_consume_calls == 1);
        // 回调后覆写 ringbuf 借用内存，队列仍须持有独立事件值。
        payload.fill(0);
        Event received{};
        REQUIRE(queue.pop(received) && same_event(received, event));
        REQUIRE(queue.empty());

        // 对更长载荷只复制已知 ABI 前缀。
        std::memcpy(payload.data() + 1, &event, sizeof(event));
        REQUIRE(ring->callback(ring->context, payload.data() + 1,
                               payload.size() - 1) == 0);
        REQUIRE(queue.pop(received) && same_event(received, event));

        // 满队列不覆写已有元素，也不向 libbpf 报错。
        for (int i = 0; i < 4; ++i)
            REQUIRE(ring->callback(ring->context, &event, sizeof(event)) == 0);
        Event different{};
        REQUIRE(ring->callback(ring->context, &different, sizeof(different)) ==
                0);
        REQUIRE(queue.size() == 4);
        for (int i = 0; i < 4; ++i)
            REQUIRE(queue.pop(received) && same_event(received, event));
        REQUIRE(queue.empty());

        reset_consume();
        hng_test_consume_error = -EIO;
        REQUIRE(collector.consume(1) == -EIO);
        REQUIRE(hng_test_consume_calls == 1);

        reset_consume();
        hng_test_deliver_payload = true;
        hng_test_payload         = &event;
        hng_test_payload_size    = sizeof(event) - 1;
        REQUIRE(collector.consume(1) == -EINVAL);
        REQUIRE(hng_test_callback_result == -EINVAL);
        REQUIRE(hng_test_consume_calls == 1);
        REQUIRE(queue.empty());
        reset_consume();
    }
    REQUIRE(hng_test_live_skeletons == 0 && hng_test_live_rings == 0);
    REQUIRE(!hng_test_bad_cleanup_order);

    // 0 是有效 fd，不能按布尔值判断有效性。
    hng_test_filter_fd_override = 0;
    {
        Collector collector(queue);
        REQUIRE(collector.init());
        REQUIRE(collector.role_filter_map_fd() == 0);
    }
    hng_test_filter_fd_override.reset();
    hng_test_event_fd_override = 0;
    {
        Collector collector(queue);
        REQUIRE(collector.init());
        REQUIRE(hng_test_last_ring->map_fd == 0);
    }
    hng_test_event_fd_override.reset();
    REQUIRE(hng_test_live_skeletons == 0 && hng_test_live_rings == 0);
    REQUIRE(!hng_test_bad_cleanup_order);
}

void verify_multiple_instances()
{
    hng::SPSC_Queue<file_access_data> files(1), more_files(1);
    hng::SPSC_Queue<syscall_event> syscalls(1);
    hng::SPSC_Queue<network_data> networks(1);
    std::unique_ptr<CollectorType> first =
        std::make_unique<FileEventCollector>(files);
    auto second = std::make_unique<FileEventCollector>(more_files);
    auto third  = std::make_unique<SyscallEventCollector>(syscalls);
    auto fourth = std::make_unique<NetworkEventCollector>(networks);
    REQUIRE(first->init() && second->init() && third->init() && fourth->init());
    REQUIRE(hng_test_live_skeletons == 4 && hng_test_live_rings == 4);
    first.reset();  // 验证虚析构；其余采集器的资源仍然存活。
    REQUIRE(hng_test_live_skeletons == 3 && hng_test_live_rings == 3);
    REQUIRE(!hng_test_bad_cleanup_order);
    third.reset();
    second.reset();
    fourth.reset();
    REQUIRE(hng_test_live_skeletons == 0 && hng_test_live_rings == 0);
    REQUIRE(!hng_test_bad_cleanup_order);
}
}  // namespace

int main()
{
    try {
        verify<FileEventCollector, file_access_data>();
        verify<SyscallEventCollector, syscall_event>();
        verify<NetworkEventCollector, network_data>();
        verify_multiple_instances();
        std::printf("PASS: collector filter map, %d checks (skeleton mocks)\n",
                    checks);
        return 0;
    }
    catch (const std::exception& error) {
        std::fprintf(stderr, "FAIL: %s\n", error.what());
        return 1;
    }
}
