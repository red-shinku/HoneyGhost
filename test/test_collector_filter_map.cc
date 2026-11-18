/**
 * @file test_collector_filter_map.cc
 * @brief 用真实采集器源码验证初始化事务、回调边界、map fd、消费与资源回收。
 * @note 使用骨架替身，不代表真实内核加载验证。
 */
#include "agent/collector/src/collector.hpp"
#include "test/fixtures/collector_skeleton_stub.hpp"

#include <array>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
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

/// @brief 把 tracepoint/<group>/<event> 拆成组名与事件名
bool split_tracepoint(const std::string& section, std::string& group,
                      std::string& event)
{
    constexpr std::string_view prefix = "tracepoint/";
    if (section.rfind(prefix, 0) != 0) {
        return false;
    }
    const std::size_t separator = section.find('/', prefix.size());
    if (separator == std::string::npos) {
        return false;
    }
    group = section.substr(prefix.size(), separator - prefix.size());
    event = section.substr(separator + 1);
    return !group.empty() && !event.empty() &&
           event.find('/') == std::string::npos;
}

/// @brief 由 mkdtemp 独占创建的 tracefs 根，析构时整体删除
struct TempTracefs {
    std::filesystem::path root;

    TempTracefs()
    {
        std::string pattern = (std::filesystem::temp_directory_path() /
                               "hng_collector_tracefs_XXXXXX")
                                  .string();
        if (::mkdtemp(pattern.data()) != nullptr) {
            root = pattern;
        }
    }

    ~TempTracefs()
    {
        if (!root.empty()) {
            std::error_code error;
            std::filesystem::remove_all(root, error);
        }
    }

    /// @brief 为 tracepoint/<group>/<event> 创建 events/<group>/<event>/id
    void add(const std::string& section)
    {
        if (root.empty()) {
            return;
        }
        std::string group;
        std::string event;
        if (!split_tracepoint(section, group, event)) {
            return;
        }
        const std::filesystem::path directory = root / "events" / group / event;
        std::filesystem::create_directories(directory);
        std::ofstream id(directory / "id");
        id << "1\n";
    }
};

/// @brief 写上三个骨架的全部程序 section
void add_all_programs(TempTracefs& tracefs)
{
    for (const char* skeleton :
         {"files_collector", "syscalls_collector", "networks_collector"}) {
        for (const std::string& section : hng_test_program_sections(skeleton)) {
            tracefs.add(section);
        }
    }
}

int program_count(const char* skeleton)
{
    return static_cast<int>(hng_test_program_sections(skeleton).size());
}

/// @brief 按 section 取替身程序
bpf_program* find_program(const std::string& section)
{
    REQUIRE(hng_test_last_object != nullptr);
    for (bpf_program& program : hng_test_last_object->programs) {
        if (program.section == section) {
            return &program;
        }
    }
    return nullptr;
}

template <class Collector>
struct CollectorInfo;

template <>
struct CollectorInfo<FileEventCollector> {
    static constexpr const char* skeleton = "files_collector";
};

template <>
struct CollectorInfo<SyscallEventCollector> {
    static constexpr const char* skeleton = "syscalls_collector";
};

template <>
struct CollectorInfo<NetworkEventCollector> {
    static constexpr const char* skeleton = "networks_collector";
};

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

void reset_attach_controls()
{
    hng_test_attach_failure = false;
    hng_test_attach_failure_sections.clear();
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
void verify(const std::filesystem::path& tracefs_root)
{
    reset_attach_controls();
    hng::EventChannel<Event> channel(4);
    reset_consume();
    // prepare 只加载骨架、建 ringbuf 并取 map fd；探针未挂载前不消费。
    {
        Collector collector(channel.writer(), tracefs_root);
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
        const int programs =
            static_cast<int>(hng_test_last_object->programs.size());
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
        REQUIRE(hng_test_attach_calls == attaches_before + programs);
        REQUIRE(hng_test_live_links == programs);
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

        // detach 只停止新事件，销毁链接；ringbuf 仍可继续排空。
        collector.detach();
        REQUIRE(hng_test_live_links == 0);
        REQUIRE(collector.epoll_fd() >= 0);
        collector.detach();
        REQUIRE(hng_test_live_links == 0);
        reset_consume();
        hng_test_consume_successes = 1;
        REQUIRE(collector.consume(1) == 1);
        REQUIRE(hng_test_consume_calls == 1);
    }
    REQUIRE(hng_test_live_skeletons == 0 && hng_test_live_rings == 0);
    REQUIRE(hng_test_live_links == 0);
    REQUIRE(!hng_test_bad_cleanup_order);

    // 全部探针 attach 失败时保留已准备资源，重试成功；析构仍回收全部资源。
    {
        Collector collector(channel.writer(), tracefs_root);
        REQUIRE(collector.prepare());
        const int programs =
            static_cast<int>(hng_test_last_object->programs.size());
        const int fd = collector.role_filter_map_fd();
        REQUIRE(fd == hng_test_last_filter_fd);
        reset_consume();
        hng_test_attach_failure = true;
        REQUIRE(!collector.attach());
        REQUIRE(collector.stats().attach_failed ==
                static_cast<std::uint64_t>(programs));
        REQUIRE(collector.stats().skipped_probes == 0);
        REQUIRE(hng_test_live_links == 0);
        REQUIRE(collector.role_filter_map_fd() == fd);
        REQUIRE(collector.consume(1) == 0);
        REQUIRE(hng_test_consume_calls == 0);
        REQUIRE(hng_test_live_skeletons == 1 && hng_test_live_rings == 1);
        hng_test_attach_failure = false;
        REQUIRE(collector.attach());
        REQUIRE(hng_test_live_links == programs);
        REQUIRE(collector.role_filter_map_fd() == fd);
    }
    REQUIRE(hng_test_live_skeletons == 0 && hng_test_live_rings == 0);
    REQUIRE(hng_test_live_links == 0);
    REQUIRE(!hng_test_bad_cleanup_order);

    {
        Collector collector(channel.writer(), tracefs_root);
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
        REQUIRE(channel.empty());

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
        REQUIRE(channel.reader().try_pop(received) &&
                same_event(received, event));
        REQUIRE(channel.empty());

        // 对更长载荷只复制已知 ABI 前缀。
        std::memcpy(payload.data() + 1, &event, sizeof(event));
        REQUIRE(ring->callback(ring->context, payload.data() + 1,
                               payload.size() - 1) == 0);
        REQUIRE(channel.reader().try_pop(received) &&
                same_event(received, event));

        // 满队列不覆写已有元素，也不向 libbpf 报错。
        for (int i = 0; i < 4; ++i)
            REQUIRE(ring->callback(ring->context, &event, sizeof(event)) == 0);
        Event different{};
        REQUIRE(ring->callback(ring->context, &different, sizeof(different)) ==
                0);
        REQUIRE(channel.size() == 4);
        for (int i = 0; i < 4; ++i)
            REQUIRE(channel.reader().try_pop(received) &&
                    same_event(received, event));
        REQUIRE(channel.empty());

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
        REQUIRE(channel.empty());
        reset_consume();
    }
    REQUIRE(hng_test_live_skeletons == 0 && hng_test_live_rings == 0);
    REQUIRE(hng_test_live_links == 0);
    REQUIRE(!hng_test_bad_cleanup_order);

    // 0 是有效 fd，不能按布尔值判断有效性。
    hng_test_filter_fd_override = 0;
    {
        Collector collector(channel.writer(), tracefs_root);
        REQUIRE(collector.init());
        REQUIRE(collector.role_filter_map_fd() == 0);
    }
    hng_test_filter_fd_override.reset();
    hng_test_event_fd_override = 0;
    {
        Collector collector(channel.writer(), tracefs_root);
        REQUIRE(collector.init());
        REQUIRE(hng_test_last_ring->map_fd == 0);
    }
    hng_test_event_fd_override.reset();
    REQUIRE(hng_test_live_skeletons == 0 && hng_test_live_rings == 0);
    REQUIRE(hng_test_live_links == 0);
    REQUIRE(!hng_test_bad_cleanup_order);
}

/// @brief tracepoint 缺失的程序不 autoload，也不参与 attach
template <class Collector, class Event>
void verify_skips_missing_tracepoint()
{
    reset_attach_controls();
    TempTracefs tracefs;
    REQUIRE(!tracefs.root.empty());
    add_all_programs(tracefs);
    const auto& sections =
        hng_test_program_sections(CollectorInfo<Collector>::skeleton);
    std::string missing;
    for (const std::string& section : sections) {
        if (section.rfind("tracepoint/", 0) == 0) {
            missing = section;
            break;
        }
    }
    REQUIRE(!missing.empty());
    std::string group;
    std::string event;
    REQUIRE(split_tracepoint(missing, group, event));
    std::error_code error;
    std::filesystem::remove_all(tracefs.root / "events" / group / event, error);

    hng::EventChannel<Event> channel(4);
    Collector collector(channel.writer(), tracefs.root);
    REQUIRE(collector.prepare());

    const int programs = static_cast<int>(hng_test_last_object->programs.size());
    const int calls_before = hng_test_attach_calls;
    REQUIRE(collector.stats().skipped_probes == 1);
    REQUIRE(collector.stats().attach_failed == 0);
    bpf_program* skipped = find_program(missing);
    REQUIRE(skipped != nullptr && !skipped->autoload);

    REQUIRE(collector.attach());
    REQUIRE(hng_test_attach_calls == calls_before + programs - 1);
    REQUIRE(hng_test_live_links == programs - 1);
    REQUIRE(!skipped->attached);
    const hng::CollectorLineStats stats = collector.stats();
    REQUIRE(stats.skipped_probes == 1);
    REQUIRE(stats.attach_failed == 0);
    REQUIRE(stats.attached);

    collector.detach();
    REQUIRE(hng_test_live_links == 0);
    REQUIRE(!collector.stats().attached);
}

/// @brief 全部 tracepoint 缺失时只跳过，不拖垮启动；非 tracepoint 程序照常挂载
template <class Collector, class Event>
void verify_all_tracepoints_skipped()
{
    reset_attach_controls();
    TempTracefs tracefs;  // 不创建任何 events 条目
    REQUIRE(!tracefs.root.empty());
    const auto& sections =
        hng_test_program_sections(CollectorInfo<Collector>::skeleton);
    int tracepoints = 0;
    for (const std::string& section : sections) {
        if (section.rfind("tracepoint/", 0) == 0) {
            ++tracepoints;
        }
    }
    REQUIRE(tracepoints > 0);

    hng::EventChannel<Event> channel(4);
    Collector collector(channel.writer(), tracefs.root);
    REQUIRE(collector.prepare());
    const int total = static_cast<int>(hng_test_last_object->programs.size());
    const int calls_before = hng_test_attach_calls;

    REQUIRE(collector.attach());
    REQUIRE(hng_test_attach_calls == calls_before + total - tracepoints);
    REQUIRE(hng_test_live_links == total - tracepoints);
    const hng::CollectorLineStats stats = collector.stats();
    REQUIRE(stats.skipped_probes == static_cast<std::uint64_t>(tracepoints));
    REQUIRE(stats.attach_failed == 0);
    REQUIRE(stats.attached);
    for (const bpf_program& program : hng_test_last_object->programs) {
        const bool is_tracepoint = program.section.rfind("tracepoint/", 0) == 0;
        REQUIRE(program.autoload == !is_tracepoint);
        REQUIRE(program.attached == !is_tracepoint);
    }

    collector.detach();
    REQUIRE(hng_test_live_links == 0);
}

/// @brief 单个程序 attach 失败只计数，其余仍挂载
template <class Collector, class Event>
void verify_partial_attach_failure()
{
    reset_attach_controls();
    TempTracefs tracefs;
    REQUIRE(!tracefs.root.empty());
    add_all_programs(tracefs);
    const auto& sections =
        hng_test_program_sections(CollectorInfo<Collector>::skeleton);
    REQUIRE(sections.size() > 1);
    const std::string failed = sections[1];

    hng::EventChannel<Event> channel(4);
    Collector collector(channel.writer(), tracefs.root);
    REQUIRE(collector.prepare());
    const int programs = static_cast<int>(hng_test_last_object->programs.size());
    const int calls_before           = hng_test_attach_calls;
    hng_test_attach_failure_sections = {failed};

    REQUIRE(collector.attach());
    REQUIRE(hng_test_attach_calls == calls_before + programs);
    REQUIRE(hng_test_live_links == programs - 1);
    for (const bpf_program& program : hng_test_last_object->programs) {
        REQUIRE(program.attached == (program.section != failed));
    }
    const hng::CollectorLineStats stats = collector.stats();
    REQUIRE(stats.attach_failed == 1);
    REQUIRE(stats.skipped_probes == 0);
    REQUIRE(stats.attached);

    collector.detach();
    REQUIRE(hng_test_live_links == 0);
    reset_attach_controls();
}

void verify_multiple_instances()
{
    reset_attach_controls();
    TempTracefs tracefs;
    REQUIRE(!tracefs.root.empty());
    add_all_programs(tracefs);
    hng::EventChannel<file_access_data> files(1), more_files(1);
    hng::EventChannel<syscall_event> syscalls(1);
    hng::EventChannel<network_data> networks(1);
    std::unique_ptr<CollectorType> first =
        std::make_unique<FileEventCollector>(files.writer(), tracefs.root);
    auto second =
        std::make_unique<FileEventCollector>(more_files.writer(), tracefs.root);
    auto third =
        std::make_unique<SyscallEventCollector>(syscalls.writer(), tracefs.root);
    auto fourth =
        std::make_unique<NetworkEventCollector>(networks.writer(), tracefs.root);
    REQUIRE(first->init() && second->init() && third->init() && fourth->init());
    const int files_count    = program_count("files_collector");
    const int syscalls_count = program_count("syscalls_collector");
    const int networks_count = program_count("networks_collector");
    REQUIRE(hng_test_live_links ==
            2 * files_count + syscalls_count + networks_count);
    REQUIRE(hng_test_live_skeletons == 4 && hng_test_live_rings == 4);
    first.reset();  // 验证虚析构；其余采集器的资源仍然存活。
    REQUIRE(hng_test_live_skeletons == 3 && hng_test_live_rings == 3);
    REQUIRE(hng_test_live_links == files_count + syscalls_count + networks_count);
    REQUIRE(!hng_test_bad_cleanup_order);
    third.reset();
    second.reset();
    fourth.reset();
    REQUIRE(hng_test_live_skeletons == 0 && hng_test_live_rings == 0);
    REQUIRE(hng_test_live_links == 0);
    REQUIRE(!hng_test_bad_cleanup_order);
}
}  // namespace

int main()
{
    try {
        TempTracefs tracefs;
        REQUIRE(!tracefs.root.empty());
        add_all_programs(tracefs);
        verify<FileEventCollector, file_access_data>(tracefs.root);
        verify<SyscallEventCollector, syscall_event>(tracefs.root);
        verify<NetworkEventCollector, network_data>(tracefs.root);
        verify_skips_missing_tracepoint<FileEventCollector, file_access_data>();
        verify_skips_missing_tracepoint<SyscallEventCollector, syscall_event>();
        verify_skips_missing_tracepoint<NetworkEventCollector, network_data>();
        verify_all_tracepoints_skipped<FileEventCollector, file_access_data>();
        verify_all_tracepoints_skipped<SyscallEventCollector, syscall_event>();
        verify_all_tracepoints_skipped<NetworkEventCollector, network_data>();
        verify_partial_attach_failure<FileEventCollector, file_access_data>();
        verify_partial_attach_failure<SyscallEventCollector, syscall_event>();
        verify_partial_attach_failure<NetworkEventCollector, network_data>();
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
