/**
 * @file test_collector_syscall_line.cc
 * @brief 系统调用采集线的记录解析、malformed 统计与 loader/reader
 *        合并测试。
 * @note 使用骨架与 libbpf 替身，无特权；不验证真实内核加载。
 */
#include "agent/bpf_loader/include/bpf_loader_factory.hpp"
#include "agent/collector/src/collector.hpp"
#include "test/fixtures/bpf_loader_stub.hpp"

#include <fcntl.h>
#include <linux/bpf.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>

namespace {

int checks = 0;
#define REQUIRE(expression)                                                   \
    do {                                                                      \
        ++checks;                                                             \
        if (!(expression))                                                    \
            throw std::runtime_error(std::string(#expression) + " at line " + \
                                     std::to_string(__LINE__));               \
    } while (false)

constexpr const char* kSkeleton = "syscalls_collector";
int backing_fd                  = -1;
std::map<int, int> duplicate_origins;
std::uint64_t reserve_values[2] = {0, 0};
std::uint64_t pending_values[2] = {0, 0};

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

struct TempTracefs {
    std::filesystem::path root;

    TempTracefs()
    {
        std::string pattern = (std::filesystem::temp_directory_path() /
                               "hng_collector_line_tracefs_XXXXXX")
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

    void remove(const std::string& section)
    {
        std::string group;
        std::string event;
        if (!split_tracepoint(section, group, event)) {
            return;
        }
        std::error_code error;
        std::filesystem::remove_all(root / "events" / group / event, error);
    }
};

void add_syscall_programs(TempTracefs& tracefs)
{
    for (const std::string& section : hng_test_program_sections(kSkeleton)) {
        tracefs.add(section);
    }
}

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

void reset_stub()
{
    hng_test_open_failure             = false;
    hng_test_load_failure             = false;
    hng_test_attach_failure           = false;
    hng_test_ring_failure             = false;
    hng_test_bad_cleanup_order        = false;
    hng_test_live_skeletons           = 0;
    hng_test_live_rings               = 0;
    hng_test_live_links               = 0;
    hng_test_next_fd                  = 100;
    hng_test_last_filter_fd           = -1;
    hng_test_last_event_fd            = -1;
    hng_test_last_reserve_failures_fd = -1;
    hng_test_last_pending_lost_fd     = -1;
    hng_test_event_fd_override.reset();
    hng_test_filter_fd_override.reset();
    hng_test_pending_lost_fd_override.reset();
    hng_test_event_spec_override.reset();
    hng_test_filter_spec_override.reset();
    hng_test_reserve_spec_override.reset();
    hng_test_pending_spec_override.reset();
    hng_test_attach_failure_sections.clear();
    hng_test_map_specs.clear();
    duplicate_origins.clear();
    reserve_values[0]          = 0;
    reserve_values[1]          = 0;
    pending_values[0]          = 0;
    pending_values[1]          = 0;
    hng_test_consume_calls     = 0;
    hng_test_consume_successes = 0;
    hng_test_consume_error     = -EIO;
    hng_test_consume_budget    = 0;
    hng_test_deliver_payload   = false;
    hng_test_payload           = nullptr;
    hng_test_payload_size      = 0;
    hng_test_callback_result   = 0;
}

void reset_consume()
{
    hng_test_consume_calls     = 0;
    hng_test_consume_successes = 0;
    hng_test_consume_error     = -EIO;
    hng_test_consume_budget    = 0;
    hng_test_deliver_payload   = false;
    hng_test_payload           = nullptr;
    hng_test_payload_size      = 0;
    hng_test_callback_result   = 0;
}

/// @brief EXEC 子类型的 ringbuf 记录长度：事件头 + exec 载荷。
constexpr std::size_t kExecRecordSize =
    sizeof(struct syscall_event_head) + sizeof(struct exec_event);

syscall_event sample()
{
    syscall_event event{};
    event.hdr.head.pid = 456;
    event.hdr.name     = SYSCALL_EVENT_EXECVE;
    event.hdr.subtype  = EXEC_EVENT;
    std::memset(event.exec_event.invoked, 'x', sizeof(event.exec_event.invoked));
    std::memset(event.exec_event.image, 'y', sizeof(event.exec_event.image));
    std::memset(event.exec_event.argv0, 'a', sizeof(event.exec_event.argv0));
    std::memset(event.exec_event.argv1, 'b', sizeof(event.exec_event.argv1));
    std::memset(event.exec_event.argv2, 'c', sizeof(event.exec_event.argv2));
    std::memset(event.exec_event.argv3, 'd', sizeof(event.exec_event.argv3));
    std::memset(event.exec_event.ld_preload, 'e',
                sizeof(event.exec_event.ld_preload));
    std::memset(event.exec_event.ld_library_path, 'f',
                sizeof(event.exec_event.ld_library_path));
    event.exec_event.flags                 = 7;
    event.exec_event.image_flags           = PATH_TRUNCATED;
    event.credential_event.kind            = CREDENTIAL_CAPS;
    event.credential_event.requested_count = 2;
    event.credential_event.requested[0]    = 1000;
    event.credential_event.requested[1]    = 1001;
    event.credential_event.cap_effective   = 0x1;
    event.credential_event.cap_permitted   = 0x2;
    event.credential_event.cap_inheritable = 0x4;
    event.namespace_event.flags            = 0x50000000;
    event.namespace_event.ns_mask          = 0x50000000;
    event.namespace_event.fd               = 7;
    std::memset(event.namespace_event.source, 's',
                sizeof(event.namespace_event.source));
    std::memset(event.namespace_event.target, 't',
                sizeof(event.namespace_event.target));
    std::memset(event.namespace_event.fstype, 'f',
                sizeof(event.namespace_event.fstype));
    event.signal_event.sig        = 9;
    event.signal_event.target_pid = 1234;
    event.signal_event.target_tid = 2;
    event.signal_event.si_code    = -6;
    return event;
}

bool same_event(const syscall_event& left, const syscall_event& right)
{
    return left.hdr.head.pid == right.hdr.head.pid &&
           left.hdr.name == right.hdr.name &&
           left.hdr.subtype == right.hdr.subtype &&
           left.exec_event.flags == right.exec_event.flags &&
           left.exec_event.image_flags == right.exec_event.image_flags &&
           std::memcmp(left.exec_event.invoked, right.exec_event.invoked,
                       sizeof(left.exec_event.invoked)) == 0 &&
           std::memcmp(left.exec_event.image, right.exec_event.image,
                       sizeof(left.exec_event.image)) == 0 &&
           std::memcmp(left.exec_event.argv0, right.exec_event.argv0,
                       sizeof(left.exec_event.argv0)) == 0 &&
           std::memcmp(left.exec_event.argv1, right.exec_event.argv1,
                       sizeof(left.exec_event.argv1)) == 0 &&
           std::memcmp(left.exec_event.argv2, right.exec_event.argv2,
                       sizeof(left.exec_event.argv2)) == 0 &&
           std::memcmp(left.exec_event.argv3, right.exec_event.argv3,
                       sizeof(left.exec_event.argv3)) == 0 &&
           std::memcmp(left.exec_event.ld_preload, right.exec_event.ld_preload,
                       sizeof(left.exec_event.ld_preload)) == 0 &&
           std::memcmp(left.exec_event.ld_library_path,
                       right.exec_event.ld_library_path,
                       sizeof(left.exec_event.ld_library_path)) == 0 &&
           left.credential_event.kind == right.credential_event.kind &&
           left.credential_event.requested_count ==
               right.credential_event.requested_count &&
           std::memcmp(left.credential_event.requested,
                       right.credential_event.requested,
                       sizeof(left.credential_event.requested)) == 0 &&
           left.namespace_event.flags == right.namespace_event.flags &&
           left.namespace_event.ns_mask == right.namespace_event.ns_mask &&
           std::memcmp(left.namespace_event.source, right.namespace_event.source,
                       sizeof(left.namespace_event.source)) == 0 &&
           std::memcmp(left.namespace_event.target, right.namespace_event.target,
                       sizeof(left.namespace_event.target)) == 0 &&
           left.signal_event.sig == right.signal_event.sig &&
           left.signal_event.target_pid == right.signal_event.target_pid;
}

void verify_line(const std::filesystem::path& tracefs_root)
{
    reset_stub();
    hng::EventChannel<syscall_event> channel(4);
    auto loader = hng::BpfLoaderFactory::create_syscall_probe(tracefs_root);
    REQUIRE(loader->prepare());
    SyscallEventCollector collector(channel.writer(), loader->maps());

    REQUIRE(loader->state() == hng::BpfProgramState::PREPARED);
    REQUIRE(collector.stats().consumed == 0);
    REQUIRE(collector.epoll_fd() == -1);
    REQUIRE(collector.consume(1) == 0);
    REQUIRE(hng_test_consume_calls == 0);

    REQUIRE(collector.prepare());
    REQUIRE(hng_test_live_skeletons == 1 && hng_test_live_rings == 1);
    REQUIRE(collector.epoll_fd() >= 0);
    REQUIRE(!collector.prepare());

    const int programs = static_cast<int>(hng_test_last_object->programs.size());
    REQUIRE(loader->attach());
    REQUIRE(loader->state() == hng::BpfProgramState::ATTACHED);
    REQUIRE(hng_test_live_links == programs);
    collector.mark_attached(true);
    REQUIRE(!loader->attach());

    hng::CollectorLineStats stats = collector.stats();
    REQUIRE(stats.line == "syscall");
    REQUIRE(stats.attached);
    REQUIRE(stats.skipped_probes == 0);
    REQUIRE(stats.attach_failed == 0);
    REQUIRE(stats.reserve_failures == 0);
    REQUIRE(stats.pending_lost == 0);
    reserve_values[0] = 2;
    reserve_values[1] = 3;
    pending_values[0] = 4;
    pending_values[1] = 5;
    stats             = collector.stats();
    REQUIRE(stats.reserve_failures == 5);
    REQUIRE(stats.pending_lost == 9);

    auto* ring          = hng_test_last_ring;
    syscall_event event = sample();
    REQUIRE(ring->callback(nullptr, &event, kExecRecordSize) == -EINVAL);
    REQUIRE(ring->callback(ring->context, nullptr, kExecRecordSize) == -EINVAL);
    REQUIRE(channel.empty());

    const std::uint64_t malformed_before = collector.stats().malformed;
    REQUIRE(ring->callback(ring->context, &event, 0) == 0);
    REQUIRE(ring->callback(ring->context, &event,
                           sizeof(struct syscall_event_head)) == 0);
    REQUIRE(ring->callback(ring->context, &event, kExecRecordSize - 1) == 0);
    REQUIRE(ring->callback(ring->context, &event, kExecRecordSize + 1) == 0);
    REQUIRE(channel.empty());
    REQUIRE(collector.stats().malformed == malformed_before + 4);
    REQUIRE(collector.stats().consumed == 0);

    alignas(syscall_event) std::array<unsigned char, kExecRecordSize + 2>
        payload{};
    std::memcpy(payload.data() + 1, &event, kExecRecordSize);
    reset_consume();
    hng_test_deliver_payload = true;
    hng_test_payload         = payload.data() + 1;
    hng_test_payload_size    = kExecRecordSize;
    REQUIRE(collector.consume(1) == 1);
    REQUIRE(hng_test_callback_result == 0 && hng_test_consume_calls == 1);
    payload.fill(0);
    syscall_event received{};
    REQUIRE(channel.reader().try_pop(received) && same_event(received, event));
    REQUIRE(channel.empty());

    for (int i = 0; i < 4; ++i) {
        REQUIRE(ring->callback(ring->context, &event, kExecRecordSize) == 0);
    }
    syscall_event different{};
    different.hdr.subtype = EXEC_EVENT;
    REQUIRE(ring->callback(ring->context, &different, kExecRecordSize) == 0);
    REQUIRE(channel.size() == 4);
    for (int i = 0; i < 4; ++i) {
        REQUIRE(channel.reader().try_pop(received) &&
                same_event(received, event));
    }
    REQUIRE(channel.empty());

    reset_consume();
    hng_test_consume_error = -EIO;
    REQUIRE(collector.consume(1) == -EIO);
    REQUIRE(collector.stats().consume_errors == 1);

    loader->detach();
    REQUIRE(hng_test_live_links == 0);
    collector.mark_attached(false);
    REQUIRE(!collector.stats().attached);
    REQUIRE(collector.epoll_fd() >= 0);
    reset_consume();
    hng_test_consume_successes = 1;
    REQUIRE(collector.consume(1) == 1);
    REQUIRE(hng_test_consume_calls == 1);
    loader->detach();
    REQUIRE(hng_test_live_links == 0);
}

void verify_record_framing(const std::filesystem::path& tracefs_root)
{
    reset_stub();
    reset_consume();
    hng::EventChannel<syscall_event> channel(16);
    auto loader = hng::BpfLoaderFactory::create_syscall_probe(tracefs_root);
    REQUIRE(loader->prepare());
    SyscallEventCollector collector(channel.writer(), loader->maps());
    REQUIRE(collector.prepare());
    auto* ring = hng_test_last_ring;

    struct Case {
        enum syscall_event_type subtype;
        std::size_t payload_size;
    };
    const Case cases[] = {
        {PROCESS_EVENT, sizeof(struct process_event)},
        {EXEC_EVENT, sizeof(struct exec_event)},
        {CREDENTIAL_EVENT, sizeof(struct credential_event)},
        {NAMESPACE_EVENT, sizeof(struct namespace_event)},
        {FILE_EVENT, sizeof(struct file_event)},
        {MEMORY_EVENT, sizeof(struct memory_event)},
        {NETWORK_EVENT, sizeof(struct network_event)},
        {KERNEL_EVENT, sizeof(struct kernel_event)},
        {SIGNAL_EVENT, sizeof(struct signal_event)},
    };
    const std::size_t head = sizeof(struct syscall_event_head);
    REQUIRE(head == 80);
    alignas(syscall_event) std::array<unsigned char, head + sizeof(syscall_event)>
        record{};

    std::uint64_t malformed = 0;
    for (const Case& c : cases) {
        const std::size_t record_size = head + c.payload_size;
        REQUIRE(hng::detail::SyscallRecordSize(c.subtype) == record_size);

        syscall_event source{};
        source.hdr.subtype  = c.subtype;
        source.hdr.head.pid = 456;
        std::memset(record.data(), 0, record.size());
        std::memcpy(record.data(), &source, record_size);
        std::memset(record.data() + head, 0x5A, c.payload_size);

        REQUIRE(ring->callback(ring->context, record.data(), record_size) == 0);
        syscall_event received{};
        REQUIRE(channel.reader().try_pop(received));
        REQUIRE(received.hdr.subtype == c.subtype);
        REQUIRE(received.hdr.head.pid == 456);
        REQUIRE(std::memcmp(reinterpret_cast<const char*>(&received) + head,
                            record.data() + head, c.payload_size) == 0);
        const auto* bytes = reinterpret_cast<const unsigned char*>(&received);
        for (std::size_t i = head + c.payload_size; i < sizeof(syscall_event);
             ++i) {
            REQUIRE(bytes[i] == 0);
        }
        REQUIRE(channel.empty());

        REQUIRE(ring->callback(ring->context, record.data(), record_size + 1) ==
                0);
        REQUIRE(ring->callback(ring->context, record.data(), record_size - 1) ==
                0);
        malformed += 2;
        REQUIRE(collector.stats().malformed == malformed);
    }

    syscall_event unknown{};
    unknown.hdr.subtype = UNKNOWN_EVENT;
    REQUIRE(ring->callback(ring->context, &unknown, head) == 0);
    unknown.hdr.subtype = static_cast<enum syscall_event_type>(10);
    REQUIRE(ring->callback(ring->context, &unknown, head) == 0);
    syscall_event head_only{};
    head_only.hdr.subtype = EXEC_EVENT;
    REQUIRE(ring->callback(ring->context, &head_only, head) == 0);
    malformed += 3;
    REQUIRE(collector.stats().malformed == malformed);
    REQUIRE(collector.stats().consumed == 9);
    REQUIRE(channel.empty());
    REQUIRE(hng::detail::SyscallRecordSize(UNKNOWN_EVENT) == 0);
}

void verify_skipped_stats()
{
    reset_stub();
    TempTracefs tracefs;
    REQUIRE(!tracefs.root.empty());
    add_syscall_programs(tracefs);
    const auto& sections = hng_test_program_sections(kSkeleton);
    std::string missing;
    for (const std::string& section : sections) {
        if (section.rfind("tracepoint/", 0) == 0) {
            missing = section;
            break;
        }
    }
    REQUIRE(!missing.empty());
    tracefs.remove(missing);

    {
        hng::EventChannel<syscall_event> channel(4);
        auto loader = hng::BpfLoaderFactory::create_syscall_probe(tracefs.root);
        REQUIRE(loader->prepare());
        SyscallEventCollector collector(channel.writer(), loader->maps());
        REQUIRE(collector.prepare());
        REQUIRE(loader->stats().skipped_probes == 1);
        const int programs   = static_cast<int>(sections.size());
        bpf_program* skipped = find_program(missing);
        REQUIRE(skipped != nullptr && !skipped->autoload);
        REQUIRE(loader->attach());
        REQUIRE(hng_test_live_links == programs - 1);
        REQUIRE(!skipped->attached);
        loader->detach();
    }
    REQUIRE(hng_test_live_skeletons == 0);
    REQUIRE(hng_test_live_rings == 0);
    REQUIRE(hng_test_live_links == 0);
}

void verify_attach_failure_stats()
{
    reset_stub();
    TempTracefs tracefs;
    REQUIRE(!tracefs.root.empty());
    add_syscall_programs(tracefs);
    const auto& sections = hng_test_program_sections(kSkeleton);
    const int programs   = static_cast<int>(sections.size());

    {
        hng::EventChannel<syscall_event> channel(4);
        auto loader = hng::BpfLoaderFactory::create_syscall_probe(tracefs.root);
        REQUIRE(loader->prepare());
        SyscallEventCollector collector(channel.writer(), loader->maps());
        REQUIRE(collector.prepare());
        hng_test_attach_failure_sections = {sections[1]};
        REQUIRE(loader->attach());
        REQUIRE(loader->stats().attach_failed == 1);
        REQUIRE(hng_test_live_links == programs - 1);
        loader->detach();
    }
    REQUIRE(hng_test_live_skeletons == 0);
    REQUIRE(hng_test_live_rings == 0);
    REQUIRE(hng_test_live_links == 0);
}

void verify_prepare_failure_cleanup(const std::filesystem::path& tracefs_root)
{
    reset_stub();
    hng::EventChannel<syscall_event> channel(4);
    auto loader = hng::BpfLoaderFactory::create_syscall_probe(tracefs_root);
    REQUIRE(loader->prepare());
    SyscallEventCollector collector(channel.writer(), loader->maps());

    hng_test_ring_failure = true;
    REQUIRE(!collector.prepare());
    REQUIRE(hng_test_live_rings == 0);
    REQUIRE(collector.epoll_fd() == -1);
    REQUIRE(collector.consume(1) == 0);
    hng_test_ring_failure = false;
}

}  // namespace

extern "C" long __wrap_syscall(long number, ...)
{
    va_list args;
    va_start(args, number);
    const int command = va_arg(args, int);
    auto* attr        = va_arg(args, union bpf_attr*);
    const auto size   = va_arg(args, std::size_t);
    va_end(args);

    if (number != SYS_bpf || command != BPF_OBJ_GET_INFO_BY_FD ||
        attr == nullptr || size != sizeof(*attr)) {
        errno = EINVAL;
        return -1;
    }
    const int fd                  = static_cast<int>(attr->info.bpf_fd);
    const hng_test_map_spec* spec = hng_test_find_map_spec(fd);
    if (spec == nullptr || attr->info.info_len != sizeof(bpf_map_info)) {
        errno = EBADF;
        return -1;
    }
    auto* info = reinterpret_cast<bpf_map_info*>(attr->info.info);
    if (info == nullptr) {
        errno = EINVAL;
        return -1;
    }
    *info             = {};
    info->type        = spec->type;
    info->key_size    = spec->key_size;
    info->value_size  = spec->value_size;
    info->max_entries = spec->max_entries;
    return 0;
}

extern "C" int __real_fcntl(int fd, int command, ...);

extern "C" int __wrap_fcntl(int fd, int command, ...)
{
    if (command != F_DUPFD_CLOEXEC) {
        return __real_fcntl(fd, command);
    }
    if (hng_test_find_map_spec(fd) == nullptr || backing_fd < 0) {
        errno = EBADF;
        return -1;
    }
    const int copy = __real_fcntl(backing_fd, F_DUPFD_CLOEXEC, 0);
    if (copy >= 0) {
        duplicate_origins[copy] = fd;
    }
    return copy;
}

extern "C" int __wrap_bpf_map_lookup_elem(int fd, const void* key, void* value)
{
    if (key == nullptr || value == nullptr) {
        errno = EINVAL;
        return -1;
    }
    const auto found = duplicate_origins.find(fd);
    if (found == duplicate_origins.end()) {
        errno = EBADF;
        return -1;
    }
    auto* cells = static_cast<std::uint64_t*>(value);
    if (found->second == hng_test_last_reserve_failures_fd) {
        cells[0] = reserve_values[0];
        cells[1] = reserve_values[1];
        return 0;
    }
    if (found->second == hng_test_last_pending_lost_fd) {
        cells[0] = pending_values[0];
        cells[1] = pending_values[1];
        return 0;
    }
    errno = ENOENT;
    return -1;
}

extern "C" int __wrap_libbpf_num_possible_cpus(void) { return 2; }

int main()
{
    try {
        backing_fd = ::open("/dev/null", O_RDONLY | O_CLOEXEC);
        REQUIRE(backing_fd >= 0);
        TempTracefs tracefs;
        REQUIRE(!tracefs.root.empty());
        add_syscall_programs(tracefs);
        verify_line(tracefs.root);
        verify_record_framing(tracefs.root);
        verify_skipped_stats();
        verify_attach_failure_stats();
        verify_prepare_failure_cleanup(tracefs.root);
        ::close(backing_fd);
        REQUIRE(hng_test_live_skeletons == 0);
        REQUIRE(hng_test_live_rings == 0);
        REQUIRE(hng_test_live_links == 0);
        REQUIRE(!hng_test_bad_cleanup_order);
        std::printf("PASS: collector syscall line, %d checks\n", checks);
        return 0;
    }
    catch (const std::exception& error) {
        if (backing_fd >= 0) {
            ::close(backing_fd);
        }
        std::fprintf(stderr, "FAIL: %s\n", error.what());
        return 1;
    }
}
