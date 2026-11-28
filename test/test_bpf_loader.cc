/**
 * @file test_bpf_loader.cc
 * @brief SyscallProbeLoader 的生命周期、map 校验、统计与资源释放
 *        测试。
 * @note 使用骨架与 libbpf 替身；syscall 只用于读取 map ABI，
 *       无特权。
 */
#include "agent/bpf_loader/include/bpf_loader_factory.hpp"
#include "agent/bpf_loader/include/syscall_probe_loader.hpp"
#include "agent/bpf_loader/include/syscall_probe_maps.hpp"
#include "test/fixtures/bpf_loader_stub.hpp"

#include <linux/bpf.h>
#include <sys/syscall.h>

#include <cerrno>
#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
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

template <class Action>
void require_logic_error(Action action)
{
    try {
        action();
    }
    catch (const std::logic_error&) {
        return;
    }
    throw std::runtime_error("expected std::logic_error");
}

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
                               "hng_bpf_loader_tracefs_XXXXXX")
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
}

void verify_lifecycle(const std::filesystem::path& tracefs_root)
{
    reset_stub();
    {
        auto loader = hng::BpfLoaderFactory::create_syscall_probe(tracefs_root);
        REQUIRE(loader->state() == hng::BpfProgramState::UNPREPARED);
        const hng::BpfProgramStats empty = loader->stats();
        REQUIRE(empty.total_programs == 0 && empty.attached_programs == 0);
        REQUIRE(empty.skipped_probes == 0 && empty.attach_failed == 0);
        require_logic_error([&] { (void)loader->maps(); });

        hng_test_open_failure = true;
        REQUIRE(!loader->prepare());
        REQUIRE(loader->state() == hng::BpfProgramState::UNPREPARED);
        REQUIRE(hng_test_live_skeletons == 0);
        hng_test_open_failure = false;

        REQUIRE(loader->prepare());
        const std::uint64_t programs =
            hng_test_program_sections(kSkeleton).size();
        REQUIRE(loader->state() == hng::BpfProgramState::PREPARED);
        REQUIRE(hng_test_live_skeletons == 1 && hng_test_live_rings == 0);
        const hng::BpfProgramStats prepared = loader->stats();
        REQUIRE(prepared.total_programs == programs);
        REQUIRE(prepared.attached_programs == 0);
        REQUIRE(prepared.skipped_probes == 0);
        REQUIRE(prepared.attach_failed == 0);
        const hng::SyscallProbeMaps maps = loader->maps();
        REQUIRE(maps.events_ringbuf().fd() == hng_test_last_event_fd);
        REQUIRE(maps.reserve_failures_map().fd() ==
                hng_test_last_reserve_failures_fd);
        REQUIRE(maps.pending_lost_map().fd() == hng_test_last_pending_lost_fd);
        REQUIRE(maps.role_filter_map().fd() == hng_test_last_filter_fd);
        REQUIRE(maps.events_ringbuf().spec().type == BPF_MAP_TYPE_RINGBUF);
        REQUIRE(maps.role_filter_map().spec().key_size == 16);
        REQUIRE(maps.role_filter_map().spec().value_size ==
                sizeof(std::uint32_t));
        REQUIRE(maps.role_filter_map().spec().max_entries == 65536);
        REQUIRE(maps.reserve_failures_map().spec().type ==
                BPF_MAP_TYPE_PERCPU_ARRAY);
        REQUIRE(maps.pending_lost_map().spec().max_entries == 1);

        const int opens_before = hng_test_open_calls;
        REQUIRE(!loader->prepare());
        REQUIRE(hng_test_open_calls == opens_before);

        const int attaches_before = hng_test_attach_calls;
        REQUIRE(loader->attach());
        REQUIRE(loader->state() == hng::BpfProgramState::ATTACHED);
        REQUIRE(hng_test_attach_calls ==
                attaches_before + static_cast<int>(programs));
        REQUIRE(hng_test_live_links == static_cast<int>(programs));
        REQUIRE(loader->stats().attached_programs == programs);
        REQUIRE(!loader->attach());

        loader->detach();
        REQUIRE(loader->state() == hng::BpfProgramState::PREPARED);
        REQUIRE(hng_test_live_links == 0);
        REQUIRE(loader->stats().attached_programs == 0);
        loader->detach();
        REQUIRE(hng_test_live_links == 0);
    }
    REQUIRE(hng_test_live_skeletons == 0);
    REQUIRE(hng_test_live_links == 0);
    REQUIRE(!hng_test_bad_cleanup_order);
}

void verify_skips_missing_tracepoint()
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
        auto loader = hng::BpfLoaderFactory::create_syscall_probe(tracefs.root);
        REQUIRE(loader->prepare());
        const auto programs = static_cast<std::uint64_t>(sections.size());
        REQUIRE(loader->stats().skipped_probes == 1);
        REQUIRE(loader->stats().total_programs == programs);
        bpf_program* skipped = find_program(missing);
        REQUIRE(skipped != nullptr && !skipped->autoload);

        REQUIRE(loader->attach());
        REQUIRE(loader->stats().attached_programs == programs - 1);
        REQUIRE(hng_test_live_links == static_cast<int>(programs) - 1);
        REQUIRE(!skipped->attached);
        loader->detach();
        REQUIRE(hng_test_live_links == 0);
    }
    REQUIRE(hng_test_live_skeletons == 0);
    REQUIRE(!hng_test_bad_cleanup_order);
}

void verify_attach_failure_accounting()
{
    reset_stub();
    TempTracefs tracefs;
    REQUIRE(!tracefs.root.empty());
    add_syscall_programs(tracefs);
    const auto& sections = hng_test_program_sections(kSkeleton);
    REQUIRE(sections.size() > 1);

    {
        auto loader = hng::BpfLoaderFactory::create_syscall_probe(tracefs.root);
        REQUIRE(loader->prepare());
        const int programs               = static_cast<int>(sections.size());
        hng_test_attach_failure_sections = {sections[1]};
        REQUIRE(loader->attach());
        REQUIRE(loader->state() == hng::BpfProgramState::ATTACHED);
        REQUIRE(loader->stats().attach_failed == 1);
        REQUIRE(loader->stats().attached_programs ==
                static_cast<std::uint64_t>(programs - 1));
        REQUIRE(hng_test_live_links == programs - 1);
        loader->detach();
    }
    REQUIRE(hng_test_live_links == 0);

    {
        auto loader = hng::BpfLoaderFactory::create_syscall_probe(tracefs.root);
        REQUIRE(loader->prepare());
        const int programs      = static_cast<int>(sections.size());
        hng_test_attach_failure = true;
        REQUIRE(!loader->attach());
        REQUIRE(loader->state() == hng::BpfProgramState::PREPARED);
        REQUIRE(loader->stats().attach_failed ==
                static_cast<std::uint64_t>(programs));
        REQUIRE(loader->stats().attached_programs == 0);
        REQUIRE(hng_test_live_links == 0);

        hng_test_attach_failure = false;
        hng_test_attach_failure_sections.clear();
        REQUIRE(loader->attach());
        REQUIRE(loader->state() == hng::BpfProgramState::ATTACHED);
        REQUIRE(loader->stats().attach_failed ==
                static_cast<std::uint64_t>(programs));
        REQUIRE(hng_test_live_links == programs);
    }
    REQUIRE(hng_test_live_skeletons == 0);
    REQUIRE(hng_test_live_links == 0);
    REQUIRE(!hng_test_bad_cleanup_order);
}

void verify_map_validation_and_cleanup()
{
    reset_stub();
    TempTracefs tracefs;
    REQUIRE(!tracefs.root.empty());
    add_syscall_programs(tracefs);

    {
        auto loader = hng::BpfLoaderFactory::create_syscall_probe(tracefs.root);
        hng_test_load_failure = true;
        REQUIRE(!loader->prepare());
        REQUIRE(loader->state() == hng::BpfProgramState::UNPREPARED);
        REQUIRE(hng_test_live_skeletons == 0);
        hng_test_load_failure = false;
    }

    {
        hng_test_event_spec_override =
            hng_test_map_spec{BPF_MAP_TYPE_HASH, 4, 8, 1};
        auto loader = hng::BpfLoaderFactory::create_syscall_probe(tracefs.root);
        REQUIRE(!loader->prepare());
        REQUIRE(hng_test_live_skeletons == 0);
        hng_test_event_spec_override.reset();
    }

    {
        hng_test_reserve_spec_override =
            hng_test_map_spec{BPF_MAP_TYPE_PERCPU_ARRAY, 4, 8, 2};
        auto loader = hng::BpfLoaderFactory::create_syscall_probe(tracefs.root);
        REQUIRE(!loader->prepare());
        REQUIRE(hng_test_live_skeletons == 0);
        hng_test_reserve_spec_override.reset();
    }

    {
        hng_test_pending_spec_override =
            hng_test_map_spec{BPF_MAP_TYPE_PERCPU_ARRAY, 4, 4, 1};
        auto loader = hng::BpfLoaderFactory::create_syscall_probe(tracefs.root);
        REQUIRE(!loader->prepare());
        REQUIRE(hng_test_live_skeletons == 0);
        hng_test_pending_spec_override.reset();
    }

    {
        hng_test_filter_spec_override =
            hng_test_map_spec{BPF_MAP_TYPE_HASH, 8, 4, 65536};
        auto loader = hng::BpfLoaderFactory::create_syscall_probe(tracefs.root);
        REQUIRE(!loader->prepare());
        REQUIRE(hng_test_live_skeletons == 0);
        hng_test_filter_spec_override.reset();
    }

    {
        hng_test_event_fd_override = -EBADF;
        auto loader = hng::BpfLoaderFactory::create_syscall_probe(tracefs.root);
        REQUIRE(!loader->prepare());
        REQUIRE(hng_test_live_skeletons == 0);
        hng_test_event_fd_override.reset();
    }

    // 失败后允许重新 prepare；成功路径仍会完整构造并释放资源。
    {
        auto loader = hng::BpfLoaderFactory::create_syscall_probe(tracefs.root);
        hng_test_load_failure = true;
        REQUIRE(!loader->prepare());
        hng_test_load_failure = false;
        REQUIRE(loader->prepare());
        REQUIRE(loader->state() == hng::BpfProgramState::PREPARED);
    }
    REQUIRE(hng_test_live_skeletons == 0);
    REQUIRE(!hng_test_bad_cleanup_order);
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

int main()
{
    try {
        TempTracefs tracefs;
        REQUIRE(!tracefs.root.empty());
        add_syscall_programs(tracefs);
        verify_lifecycle(tracefs.root);
        verify_skips_missing_tracepoint();
        verify_attach_failure_accounting();
        verify_map_validation_and_cleanup();
        std::printf("PASS: bpf loader, %d checks (skeleton mocks)\n", checks);
        return 0;
    }
    catch (const std::exception& error) {
        std::fprintf(stderr, "FAIL: %s\n", error.what());
        return 1;
    }
}
