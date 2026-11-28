/**
 * @file syscall_probe_loader.cc
 * @brief 系统调用采集骨架加载器的实现。
 */

#include "agent/bpf_loader/include/syscall_probe_loader.hpp"

#include "agent/bpf_loader/include/bpf_loader_factory.hpp"
#include "agent/bpf_loader/src/probe_attach.hpp"
#include "agent/util/include/tracefs.hpp"
#include "kernel/include/role_filter_types.h"
#include "kernel/syscalls.skel.h"

#include <linux/bpf.h>

#include <atomic>
#include <cerrno>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace hng {

namespace {

BpfMapView map_view(bpf_map* map, const char* name)
{
    if (map == nullptr || ::bpf_map__fd(map) < 0) {
        throw std::system_error(EBADF, std::generic_category(),
                                std::string("missing BPF map: ") + name);
    }
    return BpfMapView::from_fd(::bpf_map__fd(map));
}

void require_spec(const BpfMapView& view, const BpfMapSpec& expected,
                  const char* name)
{
    if (view.spec() != expected) {
        throw std::system_error(EINVAL, std::generic_category(),
                                std::string("BPF map ABI mismatch: ") + name);
    }
}

std::uint64_t count_programs(bpf_object* object)
{
    std::uint64_t count  = 0;
    bpf_program* program = nullptr;
    bpf_object__for_each_program(program, object) { ++count; }
    return count;
}

}  // namespace

struct SyscallProbeLoader::Impl {
    explicit Impl(std::filesystem::path tracefs_root)
        : tracefs_root(std::move(tracefs_root))
    {
    }

    ~Impl()
    {
        for (bpf_link* link : links) {
            ::bpf_link__destroy(link);
        }
    }

    std::unique_ptr<::syscalls_collector,
                    decltype(&::syscalls_collector__destroy)>
        skeleton{nullptr, &::syscalls_collector__destroy};
    std::vector<::bpf_link*> links;
    std::optional<SyscallProbeMaps> maps;
    std::filesystem::path tracefs_root;
    std::atomic<BpfProgramState> state{BpfProgramState::UNPREPARED};
    std::atomic<std::uint64_t> total_programs{0};
    std::atomic<std::uint64_t> attached_programs{0};
    std::atomic<std::uint64_t> skipped_probes{0};
    std::atomic<std::uint64_t> attach_failed{0};
};

SyscallProbeLoader::SyscallProbeLoader(std::unique_ptr<Impl> impl)
    : impl_(std::move(impl))
{
}

SyscallProbeLoader::~SyscallProbeLoader() { detach(); }

bool SyscallProbeLoader::prepare()
{
    if (impl_ == nullptr || impl_->state.load(std::memory_order_acquire) !=
                                BpfProgramState::UNPREPARED) {
        return false;
    }

    try {
        std::unique_ptr<::syscalls_collector,
                        decltype(&::syscalls_collector__destroy)>
            skeleton(::syscalls_collector__open(),
                     &::syscalls_collector__destroy);
        if (skeleton == nullptr) {
            return false;
        }

        const std::filesystem::path tracefs_root =
            impl_->tracefs_root.empty() ? detail::find_tracefs_root()
                                        : impl_->tracefs_root;
        const int skipped =
            detail::skip_missing_tracepoints(skeleton->obj, tracefs_root);
        if (::syscalls_collector__load(skeleton.get()) != 0) {
            return false;
        }

        const BpfMapSpec counter_spec{BPF_MAP_TYPE_PERCPU_ARRAY,
                                      sizeof(std::uint32_t),
                                      sizeof(std::uint64_t), 1};
        const BpfMapSpec role_filter_spec{
            BPF_MAP_TYPE_HASH, sizeof(hng_role_filter_key), sizeof(std::uint32_t),
            HNG_ROLE_FILTER_MAX_ENTRIES};

        BpfMapView events =
            map_view(skeleton->maps.syscall_events, "syscall_events");
        if (events.spec().type != BPF_MAP_TYPE_RINGBUF) {
            throw std::system_error(EINVAL, std::generic_category(),
                                    "BPF map ABI mismatch: syscall_events");
        }
        BpfMapView reserve =
            map_view(skeleton->maps.reserve_failures, "reserve_failures");
        require_spec(reserve, counter_spec, "reserve_failures");
        BpfMapView pending =
            map_view(skeleton->maps.pending_lost, "pending_lost");
        require_spec(pending, counter_spec, "pending_lost");
        BpfMapView role_filter =
            map_view(skeleton->maps.hng_role_filter, "hng_role_filter");
        require_spec(role_filter, role_filter_spec, "hng_role_filter");

        impl_->links.clear();
        impl_->maps = SyscallProbeMaps(events, reserve, pending, role_filter);
        impl_->total_programs.store(count_programs(skeleton->obj),
                                    std::memory_order_relaxed);
        impl_->attached_programs.store(0, std::memory_order_relaxed);
        impl_->skipped_probes.store(static_cast<std::uint64_t>(skipped),
                                    std::memory_order_relaxed);
        impl_->skeleton = std::move(skeleton);
        impl_->state.store(BpfProgramState::PREPARED, std::memory_order_release);
        return true;
    }
    catch (...) {
        return false;
    }
}

bool SyscallProbeLoader::attach()
{
    if (impl_ == nullptr || impl_->state.load(std::memory_order_acquire) !=
                                BpfProgramState::PREPARED) {
        return false;
    }

    const int failures =
        detail::attach_programs(impl_->skeleton->obj, impl_->links);
    if (failures > 0) {
        impl_->attach_failed.fetch_add(static_cast<std::uint64_t>(failures),
                                       std::memory_order_relaxed);
    }
    if (failures > 0 && impl_->links.empty()) {
        return false;
    }

    impl_->attached_programs.store(impl_->links.size(),
                                   std::memory_order_relaxed);
    impl_->state.store(BpfProgramState::ATTACHED, std::memory_order_release);
    return true;
}

void SyscallProbeLoader::detach() noexcept
{
    if (impl_ == nullptr) {
        return;
    }
    for (::bpf_link* link : impl_->links) {
        ::bpf_link__destroy(link);
    }
    impl_->links.clear();
    impl_->attached_programs.store(0, std::memory_order_relaxed);
    if (impl_->state.load(std::memory_order_acquire) ==
        BpfProgramState::ATTACHED) {
        impl_->state.store(BpfProgramState::PREPARED, std::memory_order_release);
    }
}

BpfProgramState SyscallProbeLoader::state() const noexcept
{
    return impl_ == nullptr ? BpfProgramState::UNPREPARED
                            : impl_->state.load(std::memory_order_acquire);
}

BpfProgramStats SyscallProbeLoader::stats() const noexcept
{
    BpfProgramStats snapshot;
    if (impl_ == nullptr) {
        return snapshot;
    }
    snapshot.total_programs =
        impl_->total_programs.load(std::memory_order_relaxed);
    snapshot.attached_programs =
        impl_->attached_programs.load(std::memory_order_relaxed);
    snapshot.skipped_probes =
        impl_->skipped_probes.load(std::memory_order_relaxed);
    snapshot.attach_failed = impl_->attach_failed.load(std::memory_order_relaxed);
    return snapshot;
}

SyscallProbeMaps SyscallProbeLoader::maps() const
{
    if (impl_ == nullptr || !impl_->maps) {
        throw std::logic_error("syscall probe loader is not prepared");
    }
    return *impl_->maps;
}

std::unique_ptr<SyscallProbeLoader> BpfLoaderFactory::create_syscall_probe(
    std::filesystem::path tracefs_root)
{
    auto impl =
        std::make_unique<SyscallProbeLoader::Impl>(std::move(tracefs_root));
    return std::unique_ptr<SyscallProbeLoader>(
        new SyscallProbeLoader(std::move(impl)));
}

}  // namespace hng
