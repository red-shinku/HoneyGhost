/**
 * @file syscall_probe_maps.hpp
 * @brief syscalls 骨架 map schema 的借用视图集合。
 * @details 视图不拥有 fd，只在 loader 存活期间有效。
 */

#ifndef HNG_BPF_LOADER_INCLUDE_SYSCALL_PROBE_MAPS_HPP_
#define HNG_BPF_LOADER_INCLUDE_SYSCALL_PROBE_MAPS_HPP_

#include "agent/bpf_loader/include/bpf_map.hpp"

#include <utility>

namespace hng {

class SyscallProbeLoader;

/**
 * @brief syscalls 骨架中采集所需 map 的借用视图集合。
 * @details 由 SyscallProbeLoader::maps() 返回；视图只在 loader 存活期间
 *          有效，使用方须自行复制 fd 或在其生命周期内读取。
 */
class SyscallProbeMaps {
   public:
    /// @brief 系统调用事件 ringbuf map
    BpfMapView events_ringbuf() const noexcept { return events_; }

    /// @brief ringbuf 预留失败计数 map
    BpfMapView reserve_failures_map() const noexcept { return reserve_; }

    /// @brief enter 暂存条目丢失计数 map
    BpfMapView pending_lost_map() const noexcept { return pending_; }

    /// @brief 角色过滤 HASH map
    BpfMapView role_filter_map() const noexcept { return role_filter_; }

   private:
    friend class SyscallProbeLoader;

    SyscallProbeMaps(BpfMapView events, BpfMapView reserve, BpfMapView pending,
                     BpfMapView role_filter) noexcept
        : events_(std::move(events)),
          reserve_(std::move(reserve)),
          pending_(std::move(pending)),
          role_filter_(std::move(role_filter))
    {
    }

    BpfMapView events_;
    BpfMapView reserve_;
    BpfMapView pending_;
    BpfMapView role_filter_;
};

}  // namespace hng

#endif  // HNG_BPF_LOADER_INCLUDE_SYSCALL_PROBE_MAPS_HPP_
