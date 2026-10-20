/** @file @brief 公共头可在没有生成骨架与 libbpf 的环境中独立编译。 */
#include "agent/collector/include/collector.hpp"

#ifdef HNG_TEST_COLLECTOR_SKELETON_STUB_HPP_
#error "collector.hpp must not include generated skeletons"
#endif

#include <type_traits>
#include <utility>

static_assert(!std::is_copy_constructible_v<FileEventCollector>);
static_assert(!std::is_copy_assignable_v<FileEventCollector>);
static_assert(!std::is_move_constructible_v<FileEventCollector>);
static_assert(!std::is_move_assignable_v<FileEventCollector>);
static_assert(!std::is_copy_constructible_v<SyscallEventCollector>);
static_assert(!std::is_copy_assignable_v<SyscallEventCollector>);
static_assert(!std::is_move_constructible_v<SyscallEventCollector>);
static_assert(!std::is_move_assignable_v<SyscallEventCollector>);
static_assert(!std::is_copy_constructible_v<NetworkEventCollector>);
static_assert(!std::is_copy_assignable_v<NetworkEventCollector>);
static_assert(!std::is_move_constructible_v<NetworkEventCollector>);
static_assert(!std::is_move_assignable_v<NetworkEventCollector>);
static_assert(std::has_virtual_destructor_v<CollectorType>);
static_assert(noexcept(std::declval<const FileEventCollector&>().role_filter_map_fd()));
static_assert(noexcept(std::declval<const SyscallEventCollector&>().role_filter_map_fd()));
static_assert(noexcept(std::declval<const NetworkEventCollector&>().role_filter_map_fd()));
static_assert(!std::is_convertible_v<hng::SPSC_Queue<file_access_data>&,
                                     FileEventCollector>);

// 仅编译不链接；检查构造与析构不要求消费者看到私有状态的定义。
void verify_collector_public_header()
{
    hng::SPSC_Queue<file_access_data> files(1);
    hng::SPSC_Queue<syscall_event> syscalls(1);
    hng::SPSC_Queue<network_data> networks(1);
    FileEventCollector file_collector(files);
    SyscallEventCollector syscall_collector(syscalls);
    NetworkEventCollector network_collector(networks);
}
