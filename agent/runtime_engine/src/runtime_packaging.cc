/**
 * @file runtime_packaging.cc
 * @brief 语义事件 → RuntimeEvent 的组装 实现
 * @author red-shinku
 * @date 2026.10.10
 */

#include "agent/runtime_engine/src/runtime_packaging.hpp"

#include <type_traits>
#include <utility>
#include <variant>

namespace {

/// @brief 语义载荷 variant，备选顺序即 syscall_event_type 的 1..8
using SemanticPayload = std::decay_t<decltype(hng::syscall_semantic_data::data)>;

static_assert(std::is_same_v<std::variant_alternative_t<0, SemanticPayload>,
                             hng::process_semantic_data>,
              "variant #1 must be process (PROCESS_EVENT = 1)");
static_assert(std::is_same_v<std::variant_alternative_t<1, SemanticPayload>,
                             hng::exec_semantic_data>,
              "variant #2 must be exec (EXEC_EVENT = 2)");
static_assert(std::is_same_v<std::variant_alternative_t<2, SemanticPayload>,
                             hng::credential_semantic_data>,
              "variant #3 must be credential (CREDENTIAL_EVENT = 3)");
static_assert(std::is_same_v<std::variant_alternative_t<3, SemanticPayload>,
                             hng::namespace_semantic_data>,
              "variant #4 must be namespace (NAMESPACE_EVENT = 4)");
static_assert(std::is_same_v<std::variant_alternative_t<4, SemanticPayload>,
                             hng::file_syscall_semantic_data>,
              "variant #5 must be file (FILE_EVENT = 5)");
static_assert(std::is_same_v<std::variant_alternative_t<5, SemanticPayload>,
                             hng::memory_semantic_data>,
              "variant #6 must be memory (MEMORY_EVENT = 6)");
static_assert(std::is_same_v<std::variant_alternative_t<6, SemanticPayload>,
                             hng::network_syscall_semantic_data>,
              "variant #7 must be network (NETWORK_EVENT = 7)");
static_assert(std::is_same_v<std::variant_alternative_t<7, SemanticPayload>,
                             hng::kernel_semantic_data>,
              "variant #8 must be kernel (KERNEL_EVENT = 8)");

}  // namespace

hng::RuntimeEvent RuntimePackaging::pack(hng::syscall_semantic_data src,
                                         uint32_t roleID,
                                         hng::role_label_t roleLabel,
                                         uint32_t contextID, std::string exe)
{
    hng::RuntimeEvent event{};
    event.runtimeInfo.process =
        hng::Process{src.head.pid, src.head.pid_start_time};
    event.runtimeInfo.parent =
        hng::Process{src.head.ppid, src.head.ppid_start_time};
    event.runtimeInfo.roleID    = roleID;
    event.runtimeInfo.roleLabel = std::move(roleLabel);
    event.runtimeInfo.contextID = contextID;
    event.runtimeInfo.etype     = hng::EventType::SYSCALL_EVENT;
    event.runtimeInfo.exe       = std::move(exe);

    static_assert(
        std::variant_size_v<std::decay_t<decltype(src.data)>> == 8,
        "The payload quantity of syscall semantic events must correspond to "
        "1..8 of enum syscall_event_type");
    // 载荷 variant 的备选顺序与 syscall_event_type 的 1..8 一一对应；
    // subtype 由内核事件头给出，不在此处由变体下标推导。
    event.runtimeInfo.subtype = src.head.subtype;
    event.data                = std::move(src);
    return event;
}
