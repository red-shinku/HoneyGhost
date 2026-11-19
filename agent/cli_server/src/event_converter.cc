/**
 * @file event_converter.cc
 * @brief event_converter.hpp 的实现
 * @author red-shinku
 * @date 2026.10.16
 */

#include "agent/cli_server/src/event_converter.hpp"

#include <optional>
#include <utility>
#include <variant>

#include "agent/event_data/include/syscall_event.hpp"

namespace hng::cli {
namespace {

/// @brief 把 syscall 载荷的 variant 挪进报文的 oneof
/// @note 变体索引与 oneof 成员按各自的定义顺序一一对应；本函数依赖该对应，
///       任一侧增删成员都会在此处暴露（switch 覆盖不全时告警）
void MoveSyscallPayload(hng::syscall_semantic_data& src,
                        hng::clisv::syscall_event_data& out)
{
    switch (src.data.index()) {
        case 0:
            out.set_allocated_process_data(
                new hng::process_semantic_data(std::move(std::get<0>(src.data))));
            break;
        case 1:
            out.set_allocated_exec_data(
                new hng::exec_semantic_data(std::move(std::get<1>(src.data))));
            break;
        case 2:
            out.set_allocated_credential_data(new hng::credential_semantic_data(
                std::move(std::get<2>(src.data))));
            break;
        case 3:
            out.set_allocated_namespace_data(new hng::namespace_semantic_data(
                std::move(std::get<3>(src.data))));
            break;
        case 4:
            out.set_allocated_file_data(new hng::file_syscall_semantic_data(
                std::move(std::get<4>(src.data))));
            break;
        case 5:
            out.set_allocated_memory_data(
                new hng::memory_semantic_data(std::move(std::get<5>(src.data))));
            break;
        case 6:
            out.set_allocated_net_data(new hng::network_syscall_semantic_data(
                std::move(std::get<6>(src.data))));
            break;
        case 7:
            out.set_allocated_kernel_data(
                new hng::kernel_semantic_data(std::move(std::get<7>(src.data))));
            break;
        case 8:
            out.set_allocated_signal_data(
                new hng::signal_semantic_data(std::move(std::get<8>(src.data))));
            break;
    }
}

/// @brief 语义子类型：内核枚举 → 报文
/// @note 两侧数值一致，由下方 static_assert 在编译期锁定
hng::clisv::Subtype ToProtoSubtype(enum syscall_event_type subtype)
{
    switch (subtype) {
        case UNKNOWN_EVENT:
            return hng::clisv::SUBTYPE_UNSPECIFIED;
        case PROCESS_EVENT:
            return hng::clisv::SUBTYPE_PROCESS;
        case EXEC_EVENT:
            return hng::clisv::SUBTYPE_EXEC;
        case CREDENTIAL_EVENT:
            return hng::clisv::SUBTYPE_CREDENTIAL;
        case NAMESPACE_EVENT:
            return hng::clisv::SUBTYPE_NAMESPACE;
        case FILE_EVENT:
            return hng::clisv::SUBTYPE_FILE;
        case MEMORY_EVENT:
            return hng::clisv::SUBTYPE_MEMORY;
        case NETWORK_EVENT:
            return hng::clisv::SUBTYPE_NETWORK;
        case KERNEL_EVENT:
            return hng::clisv::SUBTYPE_KERNEL;
        case SIGNAL_EVENT:
            return hng::clisv::SUBTYPE_SIGNAL;
    }
    return hng::clisv::SUBTYPE_UNSPECIFIED;
}

// 内核 syscall_event_type 与 proto Subtype 同数值是词汇统一的前提
static_assert(static_cast<int>(UNKNOWN_EVENT) ==
                  static_cast<int>(hng::clisv::SUBTYPE_UNSPECIFIED),
              "UNKNOWN_EVENT must equal SUBTYPE_UNSPECIFIED");
static_assert(static_cast<int>(PROCESS_EVENT) ==
                  static_cast<int>(hng::clisv::SUBTYPE_PROCESS),
              "PROCESS_EVENT must equal SUBTYPE_PROCESS");
static_assert(static_cast<int>(EXEC_EVENT) ==
                  static_cast<int>(hng::clisv::SUBTYPE_EXEC),
              "EXEC_EVENT must equal SUBTYPE_EXEC");
static_assert(static_cast<int>(CREDENTIAL_EVENT) ==
                  static_cast<int>(hng::clisv::SUBTYPE_CREDENTIAL),
              "CREDENTIAL_EVENT must equal SUBTYPE_CREDENTIAL");
static_assert(static_cast<int>(NAMESPACE_EVENT) ==
                  static_cast<int>(hng::clisv::SUBTYPE_NAMESPACE),
              "NAMESPACE_EVENT must equal SUBTYPE_NAMESPACE");
static_assert(static_cast<int>(FILE_EVENT) ==
                  static_cast<int>(hng::clisv::SUBTYPE_FILE),
              "FILE_EVENT must equal SUBTYPE_FILE");
static_assert(static_cast<int>(MEMORY_EVENT) ==
                  static_cast<int>(hng::clisv::SUBTYPE_MEMORY),
              "MEMORY_EVENT must equal SUBTYPE_MEMORY");
static_assert(static_cast<int>(NETWORK_EVENT) ==
                  static_cast<int>(hng::clisv::SUBTYPE_NETWORK),
              "NETWORK_EVENT must equal SUBTYPE_NETWORK");
static_assert(static_cast<int>(KERNEL_EVENT) ==
                  static_cast<int>(hng::clisv::SUBTYPE_KERNEL),
              "KERNEL_EVENT must equal SUBTYPE_KERNEL");
static_assert(static_cast<int>(SIGNAL_EVENT) ==
                  static_cast<int>(hng::clisv::SUBTYPE_SIGNAL),
              "SIGNAL_EVENT must equal SUBTYPE_SIGNAL");

}  // namespace

hng::clisv::EventType ToProtoEventType(hng::EventType etype)
{
    switch (etype) {
        case hng::EventType::SYSCALL_EVENT:
            return hng::clisv::EVENT_TYPE_SYSCALL;
    }
    return hng::clisv::EVENT_TYPE_SYSCALL;
}

std::optional<hng::EventType> FromProtoEventType(hng::clisv::EventType etype)
{
    switch (etype) {
        case hng::clisv::EVENT_TYPE_SYSCALL:
            return hng::EventType::SYSCALL_EVENT;
        // proto 为把枚举定宽到 int 而生成的两个哨兵成员，不能省，否则 switch 不全
        case hng::clisv::EventType_INT_MIN_SENTINEL_DO_NOT_USE_:
        case hng::clisv::EventType_INT_MAX_SENTINEL_DO_NOT_USE_:
            break;
    }
    return std::nullopt;
}

void ToProto(hng::RuntimeEvent& event, hng::clisv::eventrecord& out)
{
    const hng::RuntimeInformation& info = event.runtimeInfo;
    hng::syscall_semantic_data& syscall = event.data;

    hng::clisv::eventhead* head         = out.mutable_head();
    head->set_rolelabel(info.roleLabel);
    head->set_roleid(info.roleID);
    head->set_contextid(info.contextID);
    head->set_pid(info.process.pid);
    head->set_pid_start_time(syscall.head.pid_start_time);
    head->set_ppid(syscall.head.ppid);
    head->set_ppid_start_time(syscall.head.ppid_start_time);
    head->set_type(ToProtoEventType(syscall.head.type));
    head->set_subtype(ToProtoSubtype(syscall.head.subtype));
    head->set_uid(syscall.head.uid);
    head->set_euid(syscall.head.euid);
    head->set_ret(syscall.head.ret);
    head->set_comm(syscall.head.comm);
    head->set_mnt_ns(syscall.head.mnt_ns);
    head->set_exe(info.exe);
    MoveSyscallPayload(syscall, *out.mutable_syscall_ev());
}

}  // namespace hng::cli
