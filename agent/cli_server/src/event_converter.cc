/**
 * @file event_converter.cc
 * @brief event_converter.hpp 的实现
 * @author red-shinku
 * @date 2026.10.16
 */

#include "agent/cli_server/src/event_converter.hpp"

#include <utility>
#include <variant>

#include "agent/event_data/include/file_event.hpp"
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
    }
}

}  // namespace

hng::clisv::EventType ToProtoEventType(hng::EventType etype)
{
    switch (etype) {
        case hng::EventType::SYSCALL_EVENT:
            return hng::clisv::EVENT_TYPE_SYSCALL;
        case hng::EventType::FILE_EVENT:
            return hng::clisv::EVENT_TYPE_FILE;
        case hng::EventType::NETWORK_EVENT:
            return hng::clisv::EVENT_TYPE_NETWORK;
        case hng::EventType::IPC_EVENT:
            return hng::clisv::EVENT_TYPE_IPC;
    }
    return hng::clisv::EVENT_TYPE_SYSCALL;
}

hng::EventType FromProtoEventType(hng::clisv::EventType etype)
{
    switch (etype) {
        case hng::clisv::EVENT_TYPE_SYSCALL:
            return hng::EventType::SYSCALL_EVENT;
        case hng::clisv::EVENT_TYPE_FILE:
            return hng::EventType::FILE_EVENT;
        case hng::clisv::EVENT_TYPE_NETWORK:
            return hng::EventType::NETWORK_EVENT;
        case hng::clisv::EVENT_TYPE_IPC:
            return hng::EventType::IPC_EVENT;
        // proto 为把枚举定宽到 int 而生成的两个哨兵成员，不能省，否则 switch 不全
        case hng::clisv::EventType_INT_MIN_SENTINEL_DO_NOT_USE_:
        case hng::clisv::EventType_INT_MAX_SENTINEL_DO_NOT_USE_:
            break;
    }
    return hng::EventType::SYSCALL_EVENT;
}

void ToProto(hng::RuntimeEvent& event, hng::clisv::eventrecord& out)
{
    const hng::RuntimeInformation& info = event.runtimeInfo;

    hng::clisv::eventhead* head         = out.mutable_head();
    head->set_rolelabel(info.roleLabel);
    head->set_roleid(info.roleID);
    head->set_contextid(info.contextID);
    head->set_pid(info.process.pid);

    if (hng::syscall_semantic_data* syscall =
            std::get_if<hng::syscall_semantic_data>(&event.data)) {
        head->set_pid_start_time(syscall->head.pid_start_time);
        head->set_ppid(syscall->head.ppid);
        head->set_ppid_start_time(syscall->head.ppid_start_time);
        head->set_type(ToProtoEventType(syscall->head.type));
        MoveSyscallPayload(*syscall, *out.mutable_syscall_ev());
        return;
    }

    hng::file_semantic_data& file = std::get<hng::file_semantic_data>(event.data);
    head->set_pid_start_time(file.head.pid_start_time);
    head->set_ppid(file.head.ppid);
    head->set_ppid_start_time(file.head.ppid_start_time);
    head->set_type(ToProtoEventType(file.head.type));
    out.set_allocated_file_ev(new hng::file_event_data(std::move(file.data)));
}

}  // namespace hng::cli
