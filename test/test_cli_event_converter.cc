/**
 * @file test_cli_event_converter.cc
 * @brief 运行时事件 → RuntimeService 响应报文的单测
 * @details
 * 纯转换，无 IO / 无协程。覆盖：
 *  - syscall 载荷的八个变体备选各自落到 oneof 的对应成员，载荷内容不丢；
 *  - 文件事件落到 file_ev；
 *  - eventhead 的字段来源：pid 与归属（含 roleLabel）取自 RuntimeInformation，
 *    其余取自事件头；
 *  - 归属未落定时 roleLabel 留空；
 *  - 事件类型的双边映射可往返。
 * @author red-shinku
 * @date 2026.10.16
 */

#include "agent/cli_server/src/event_converter.hpp"

#include <cstdint>
#include <cstdio>
#include <functional>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace {

int g_fail = 0;

#define CHECK(cond, msg)                                                         \
    do {                                                                         \
        if (!(cond)) {                                                           \
            ++g_fail;                                                            \
            std::fprintf(stderr, "[FAIL] %s:%d  %s\n", __FILE__, __LINE__, msg); \
        }                                                                        \
    } while (0)

constexpr uint32_t kPid       = 1234;
constexpr uint64_t kPidStart  = 111;
constexpr uint32_t kPpid      = 42;
constexpr uint64_t kPpidStart = 84;
constexpr uint32_t kRoleID    = 7;
constexpr uint32_t kContextID = 9;
constexpr char kRoleLabel[]   = "nginx:1.25";

/// 一条归属已落定的 syscall 事件，事件头填齐
hng::RuntimeEvent make_syscall(hng::EventType type)
{
    hng::RuntimeEvent event{};
    event.runtimeInfo.process   = hng::Process{kPid, kPidStart};
    event.runtimeInfo.etype     = type;
    event.runtimeInfo.roleID    = kRoleID;
    event.runtimeInfo.roleLabel = kRoleLabel;
    event.runtimeInfo.contextID = kContextID;
    event.data.emplace<hng::syscall_semantic_data>();

    hng::syscall_semantic_data& syscall =
        std::get<hng::syscall_semantic_data>(event.data);
    syscall.head.pid             = kPid;
    syscall.head.pid_start_time  = kPidStart;
    syscall.head.ppid            = kPpid;
    syscall.head.ppid_start_time = kPpidStart;
    syscall.head.type            = type;
    return event;
}

using SDataCase = hng::clisv::syscall_event_data::SDataCase;

/// 一个变体备选：怎么填、应落到 oneof 的哪个成员、怎么读回它的 syscall_name
struct PayloadCase {
    const char* name;
    std::function<void(hng::syscall_semantic_data&)> fill;
    SDataCase expected;
    std::function<std::string(const hng::clisv::syscall_event_data&)> read_name;
};

void run_syscall_payload_mapping()
{
    // 变体的备选顺序与 oneof 成员的定义顺序一一对应
    const std::vector<PayloadCase> table{
        {"process",
         [](hng::syscall_semantic_data& s) {
             s.data.emplace<0>().set_syscall_name("process");
         },
         hng::clisv::syscall_event_data::kProcessData,
         [](const hng::clisv::syscall_event_data& d) {
             return d.process_data().syscall_name();
         }},
        {"exec",
         [](hng::syscall_semantic_data& s) {
             s.data.emplace<1>().set_syscall_name("exec");
         },
         hng::clisv::syscall_event_data::kExecData,
         [](const hng::clisv::syscall_event_data& d) {
             return d.exec_data().syscall_name();
         }},
        {"credential",
         [](hng::syscall_semantic_data& s) {
             s.data.emplace<2>().set_syscall_name("credential");
         },
         hng::clisv::syscall_event_data::kCredentialData,
         [](const hng::clisv::syscall_event_data& d) {
             return d.credential_data().syscall_name();
         }},
        {"namespace",
         [](hng::syscall_semantic_data& s) {
             s.data.emplace<3>().set_syscall_name("namespace");
         },
         hng::clisv::syscall_event_data::kNamespaceData,
         [](const hng::clisv::syscall_event_data& d) {
             return d.namespace_data().syscall_name();
         }},
        {"file_syscall",
         [](hng::syscall_semantic_data& s) {
             s.data.emplace<4>().set_syscall_name("file_syscall");
         },
         hng::clisv::syscall_event_data::kFileData,
         [](const hng::clisv::syscall_event_data& d) {
             return d.file_data().syscall_name();
         }},
        {"memory",
         [](hng::syscall_semantic_data& s) {
             s.data.emplace<5>().set_syscall_name("memory");
         },
         hng::clisv::syscall_event_data::kMemoryData,
         [](const hng::clisv::syscall_event_data& d) {
             return d.memory_data().syscall_name();
         }},
        {"network",
         [](hng::syscall_semantic_data& s) {
             s.data.emplace<6>().set_syscall_name("network");
         },
         hng::clisv::syscall_event_data::kNetData,
         [](const hng::clisv::syscall_event_data& d) {
             return d.net_data().syscall_name();
         }},
        {"kernel",
         [](hng::syscall_semantic_data& s) {
             s.data.emplace<7>().set_syscall_name("kernel");
         },
         hng::clisv::syscall_event_data::kKernelData,
         [](const hng::clisv::syscall_event_data& d) {
             return d.kernel_data().syscall_name();
         }},
    };

    for (const PayloadCase& c : table) {
        hng::RuntimeEvent event = make_syscall(hng::EventType::SYSCALL_EVENT);
        c.fill(std::get<hng::syscall_semantic_data>(event.data));

        hng::clisv::eventrecord msg;
        hng::cli::ToProto(event, msg);

        CHECK(msg.event_case() == hng::clisv::eventrecord::kSyscallEv,
              "系统调用事件应走 syscall_ev");
        CHECK(msg.syscall_ev().s_data_case() == c.expected,
              "变体备选应落到对应的 oneof 成员");
        CHECK(c.read_name(msg.syscall_ev()) == c.name, "载荷字段不应丢");
    }
}

void run_head_fields()
{
    hng::RuntimeEvent event = make_syscall(hng::EventType::FILE_EVENT);

    hng::clisv::eventrecord msg;
    hng::cli::ToProto(event, msg);

    CHECK(msg.head().pid() == kPid, "pid 取自 RuntimeInformation::process");
    CHECK(msg.head().pid_start_time() == kPidStart, "进程 start_time 取自事件头");
    CHECK(msg.head().roleid() == kRoleID, "roleID 直传");
    CHECK(msg.head().contextid() == kContextID, "contextID 直传");
    CHECK(msg.head().ppid() == kPpid, "ppid 取自事件头");
    CHECK(msg.head().ppid_start_time() == kPpidStart,
          "ppid 的 start_time 取自事件头");
    CHECK(msg.head().type() == hng::clisv::EVENT_TYPE_FILE, "事件类型取自事件头");
    CHECK(msg.head().rolelabel() == kRoleLabel, "roleLabel 直传");
}

void run_file_event()
{
    hng::RuntimeEvent event{};
    event.runtimeInfo.process   = hng::Process{kPid, kPidStart};
    event.runtimeInfo.etype     = hng::EventType::FILE_EVENT;
    event.runtimeInfo.roleID    = 0;
    event.runtimeInfo.contextID = 0;
    event.data.emplace<hng::file_semantic_data>();

    hng::file_semantic_data& file = std::get<hng::file_semantic_data>(event.data);
    file.head.pid                 = kPid;
    file.head.pid_start_time      = kPidStart;
    file.head.ppid                = kPpid;
    file.head.ppid_start_time     = kPpidStart;
    file.head.type                = hng::EventType::FILE_EVENT;
    file.data.set_semantic_filename("/tmp/a");
    file.data.set_comm("cat");

    hng::clisv::eventrecord msg;
    hng::cli::ToProto(event, msg);

    CHECK(msg.event_case() == hng::clisv::eventrecord::kFileEv,
          "文件事件应走 file_ev");
    CHECK(msg.file_ev().semantic_filename() == "/tmp/a", "文件载荷应被搬进报文");
    CHECK(msg.file_ev().comm() == "cat", "文件载荷字段不应丢");
    CHECK(msg.head().type() == hng::clisv::EVENT_TYPE_FILE, "事件类型随之");
    CHECK(msg.head().roleid() == 0, "未落定的归属传 0");
    CHECK(msg.head().rolelabel().empty(), "未落定的归属不带标签");
}

void run_event_type_round_trip()
{
    const hng::EventType all[] = {
        hng::EventType::SYSCALL_EVENT, hng::EventType::FILE_EVENT,
        hng::EventType::NETWORK_EVENT, hng::EventType::IPC_EVENT};
    for (const hng::EventType type : all) {
        CHECK(hng::cli::FromProtoEventType(hng::cli::ToProtoEventType(type)) ==
                  type,
              "事件类型的双边映射应可往返");
    }
}

}  // namespace

int main()
{
    run_syscall_payload_mapping();
    run_head_fields();
    run_file_event();
    run_event_type_round_trip();

    if (g_fail) {
        std::fprintf(stderr, "TOTAL FAILURES: %d\n", g_fail);
        return 1;
    }
    std::printf("ALL PASS\n");
    return 0;
}
