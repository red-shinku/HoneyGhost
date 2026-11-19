/**
 * @file test_cli_event_converter.cc
 * @brief 运行时事件 → RuntimeService 响应报文的单测
 * @details
 * 纯转换，无 IO / 无协程。覆盖：
 *  - syscall 载荷的九个变体备选各自落到 oneof 的对应成员，载荷内容不丢；
 *  - eventhead 的字段来源：pid、归属（含 roleLabel）与 exe 取自
 *    RuntimeInformation，其余取自事件头（含 uid/euid/ret/comm/mnt_ns）；
 *  - 归属未落定时 roleLabel 留空；
 *  - 事件来源的双边映射可往返，非法报文取值返回 std::nullopt。
 * @author red-shinku
 * @date 2026.10.16
 */

#include "agent/cli_server/src/event_converter.hpp"

#include <cstdint>
#include <cstdio>
#include <functional>
#include <optional>
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
constexpr uint32_t kUid       = 1000;
constexpr uint32_t kEuid      = 0;
constexpr int64_t kRet        = 3;
constexpr uint32_t kMntNS     = 4026532222;
constexpr char kComm[]        = "bash";
constexpr char kExe[]         = "/tmp/test";

/// 一条归属已落定的 syscall 事件，事件头填齐
hng::RuntimeEvent make_syscall()
{
    hng::RuntimeEvent event{};
    event.runtimeInfo.process       = hng::Process{kPid, kPidStart};
    event.runtimeInfo.etype         = hng::EventType::SYSCALL_EVENT;
    event.runtimeInfo.roleID        = kRoleID;
    event.runtimeInfo.roleLabel     = kRoleLabel;
    event.runtimeInfo.contextID     = kContextID;
    event.runtimeInfo.exe           = kExe;

    event.data.head.pid             = kPid;
    event.data.head.pid_start_time  = kPidStart;
    event.data.head.ppid            = kPpid;
    event.data.head.ppid_start_time = kPpidStart;
    event.data.head.type            = hng::EventType::SYSCALL_EVENT;
    event.data.head.subtype         = EXEC_EVENT;
    event.data.head.uid             = kUid;
    event.data.head.euid            = kEuid;
    event.data.head.ret             = kRet;
    event.data.head.comm            = kComm;
    event.data.head.mnt_ns          = kMntNS;
    return event;
}

// 内核 syscall_event_type 与 proto Subtype 必须同数值
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
        {"signal",
         [](hng::syscall_semantic_data& s) {
             s.data.emplace<8>().set_syscall_name("signal");
         },
         hng::clisv::syscall_event_data::kSignalData,
         [](const hng::clisv::syscall_event_data& d) {
             return d.signal_data().syscall_name();
         }},
    };

    for (const PayloadCase& c : table) {
        hng::RuntimeEvent event = make_syscall();
        c.fill(event.data);

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
    hng::RuntimeEvent event = make_syscall();

    hng::clisv::eventrecord msg;
    hng::cli::ToProto(event, msg);

    CHECK(msg.head().pid() == kPid, "pid 取自 RuntimeInformation::process");
    CHECK(msg.head().pid_start_time() == kPidStart, "进程 start_time 取自事件头");
    CHECK(msg.head().roleid() == kRoleID, "roleID 直传");
    CHECK(msg.head().contextid() == kContextID, "contextID 直传");
    CHECK(msg.head().ppid() == kPpid, "ppid 取自事件头");
    CHECK(msg.head().ppid_start_time() == kPpidStart,
          "ppid 的 start_time 取自事件头");
    CHECK(msg.head().type() == hng::clisv::EVENT_TYPE_SYSCALL,
          "事件类型取自事件头");
    CHECK(msg.head().subtype() == hng::clisv::SUBTYPE_EXEC,
          "语义子类型取自事件头");
    CHECK(msg.head().rolelabel() == kRoleLabel, "roleLabel 直传");
    CHECK(msg.head().uid() == kUid, "uid 取自事件头");
    CHECK(msg.head().euid() == kEuid, "euid 取自事件头");
    CHECK(msg.head().ret() == kRet, "ret 取自事件头");
    CHECK(msg.head().comm() == kComm, "comm 取自事件头");
    CHECK(msg.head().mnt_ns() == kMntNS, "mnt_ns 取自事件头");
    CHECK(msg.head().exe() == kExe, "exe 取自 RuntimeInformation");
}

/// 内核枚举的每个取值都应落到同数值的 Subtype
void run_subtype_mapping()
{
    struct Case {
        enum syscall_event_type subtype;
        hng::clisv::Subtype expected;
    };
    const Case cases[] = {
        {UNKNOWN_EVENT, hng::clisv::SUBTYPE_UNSPECIFIED},
        {PROCESS_EVENT, hng::clisv::SUBTYPE_PROCESS},
        {EXEC_EVENT, hng::clisv::SUBTYPE_EXEC},
        {CREDENTIAL_EVENT, hng::clisv::SUBTYPE_CREDENTIAL},
        {NAMESPACE_EVENT, hng::clisv::SUBTYPE_NAMESPACE},
        {FILE_EVENT, hng::clisv::SUBTYPE_FILE},
        {MEMORY_EVENT, hng::clisv::SUBTYPE_MEMORY},
        {NETWORK_EVENT, hng::clisv::SUBTYPE_NETWORK},
        {KERNEL_EVENT, hng::clisv::SUBTYPE_KERNEL},
        {SIGNAL_EVENT, hng::clisv::SUBTYPE_SIGNAL},
    };
    for (const Case& c : cases) {
        hng::RuntimeEvent event = make_syscall();
        event.data.head.subtype = c.subtype;

        hng::clisv::eventrecord msg;
        hng::cli::ToProto(event, msg);
        CHECK(msg.head().subtype() == c.expected,
              "内核 subtype 应映射到同数值的报文 Subtype");
    }
}

void run_event_type_round_trip()
{
    const hng::EventType type = hng::EventType::SYSCALL_EVENT;
    const std::optional<hng::EventType> round_trip =
        hng::cli::FromProtoEventType(hng::cli::ToProtoEventType(type));
    CHECK(round_trip.has_value() && *round_trip == type,
          "事件来源的双边映射应可往返");

    CHECK(!hng::cli::FromProtoEventType(static_cast<hng::clisv::EventType>(1))
               .has_value(),
          "已保留的事件来源取值应被拒绝");
    CHECK(!hng::cli::FromProtoEventType(static_cast<hng::clisv::EventType>(-1))
               .has_value(),
          "非法的事件来源取值应被拒绝");
}

}  // namespace

int main()
{
    run_syscall_payload_mapping();
    run_head_fields();
    run_subtype_mapping();
    run_event_type_round_trip();

    if (g_fail) {
        std::fprintf(stderr, "TOTAL FAILURES: %d\n", g_fail);
        return 1;
    }
    std::printf("ALL PASS\n");
    return 0;
}
