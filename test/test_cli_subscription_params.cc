/**
 * @file test_cli_subscription_params.cc
 * @brief 订阅参数 → RuntimeInfoFilter 的表驱动单测
 * @details
 * 纯值对象，无 IO / 无协程。覆盖：
 *  - 空请求为全选；
 *  - -t 单值与多值：维度之内取并集；
 *  - -i 的各维度：角色 / 上下文 / 进程同样是并集；
 *  - 角色维度含 roleID 与 roleLabel 两组，两组之间取并集；
 *  - 维度之间取交集；
 *  - roleID 的 0 只命中未落定的归属。
 * @author red-shinku
 * @date 2026.10.16
 */

#include "agent/cli_server/src/cli_runtime_service.hpp"

#include <cstdint>
#include <cstdio>
#include <functional>
#include <vector>

#include <proto/cli_service.pb.h>

#include "agent/event_data/include/runtime_event.hpp"

namespace {

int g_fail = 0;

#define CHECK(cond, msg)                                                         \
    do {                                                                         \
        if (!(cond)) {                                                           \
            ++g_fail;                                                            \
            std::fprintf(stderr, "[FAIL] %s:%d  %s\n", __FILE__, __LINE__, msg); \
        }                                                                        \
    } while (0)

using hng::clisv::ReceiveEventRequest;

hng::RuntimeInformation make_info(uint32_t pid, hng::EventType etype,
                                  uint32_t roleID, uint32_t contextID,
                                  hng::role_label_t roleLabel = {})
{
    return hng::RuntimeInformation{hng::Process{pid, pid * 10}, etype, roleID,
                                   roleLabel, contextID};
}

struct Case {
    const char* name;
    std::function<void(ReceiveEventRequest&)> build;
    hng::RuntimeInformation info;
    bool expect;
};

/// -t 的取值：类型集合原样落进过滤器
void add_types(ReceiveEventRequest& request,
               std::initializer_list<hng::clisv::EventType> types)
{
    for (const hng::clisv::EventType type : types) {
        request.add_etype(type);
    }
}

/// -i 的角色维度（按 roleID）
void add_roles(ReceiveEventRequest& request, std::initializer_list<uint32_t> ids)
{
    for (const uint32_t id : ids) {
        request.mutable_info()->add_roleid(id);
    }
}

/// -i 的角色维度（按标签）
void add_role_labels(ReceiveEventRequest& request,
                     std::initializer_list<const char*> labels)
{
    for (const char* label : labels) {
        request.mutable_info()->add_rolelabel(label);
    }
}

const std::vector<Case>& cases()
{
    static const std::vector<Case> table{
        {"空请求为全选", [](ReceiveEventRequest&) {},
         make_info(1, hng::EventType::IPC_EVENT, 9, 9), true},

        {"-t 单值命中该类型",
         [](ReceiveEventRequest& r) {
             add_types(r, {hng::clisv::EVENT_TYPE_FILE});
         },
         make_info(1, hng::EventType::FILE_EVENT, 0, 0), true},
        {"-t 单值不命中其他类型",
         [](ReceiveEventRequest& r) {
             add_types(r, {hng::clisv::EVENT_TYPE_FILE});
         },
         make_info(1, hng::EventType::SYSCALL_EVENT, 0, 0), false},
        {"-t 多值取并集（命中之一）",
         [](ReceiveEventRequest& r) {
             add_types(r, {hng::clisv::EVENT_TYPE_FILE,
                           hng::clisv::EVENT_TYPE_SYSCALL});
         },
         make_info(1, hng::EventType::SYSCALL_EVENT, 0, 0), true},
        {"-t 多值取并集（都不命中）",
         [](ReceiveEventRequest& r) {
             add_types(r, {hng::clisv::EVENT_TYPE_FILE,
                           hng::clisv::EVENT_TYPE_SYSCALL});
         },
         make_info(1, hng::EventType::IPC_EVENT, 0, 0), false},

        {"-i roleID 多值取并集（命中之一）",
         [](ReceiveEventRequest& r) { add_roles(r, {7, 8}); },
         make_info(1, hng::EventType::SYSCALL_EVENT, 8, 0), true},
        {"-i roleID 多值取并集（都不命中）",
         [](ReceiveEventRequest& r) { add_roles(r, {7, 8}); },
         make_info(1, hng::EventType::SYSCALL_EVENT, 9, 0), false},
        {"-i roleID=0 只命中未落定的归属",
         [](ReceiveEventRequest& r) { add_roles(r, {0}); },
         make_info(1, hng::EventType::SYSCALL_EVENT, 0, 0), true},
        {"-i roleID=0 不命中已落定的归属",
         [](ReceiveEventRequest& r) { add_roles(r, {0}); },
         make_info(1, hng::EventType::SYSCALL_EVENT, 3, 0), false},

        {"-i roleLabel 命中集合成员",
         [](ReceiveEventRequest& r) { add_role_labels(r, {"nginx:1.25"}); },
         make_info(1, hng::EventType::SYSCALL_EVENT, 9, 0, "nginx:1.25"), true},
        {"-i roleLabel 不命中集合之外",
         [](ReceiveEventRequest& r) { add_role_labels(r, {"nginx:1.25"}); },
         make_info(1, hng::EventType::SYSCALL_EVENT, 9, 0, "redis:7"), false},
        {"-i roleLabel 不命中未落定的归属",
         [](ReceiveEventRequest& r) { add_role_labels(r, {"nginx:1.25"}); },
         make_info(1, hng::EventType::SYSCALL_EVENT, 0, 0), false},
        {"-i roleID 与 roleLabel 取并集",
         [](ReceiveEventRequest& r) {
             add_roles(r, {7});
             add_role_labels(r, {"nginx:1.25"});
         },
         make_info(1, hng::EventType::SYSCALL_EVENT, 8, 0, "nginx:1.25"), true},

        {"-i contextID 命中集合成员",
         [](ReceiveEventRequest& r) { r.mutable_info()->add_contextid(3); },
         make_info(1, hng::EventType::SYSCALL_EVENT, 0, 3), true},
        {"-i contextID 不命中集合之外",
         [](ReceiveEventRequest& r) { r.mutable_info()->add_contextid(3); },
         make_info(1, hng::EventType::SYSCALL_EVENT, 0, 4), false},

        {"-i pid 命中集合成员",
         [](ReceiveEventRequest& r) {
             r.mutable_info()->add_pid(1001);
             r.mutable_info()->add_pid(2002);
         },
         make_info(2002, hng::EventType::SYSCALL_EVENT, 0, 0), true},
        {"-i pid 不命中集合之外",
         [](ReceiveEventRequest& r) {
             r.mutable_info()->add_pid(1001);
             r.mutable_info()->add_pid(2002);
         },
         make_info(3003, hng::EventType::SYSCALL_EVENT, 0, 0), false},

        {"维度之间取交集：两者全中",
         [](ReceiveEventRequest& r) {
             add_types(r, {hng::clisv::EVENT_TYPE_SYSCALL});
             add_roles(r, {7});
         },
         make_info(1, hng::EventType::SYSCALL_EVENT, 7, 0), true},
        {"维度之间取交集：仅事件类型不符",
         [](ReceiveEventRequest& r) {
             add_types(r, {hng::clisv::EVENT_TYPE_SYSCALL});
             add_roles(r, {7});
         },
         make_info(1, hng::EventType::FILE_EVENT, 7, 0), false},
        {"维度之间取交集：仅角色不符",
         [](ReceiveEventRequest& r) {
             add_types(r, {hng::clisv::EVENT_TYPE_SYSCALL});
             add_roles(r, {7});
         },
         make_info(1, hng::EventType::SYSCALL_EVENT, 8, 0), false},
    };
    return table;
}

}  // namespace

int main()
{
    for (const Case& c : cases()) {
        ReceiveEventRequest request;
        c.build(request);

        const RuntimeInfoFilter filter = hng::cli::ToRuntimeInfoFilter(request);
        CHECK(filter.should_take(c.info) == c.expect, c.name);
    }

    if (g_fail) {
        std::fprintf(stderr, "TOTAL FAILURES: %d\n", g_fail);
        return 1;
    }
    std::printf("ALL PASS\n");
    return 0;
}
