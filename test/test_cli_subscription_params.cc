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
 *  - roleID 的 0 只命中未落定的归属；
 *  - 布尔表达式：各字段的 atom、NE、role 标签的 PREFIX、and/or/not 与嵌套；
 *  - 表达式与 -i / -t 取交；
 *  - 表达式的非法节点、非法取值与节点 / 深度 / 取值数上限被拒绝。
 * @author red-shinku
 * @date 2026.10.16
 */

#include "agent/cli_server/src/cli_runtime_service.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <optional>
#include <string>
#include <utility>
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

using hng::clisv::filter_atom;
using hng::clisv::filter_expr;
using hng::clisv::ReceiveEventRequest;

hng::RuntimeInformation make_info(
    uint32_t pid, hng::EventType etype, uint32_t roleID, uint32_t contextID,
    hng::role_label_t roleLabel = {}, uint32_t ppid = 0,
    hng::EventKind kind = hng::EventKind::UNSPECIFIED)
{
    hng::RuntimeInformation info;
    info.process   = hng::Process{pid, pid * 10};
    info.parent    = hng::Process{ppid, ppid * 10};
    info.etype     = etype;
    info.kind      = kind;
    info.roleID    = roleID;
    info.roleLabel = roleLabel;
    info.contextID = contextID;
    return info;
}

struct Case {
    const char* name;
    std::function<void(ReceiveEventRequest&)> build;
    hng::RuntimeInformation info;
    bool expect;
};

/// 转换失败即视为非法，不需要期望信息
struct InvalidCase {
    const char* name;
    std::function<void(ReceiveEventRequest&)> build;
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

/// 构造数值字段的 atom
filter_atom number_atom(hng::clisv::FilterField field,
                        hng::clisv::FilterCompare compare,
                        std::initializer_list<uint32_t> values)
{
    filter_atom atom;
    atom.set_field(field);
    atom.set_compare(compare);
    for (const uint32_t value : values) {
        atom.add_numbers(value);
    }
    return atom;
}

/// 构造 role 标签的 atom
filter_atom label_atom(hng::clisv::FilterCompare compare,
                       std::initializer_list<const char*> values)
{
    filter_atom atom;
    atom.set_field(hng::clisv::FILTER_FIELD_ROLE_LABEL);
    atom.set_compare(compare);
    for (const char* value : values) {
        atom.add_strings(value);
    }
    return atom;
}

/// 把 atom 包成表达式
filter_expr atom_expr(filter_atom atom)
{
    filter_expr expr;
    *expr.mutable_atom() = std::move(atom);
    return expr;
}

/// 数值字段的原子表达式
filter_expr numeric(hng::clisv::FilterField field,
                    hng::clisv::FilterCompare compare,
                    std::initializer_list<uint32_t> values)
{
    return atom_expr(number_atom(field, compare, values));
}

/// role 标签的原子表达式
filter_expr label(hng::clisv::FilterCompare compare,
                  std::initializer_list<const char*> values)
{
    return atom_expr(label_atom(compare, values));
}

/// 逻辑节点；操作数原样搬入
filter_expr logic_expr(hng::clisv::FilterLogic logic,
                       std::vector<filter_expr> operands)
{
    filter_expr expr;
    hng::clisv::filter_operands* node = expr.mutable_logic();
    node->set_logic(logic);
    for (filter_expr& operand : operands) {
        *node->add_operands() = std::move(operand);
    }
    return expr;
}

filter_expr and_expr(std::vector<filter_expr> operands)
{
    return logic_expr(hng::clisv::FILTER_LOGIC_AND, std::move(operands));
}

filter_expr or_expr(std::vector<filter_expr> operands)
{
    return logic_expr(hng::clisv::FILTER_LOGIC_OR, std::move(operands));
}

filter_expr not_expr(filter_expr operand)
{
    return logic_expr(hng::clisv::FILTER_LOGIC_NOT, {std::move(operand)});
}

/// 表达式取值：type / kind 用底层枚举的数值
constexpr uint32_t kTypeSyscall =
    static_cast<uint32_t>(hng::EventType::SYSCALL_EVENT);
constexpr uint32_t kKindExec = static_cast<uint32_t>(hng::EventKind::EXEC);
constexpr uint32_t kKindFile = static_cast<uint32_t>(hng::EventKind::FILE);

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

const std::vector<Case>& expression_cases()
{
    static const std::vector<Case> table = [] {
        const filter_expr type_syscall =
            numeric(hng::clisv::FILTER_FIELD_TYPE, hng::clisv::FILTER_COMPARE_EQ,
                    {kTypeSyscall});
        const filter_expr kind_exec =
            numeric(hng::clisv::FILTER_FIELD_KIND, hng::clisv::FILTER_COMPARE_EQ,
                    {kKindExec});
        const filter_expr pid_1001_2002 =
            numeric(hng::clisv::FILTER_FIELD_PID, hng::clisv::FILTER_COMPARE_EQ,
                    {1001, 2002});
        const filter_expr pid_1001 = numeric(
            hng::clisv::FILTER_FIELD_PID, hng::clisv::FILTER_COMPARE_EQ, {1001});
        const filter_expr ppid_4321 = numeric(
            hng::clisv::FILTER_FIELD_PPID, hng::clisv::FILTER_COMPARE_EQ, {4321});
        const filter_expr ppid_0 = numeric(hng::clisv::FILTER_FIELD_PPID,
                                           hng::clisv::FILTER_COMPARE_EQ, {0});
        const filter_expr role_id_7_8 =
            numeric(hng::clisv::FILTER_FIELD_ROLE_ID,
                    hng::clisv::FILTER_COMPARE_EQ, {7, 8});
        const filter_expr role_id_0 = numeric(hng::clisv::FILTER_FIELD_ROLE_ID,
                                              hng::clisv::FILTER_COMPARE_EQ, {0});
        const filter_expr kind_file =
            numeric(hng::clisv::FILTER_FIELD_KIND, hng::clisv::FILTER_COMPARE_EQ,
                    {kKindFile});
        const filter_expr role_nginx =
            label(hng::clisv::FILTER_COMPARE_EQ, {"nginx:1.25"});
        const filter_expr context_id_3 =
            numeric(hng::clisv::FILTER_FIELD_CONTEXT_ID,
                    hng::clisv::FILTER_COMPARE_EQ, {3});
        const filter_expr pid_ne_1001_2002 =
            numeric(hng::clisv::FILTER_FIELD_PID, hng::clisv::FILTER_COMPARE_NE,
                    {1001, 2002});
        const filter_expr role_ne_nginx =
            label(hng::clisv::FILTER_COMPARE_NE, {"nginx:1.25"});
        const filter_expr role_prefix =
            label(hng::clisv::FILTER_COMPARE_PREFIX, {"nginx:", "redis:"});
        const filter_expr kind_exec_and_pid_1001 =
            and_expr({kind_exec, pid_1001});
        const filter_expr pid_1001_or_kind_exec = or_expr({pid_1001, kind_exec});
        const filter_expr not_kind_exec         = not_expr(kind_exec);
        const filter_expr not_kind_exec_or_pid_1001 =
            not_expr(or_expr({kind_exec, pid_1001}));

        const auto set = [](filter_expr expr) {
            return [expr = std::move(expr)](ReceiveEventRequest& r) {
                *r.mutable_expr() = expr;
            };
        };

        return std::vector<Case>{
            {"表达式 atom：type 命中", set(type_syscall),
             make_info(1, hng::EventType::SYSCALL_EVENT, 0, 0), true},
            {"表达式 atom：type 不命中", set(type_syscall),
             make_info(1, hng::EventType::FILE_EVENT, 0, 0), false},

            {"表达式 atom：kind 命中", set(kind_exec),
             make_info(1, hng::EventType::SYSCALL_EVENT, 0, 0, {}, 0,
                       hng::EventKind::EXEC),
             true},
            {"表达式 atom：kind 不命中", set(kind_exec),
             make_info(1, hng::EventType::SYSCALL_EVENT, 0, 0, {}, 0,
                       hng::EventKind::PROCESS),
             false},
            {"表达式 atom：kind=9 命中 file 事件", set(kind_file),
             make_info(1, hng::EventType::FILE_EVENT, 0, 0, {}, 0,
                       hng::EventKind::FILE),
             true},

            {"表达式 atom：pid 命中", set(pid_1001_2002),
             make_info(2002, hng::EventType::SYSCALL_EVENT, 0, 0), true},
            {"表达式 atom：pid 不命中", set(pid_1001_2002),
             make_info(3003, hng::EventType::SYSCALL_EVENT, 0, 0), false},

            {"表达式 atom：ppid 命中", set(ppid_4321),
             make_info(1, hng::EventType::SYSCALL_EVENT, 0, 0, {}, 4321), true},
            {"表达式 atom：ppid 不命中", set(ppid_4321),
             make_info(1, hng::EventType::SYSCALL_EVENT, 0, 0, {}, 0), false},
            {"表达式 atom：ppid=0 命中", set(ppid_0),
             make_info(1, hng::EventType::SYSCALL_EVENT, 0, 0, {}, 0), true},

            {"表达式 atom：roleID 命中", set(role_id_7_8),
             make_info(1, hng::EventType::SYSCALL_EVENT, 8, 0), true},
            {"表达式 atom：roleID 不命中", set(role_id_7_8),
             make_info(1, hng::EventType::SYSCALL_EVENT, 9, 0), false},
            {"表达式 atom：roleID=0 命中未落定", set(role_id_0),
             make_info(1, hng::EventType::SYSCALL_EVENT, 0, 0), true},

            {"表达式 atom：roleLabel 命中", set(role_nginx),
             make_info(1, hng::EventType::SYSCALL_EVENT, 9, 0, "nginx:1.25"),
             true},
            {"表达式 atom：roleLabel 不命中", set(role_nginx),
             make_info(1, hng::EventType::SYSCALL_EVENT, 9, 0, "redis:7"), false},

            {"表达式 atom：contextID 命中", set(context_id_3),
             make_info(1, hng::EventType::SYSCALL_EVENT, 0, 3), true},
            {"表达式 atom：contextID 不命中", set(context_id_3),
             make_info(1, hng::EventType::SYSCALL_EVENT, 0, 4), false},

            {"表达式 NE：pid 不在集合内命中", set(pid_ne_1001_2002),
             make_info(3003, hng::EventType::SYSCALL_EVENT, 0, 0), true},
            {"表达式 NE：pid 在集合内不命中", set(pid_ne_1001_2002),
             make_info(2002, hng::EventType::SYSCALL_EVENT, 0, 0), false},
            {"表达式 NE：roleLabel 不等于命中", set(role_ne_nginx),
             make_info(1, hng::EventType::SYSCALL_EVENT, 9, 0, "redis:7"), true},
            {"表达式 NE：roleLabel 等于不命中", set(role_ne_nginx),
             make_info(1, hng::EventType::SYSCALL_EVENT, 9, 0, "nginx:1.25"),
             false},

            {"表达式 PREFIX：roleLabel 前缀命中", set(role_prefix),
             make_info(1, hng::EventType::SYSCALL_EVENT, 9, 0, "nginx:1.25"),
             true},
            {"表达式 PREFIX：roleLabel 前缀不命中", set(role_prefix),
             make_info(1, hng::EventType::SYSCALL_EVENT, 9, 0, "postgres:16"),
             false},

            {"表达式 AND：两原子均命中", set(kind_exec_and_pid_1001),
             make_info(1001, hng::EventType::SYSCALL_EVENT, 0, 0, {}, 0,
                       hng::EventKind::EXEC),
             true},
            {"表达式 AND：仅一原子命中", set(kind_exec_and_pid_1001),
             make_info(3003, hng::EventType::SYSCALL_EVENT, 0, 0, {}, 0,
                       hng::EventKind::EXEC),
             false},

            {"表达式 OR：任一原子命中", set(pid_1001_or_kind_exec),
             make_info(3003, hng::EventType::SYSCALL_EVENT, 0, 0, {}, 0,
                       hng::EventKind::EXEC),
             true},
            {"表达式 OR：两原子均不命中", set(pid_1001_or_kind_exec),
             make_info(3003, hng::EventType::SYSCALL_EVENT, 0, 0, {}, 0,
                       hng::EventKind::PROCESS),
             false},

            {"表达式 NOT：原子不成立时命中", set(not_kind_exec),
             make_info(1, hng::EventType::SYSCALL_EVENT, 0, 0, {}, 0,
                       hng::EventKind::PROCESS),
             true},
            {"表达式 NOT：原子成立时不命中", set(not_kind_exec),
             make_info(1, hng::EventType::SYSCALL_EVENT, 0, 0, {}, 0,
                       hng::EventKind::EXEC),
             false},

            {"表达式嵌套：not (A or B) 命中", set(not_kind_exec_or_pid_1001),
             make_info(3003, hng::EventType::SYSCALL_EVENT, 0, 0, {}, 0,
                       hng::EventKind::PROCESS),
             true},
            {"表达式嵌套：not (A or B) 不命中", set(not_kind_exec_or_pid_1001),
             make_info(1001, hng::EventType::SYSCALL_EVENT, 0, 0, {}, 0,
                       hng::EventKind::PROCESS),
             false},

            {"表达式与 -i 取交：均命中",
             [pid_1001](ReceiveEventRequest& r) {
                 r.mutable_info()->add_pid(1001);
                 *r.mutable_expr() = pid_1001;
             },
             make_info(1001, hng::EventType::SYSCALL_EVENT, 0, 0), true},
            {"表达式与 -i 取交：仅 -i 不命中",
             [pid_1001](ReceiveEventRequest& r) {
                 r.mutable_info()->add_pid(2002);
                 *r.mutable_expr() = pid_1001;
             },
             make_info(1001, hng::EventType::SYSCALL_EVENT, 0, 0), false},

            {"表达式与 -t 取交：均命中",
             [pid_1001](ReceiveEventRequest& r) {
                 add_types(r, {hng::clisv::EVENT_TYPE_SYSCALL});
                 *r.mutable_expr() = pid_1001;
             },
             make_info(1001, hng::EventType::SYSCALL_EVENT, 0, 0), true},
            {"表达式与 -t 取交：仅 -t 不命中",
             [pid_1001](ReceiveEventRequest& r) {
                 add_types(r, {hng::clisv::EVENT_TYPE_SYSCALL});
                 *r.mutable_expr() = pid_1001;
             },
             make_info(1001, hng::EventType::FILE_EVENT, 0, 0), false},
        };
    }();
    return table;
}

const std::vector<InvalidCase>& invalid_cases()
{
    static const std::vector<InvalidCase> table = [] {
        std::vector<InvalidCase> cases;

        cases.push_back({"非法：表达式未设置 node", [](ReceiveEventRequest& r) {
                             *r.mutable_expr() = filter_expr{};
                         }});

        cases.push_back(
            {"非法：field 为 UNSPECIFIED", [](ReceiveEventRequest& r) {
                 *r.mutable_expr() = numeric(hng::clisv::FILTER_FIELD_UNSPECIFIED,
                                             hng::clisv::FILTER_COMPARE_EQ, {1});
             }});

        cases.push_back(
            {"非法：compare 为 UNSPECIFIED", [](ReceiveEventRequest& r) {
                 *r.mutable_expr() =
                     numeric(hng::clisv::FILTER_FIELD_TYPE,
                             hng::clisv::FILTER_COMPARE_UNSPECIFIED, {0});
             }});

        cases.push_back(
            {"非法：logic 为 UNSPECIFIED", [](ReceiveEventRequest& r) {
                 *r.mutable_expr() =
                     logic_expr(hng::clisv::FILTER_LOGIC_UNSPECIFIED,
                                {numeric(hng::clisv::FILTER_FIELD_PID,
                                         hng::clisv::FILTER_COMPARE_EQ, {1})});
             }});

        cases.push_back(
            {"非法：数值字段的取值集合为空", [](ReceiveEventRequest& r) {
                 *r.mutable_expr() = numeric(hng::clisv::FILTER_FIELD_TYPE,
                                             hng::clisv::FILTER_COMPARE_EQ, {});
             }});

        cases.push_back(
            {"非法：role 标签的取值集合为空", [](ReceiveEventRequest& r) {
                 *r.mutable_expr() = label(hng::clisv::FILTER_COMPARE_EQ, {});
             }});

        cases.push_back({"非法：role 标签 EQ 取空串", [](ReceiveEventRequest& r) {
                             *r.mutable_expr() =
                                 label(hng::clisv::FILTER_COMPARE_EQ, {""});
                         }});

        cases.push_back({"非法：role 标签 NE 取空串", [](ReceiveEventRequest& r) {
                             *r.mutable_expr() =
                                 label(hng::clisv::FILTER_COMPARE_NE, {""});
                         }});

        cases.push_back(
            {"非法：role 标签 PREFIX 取空串", [](ReceiveEventRequest& r) {
                 *r.mutable_expr() =
                     label(hng::clisv::FILTER_COMPARE_PREFIX, {""});
             }});

        cases.push_back({"非法：role 标签混有空串", [](ReceiveEventRequest& r) {
                             *r.mutable_expr() =
                                 label(hng::clisv::FILTER_COMPARE_EQ,
                                       {"nginx:1.25", ""});
                         }});

        cases.push_back({"非法：role 标签带 numbers", [](ReceiveEventRequest& r) {
                             filter_atom atom = label_atom(
                                 hng::clisv::FILTER_COMPARE_EQ, {"nginx:1.25"});
                             atom.add_numbers(7);
                             *r.mutable_expr() = atom_expr(std::move(atom));
                         }});

        cases.push_back({"非法：pid 带 strings", [](ReceiveEventRequest& r) {
                             filter_atom atom =
                                 number_atom(hng::clisv::FILTER_FIELD_PID,
                                             hng::clisv::FILTER_COMPARE_EQ, {1});
                             atom.add_strings("nginx:1.25");
                             *r.mutable_expr() = atom_expr(std::move(atom));
                         }});

        cases.push_back({"非法：PREFIX 用于 pid", [](ReceiveEventRequest& r) {
                             *r.mutable_expr() =
                                 numeric(hng::clisv::FILTER_FIELD_PID,
                                         hng::clisv::FILTER_COMPARE_PREFIX, {1});
                         }});

        cases.push_back({"非法：NOT 没有操作数", [](ReceiveEventRequest& r) {
                             *r.mutable_expr() =
                                 logic_expr(hng::clisv::FILTER_LOGIC_NOT, {});
                         }});

        cases.push_back({"非法：NOT 有两个操作数", [](ReceiveEventRequest& r) {
                             *r.mutable_expr() = logic_expr(
                                 hng::clisv::FILTER_LOGIC_NOT,
                                 {numeric(hng::clisv::FILTER_FIELD_PID,
                                          hng::clisv::FILTER_COMPARE_EQ, {1}),
                                  numeric(hng::clisv::FILTER_FIELD_PID,
                                          hng::clisv::FILTER_COMPARE_EQ, {2})});
                         }});

        cases.push_back({"非法：AND 没有操作数", [](ReceiveEventRequest& r) {
                             *r.mutable_expr() =
                                 logic_expr(hng::clisv::FILTER_LOGIC_AND, {});
                         }});

        cases.push_back({"非法：pid 取值为 0", [](ReceiveEventRequest& r) {
                             *r.mutable_expr() =
                                 numeric(hng::clisv::FILTER_FIELD_PID,
                                         hng::clisv::FILTER_COMPARE_EQ, {0});
                         }});

        cases.push_back({"非法：type 取值为 4", [](ReceiveEventRequest& r) {
                             *r.mutable_expr() =
                                 numeric(hng::clisv::FILTER_FIELD_TYPE,
                                         hng::clisv::FILTER_COMPARE_EQ, {4});
                         }});

        cases.push_back({"非法：kind 取值为 0", [](ReceiveEventRequest& r) {
                             *r.mutable_expr() =
                                 numeric(hng::clisv::FILTER_FIELD_KIND,
                                         hng::clisv::FILTER_COMPARE_EQ, {0});
                         }});

        cases.push_back({"非法：kind 取值为 10", [](ReceiveEventRequest& r) {
                             *r.mutable_expr() =
                                 numeric(hng::clisv::FILTER_FIELD_KIND,
                                         hng::clisv::FILTER_COMPARE_EQ, {10});
                         }});

        cases.push_back({"非法：节点数超过 128", [](ReceiveEventRequest& r) {
                             std::vector<filter_expr> operands;
                             for (int i = 0; i < 128; ++i) {
                                 operands.push_back(
                                     numeric(hng::clisv::FILTER_FIELD_PID,
                                             hng::clisv::FILTER_COMPARE_EQ, {1}));
                             }
                             *r.mutable_expr() = and_expr(std::move(operands));
                         }});

        cases.push_back({"非法：嵌套深度超过 16", [](ReceiveEventRequest& r) {
                             filter_expr expr =
                                 numeric(hng::clisv::FILTER_FIELD_PID,
                                         hng::clisv::FILTER_COMPARE_EQ, {1});
                             for (int i = 0; i < 16; ++i) {
                                 expr = not_expr(expr);
                             }
                             *r.mutable_expr() = std::move(expr);
                         }});

        cases.push_back({"非法：单原子取值超过 4096", [](ReceiveEventRequest& r) {
                             filter_atom atom;
                             atom.set_field(hng::clisv::FILTER_FIELD_TYPE);
                             atom.set_compare(hng::clisv::FILTER_COMPARE_EQ);
                             for (uint32_t i = 0; i < 4097u; ++i) {
                                 atom.add_numbers(i % 4);
                             }
                             *r.mutable_expr() = atom_expr(std::move(atom));
                         }});

        return cases;
    }();
    return table;
}

}  // namespace

int main()
{
    for (const Case& c : cases()) {
        ReceiveEventRequest request;
        c.build(request);

        std::string error;
        const std::optional<RuntimeInfoFilter> filter =
            hng::cli::ToRuntimeInfoFilter(request, error);
        CHECK(filter.has_value(), c.name);
        if (filter.has_value()) {
            CHECK(filter->should_take(c.info) == c.expect, c.name);
        }
    }

    for (const Case& c : expression_cases()) {
        ReceiveEventRequest request;
        c.build(request);

        std::string error;
        const std::optional<RuntimeInfoFilter> filter =
            hng::cli::ToRuntimeInfoFilter(request, error);
        CHECK(filter.has_value(), c.name);
        if (filter.has_value()) {
            CHECK(filter->should_take(c.info) == c.expect, c.name);
        }
    }

    for (const InvalidCase& c : invalid_cases()) {
        ReceiveEventRequest request;
        c.build(request);

        std::string error;
        const std::optional<RuntimeInfoFilter> filter =
            hng::cli::ToRuntimeInfoFilter(request, error);
        CHECK(!filter.has_value(), c.name);
        CHECK(!error.empty(), c.name);
    }

    if (g_fail) {
        std::fprintf(stderr, "TOTAL FAILURES: %d\n", g_fail);
        return 1;
    }
    std::printf("ALL PASS\n");
    return 0;
}
