/**
 * @file test_runtime_info_filter.cc
 * @brief RuntimeInfoFilter 的单元测试
 * @details
 * 覆盖过滤器的维度语义（纯值对象，无 IO / 无特权）：
 *  - 默认构造为全选，且可拷贝；
 *  - 进程维度只比 pid，同 pid 不同 start_time 仍命中；
 *  - 角色 / 上下文 / 事件类型维度按集合成员判定；
 *  - 角色维度含 roleID 与 roleLabel 两组，两组之间取并集；
 *  - 维度之内取并集（命中任一成员即可），维度之间取交集；
 *  - 空集合与未设置的维度一样表示不限；
 *  - set_role({0}, {}) / set_context({0}) 只命中未落定的信息，而非不限；
 *  - 未落定的事件不带标签，不会被非空的标签集合命中。
 *
 * 覆盖表达式语义：
 *  - 取值集合无序、含重复时，构造期排序去重后仍能命中；
 *  - and / or / not 的组合，以及空操作数（and 恒真、or 恒假）；
 *  - != 表示不命中集合中任何值，~= 表示标签前缀，not 下 0 与空标签仍是字面值；
 *  - ppid 与 kind 只作为表达式原子出现；
 *  - 维度与表达式、各表达式之间均取交集；
 *  - 拷贝同时保持维度与表达式，默认构造的表达式恒真。
 * @author red-shinku
 * @date 2026.10.10
 */

#include "agent/event_data/include/runtime_info_filter.hpp"

#include <cstdint>
#include <cstdio>
#include <utility>
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

hng::RuntimeInformation make_info(
    uint32_t pid, uint64_t start_time, hng::EventType etype, uint32_t roleID,
    uint32_t contextID, hng::role_label_t roleLabel = {},
    hng::EventKind kind = hng::EventKind::UNSPECIFIED, uint32_t ppid = 0)
{
    hng::RuntimeInformation info;
    info.process   = hng::Process{pid, start_time};
    info.parent    = hng::Process{ppid, static_cast<uint64_t>(ppid) * 10};
    info.etype     = etype;
    info.kind      = kind;
    info.roleID    = roleID;
    info.roleLabel = std::move(roleLabel);
    info.contextID = contextID;
    return info;
}

hng::FilterExpr atom(hng::FilterField field, hng::FilterCompare compare,
                     std::vector<uint32_t> numbers          = {},
                     std::vector<hng::role_label_t> strings = {})
{
    return hng::FilterExpr::make_atom(
        hng::FilterAtom{field, compare, std::move(numbers), std::move(strings)});
}

void run_take_all()
{
    const RuntimeInfoFilter take_all;
    CHECK(take_all.should_take(
              make_info(1, 10, hng::EventType::SYSCALL_EVENT, 0, 0)),
          "全选过滤器应命中未落定的信息");
    CHECK(take_all.should_take(
              make_info(99, 12345, hng::EventType::IPC_EVENT, 7, 8)),
          "全选过滤器应命中任意信息");
}

void run_empty_dimension_is_unlimited()
{
    // 显式设成空集合与不设置等价：该维度不限
    const RuntimeInfoFilter filter = RuntimeInfoFilter{}
                                         .set_process({})
                                         .set_role({}, {})
                                         .set_context({})
                                         .set_etype({});
    CHECK(filter.should_take(make_info(1, 10, hng::EventType::IPC_EVENT, 7, 8)),
          "空集合维度不应参与判定");
}

void run_process_dimension()
{
    RuntimeInfoFilter filter;
    filter.set_process({100, 200});
    CHECK(
        filter.should_take(make_info(100, 500, hng::EventType::FILE_EVENT, 1, 2)),
        "pid 在集合中应命中");
    CHECK(
        filter.should_take(make_info(200, 999, hng::EventType::FILE_EVENT, 1, 2)),
        "集合内任一 pid 都应命中（并集）");
    CHECK(
        filter.should_take(make_info(100, 501, hng::EventType::FILE_EVENT, 1, 2)),
        "进程维度只比 pid，start_time 不同仍应命中");
    CHECK(!filter.should_take(
              make_info(101, 500, hng::EventType::FILE_EVENT, 1, 2)),
          "pid 不在集合中不应命中");
}

void run_role_dimension()
{
    RuntimeInfoFilter filter;
    filter.set_role({42, 43}, {});
    CHECK(filter.should_take(
              make_info(1, 10, hng::EventType::SYSCALL_EVENT, 42, 0)),
          "角色在集合中应命中");
    CHECK(filter.should_take(
              make_info(1, 10, hng::EventType::SYSCALL_EVENT, 43, 0)),
          "集合内任一角色都应命中（并集）");
    CHECK(!filter.should_take(
              make_info(1, 10, hng::EventType::SYSCALL_EVENT, 44, 0)),
          "角色不在集合中不应命中");
}

void run_role_label_dimension()
{
    // roleID 与 roleLabel 同属角色维度：两组取并集
    RuntimeInfoFilter filter;
    filter.set_role({42}, {"nginx:1.25"});

    CHECK(filter.should_take(
              make_info(1, 10, hng::EventType::SYSCALL_EVENT, 42, 0, "")),
          "roleID 命中应通过");
    CHECK(filter.should_take(make_info(1, 10, hng::EventType::SYSCALL_EVENT, 43,
                                       0, "nginx:1.25")),
          "roleLabel 命中应通过：两组是并集");
    CHECK(!filter.should_take(
              make_info(1, 10, hng::EventType::SYSCALL_EVENT, 43, 0, "redis:7")),
          "两组都不命中则不应通过");
    CHECK(!filter.should_take(
              make_info(1, 10, hng::EventType::SYSCALL_EVENT, 43, 0, "")),
          "未落定的事件不带标签，不应被标签集合命中");
}

void run_role_label_only()
{
    // 只设标签：按 roleID 不限，但未落定的事件仍不命中
    RuntimeInfoFilter filter;
    filter.set_role({}, {"nginx:1.25"});

    CHECK(filter.should_take(make_info(1, 10, hng::EventType::SYSCALL_EVENT, 999,
                                       0, "nginx:1.25")),
          "只设标签时按标签命中");
    CHECK(!filter.should_take(
              make_info(1, 10, hng::EventType::SYSCALL_EVENT, 999, 0, "")),
          "只设标签时不命中未落定");
}

void run_context_dimension()
{
    RuntimeInfoFilter filter;
    filter.set_context({9});
    CHECK(
        filter.should_take(make_info(1, 10, hng::EventType::SYSCALL_EVENT, 0, 9)),
        "上下文在集合中应命中");
    CHECK(!filter.should_take(
              make_info(1, 10, hng::EventType::SYSCALL_EVENT, 0, 0)),
          "上下文不在集合中不应命中");
}

void run_etype_dimension()
{
    RuntimeInfoFilter filter;
    filter.set_etype({hng::EventType::FILE_EVENT, hng::EventType::SYSCALL_EVENT});
    CHECK(filter.should_take(make_info(1, 10, hng::EventType::FILE_EVENT, 0, 0)),
          "事件类型在集合中应命中");
    CHECK(
        filter.should_take(make_info(1, 10, hng::EventType::SYSCALL_EVENT, 0, 0)),
        "集合内任一事件类型都应命中（并集）");
    CHECK(!filter.should_take(make_info(1, 10, hng::EventType::IPC_EVENT, 0, 0)),
          "事件类型不在集合中不应命中");
}

void run_dimensions_are_intersected()
{
    RuntimeInfoFilter filter;
    filter.set_process({7}).set_role({3}, {}).set_context({5}).set_etype(
        {hng::EventType::FILE_EVENT});

    CHECK(filter.should_take(make_info(7, 70, hng::EventType::FILE_EVENT, 3, 5)),
          "四个维度全中应命中");
    CHECK(!filter.should_take(make_info(8, 70, hng::EventType::FILE_EVENT, 3, 5)),
          "仅进程不符即不命中");
    CHECK(!filter.should_take(make_info(7, 70, hng::EventType::FILE_EVENT, 4, 5)),
          "仅角色不符即不命中");
    CHECK(!filter.should_take(make_info(7, 70, hng::EventType::FILE_EVENT, 3, 6)),
          "仅上下文不符即不命中");
    CHECK(!filter.should_take(
              make_info(7, 70, hng::EventType::SYSCALL_EVENT, 3, 5)),
          "仅事件类型不符即不命中");
}

void run_zero_is_literal()
{
    // roleID / contextID 的 0 是「未落定」哨兵，按键值比较而非「不限」
    RuntimeInfoFilter filter;
    filter.set_role({0}, {});
    CHECK(filter.should_take(
              make_info(1, 10, hng::EventType::SYSCALL_EVENT, 0, 77)),
          "set_role({0}) 应命中未落定的角色");
    CHECK(!filter.should_take(
              make_info(1, 10, hng::EventType::SYSCALL_EVENT, 3, 77)),
          "set_role({0}) 不应命中已落定的角色");
}

void run_copyable()
{
    RuntimeInfoFilter filter;
    filter.set_role({3}, {}).set_etype({hng::EventType::SYSCALL_EVENT});

    const RuntimeInfoFilter copy = filter;
    CHECK(copy.should_take(make_info(1, 10, hng::EventType::SYSCALL_EVENT, 3, 0)),
          "拷贝应保持各维度");
    CHECK(!copy.should_take(make_info(1, 10, hng::EventType::FILE_EVENT, 3, 0)),
          "拷贝应保持各维度（事件类型）");
}

void run_unordered_duplicates_are_sorted()
{
    // 各维度与表达式的取值集合在构造期排序去重，无序且含重复的输入照常命中
    RuntimeInfoFilter filter;
    filter.set_process({300, 100, 200, 100});
    filter.set_context({9, 9, 3});
    filter.set_role({5, 1, 5}, {"b", "a", "b"});
    filter.set_etype({hng::EventType::FILE_EVENT, hng::EventType::SYSCALL_EVENT});
    filter.add_expression(atom(hng::FilterField::PID, hng::FilterCompare::EQ,
                               {300, 100, 200, 100}));

    CHECK(filter.should_take(
              make_info(200, 20, hng::EventType::FILE_EVENT, 5, 3, "a")),
          "无序重复的取值集合应能命中");
    CHECK(filter.should_take(
              make_info(300, 30, hng::EventType::SYSCALL_EVENT, 1, 9, "b")),
          "无序重复的取值集合应能命中（另一成员）");
    CHECK(filter.should_take(
              make_info(200, 20, hng::EventType::FILE_EVENT, 9, 3, "b")),
          "排序后的标签集合应能命中（角色维度取并集）");
    CHECK(!filter.should_take(
              make_info(400, 40, hng::EventType::FILE_EVENT, 5, 3, "a")),
          "不在集合中的 pid 不应命中");
    CHECK(!filter.should_take(
              make_info(200, 20, hng::EventType::IPC_EVENT, 5, 3, "a")),
          "不在集合中的事件类型不应命中");
    CHECK(!filter.should_take(
              make_info(200, 20, hng::EventType::FILE_EVENT, 5, 4, "a")),
          "不在集合中的上下文不应命中");
    CHECK(!filter.should_take(
              make_info(200, 20, hng::EventType::FILE_EVENT, 9, 3, "c")),
          "既不在 roleID 也不在标签集合中不应命中");
}

void run_expression_logic()
{
    const hng::FilterExpr is_exec =
        atom(hng::FilterField::KIND, hng::FilterCompare::EQ, {2});
    const hng::FilterExpr is_pid7 =
        atom(hng::FilterField::PID, hng::FilterCompare::EQ, {7});

    const hng::RuntimeInformation exec7 = make_info(
        7, 70, hng::EventType::SYSCALL_EVENT, 0, 0, "", hng::EventKind::EXEC);
    const hng::RuntimeInformation exec8 = make_info(
        8, 80, hng::EventType::SYSCALL_EVENT, 0, 0, "", hng::EventKind::EXEC);
    const hng::RuntimeInformation process7 = make_info(
        7, 70, hng::EventType::SYSCALL_EVENT, 0, 0, "", hng::EventKind::PROCESS);
    const hng::RuntimeInformation process8 = make_info(
        8, 80, hng::EventType::SYSCALL_EVENT, 0, 0, "", hng::EventKind::PROCESS);

    const hng::FilterExpr both = hng::FilterExpr::make_and({is_exec, is_pid7});
    CHECK(both.matches(exec7), "and：两个原子全中应命中");
    CHECK(!both.matches(exec8), "and：任一原子不中即不命中");
    CHECK(!both.matches(process7), "and：任一原子不中即不命中");

    const hng::FilterExpr either = hng::FilterExpr::make_or({is_exec, is_pid7});
    CHECK(either.matches(exec8), "or：命中其中一个原子即命中");
    CHECK(either.matches(process7), "or：命中其中一个原子即命中");
    CHECK(!either.matches(process8), "or：两个原子都不中才不命中");

    const hng::FilterExpr neither = hng::FilterExpr::make_not(either);
    CHECK(!neither.matches(exec8), "not：被取反的表达式为真则假");
    CHECK(neither.matches(process8), "not：被取反的表达式为假则真");

    const hng::FilterExpr nested =
        hng::FilterExpr::make_and({is_exec, hng::FilterExpr::make_not(is_pid7)});
    CHECK(nested.matches(exec8), "嵌套：and 与 not 同时命中");
    CHECK(!nested.matches(exec7), "嵌套：not 分支不命中即不命中");
    CHECK(!nested.matches(process8), "嵌套：and 分支不命中即不命中");

    const hng::RuntimeInformation any =
        make_info(1, 10, hng::EventType::FILE_EVENT, 0, 0);
    CHECK(hng::FilterExpr::make_and({}).matches(any), "and 空操作数为恒真");
    CHECK(!hng::FilterExpr::make_or({}).matches(any), "or 空操作数为恒假");
    CHECK(hng::FilterExpr::make_not(hng::FilterExpr::make_or({})).matches(any),
          "not 恒假为恒真");
}

void run_expression_compare_semantics()
{
    const hng::RuntimeInformation nginx =
        make_info(1, 10, hng::EventType::SYSCALL_EVENT, 42, 0, "nginx:1.25");
    const hng::RuntimeInformation redis =
        make_info(1, 10, hng::EventType::SYSCALL_EVENT, 42, 0, "redis:7");
    const hng::RuntimeInformation unsettled =
        make_info(1, 10, hng::EventType::SYSCALL_EVENT, 0, 0, "");

    // != 是不命中集合中任何值（NOT IN）
    const hng::FilterExpr not_nginx = atom(
        hng::FilterField::ROLE_LABEL, hng::FilterCompare::NE, {}, {"nginx:1.25"});
    CHECK(!not_nginx.matches(nginx), "!=：命中集合成员则假");
    CHECK(not_nginx.matches(redis), "!=：不在集合中则真");
    CHECK(not_nginx.matches(unsettled), "!=：空标签不在集合中则为真");

    const hng::FilterExpr not_role_id =
        atom(hng::FilterField::ROLE_ID, hng::FilterCompare::NE, {7, 8});
    CHECK(not_role_id.matches(nginx), "!= 多值：不在集合中则真");
    CHECK(!not_role_id.matches(
              make_info(1, 10, hng::EventType::SYSCALL_EVENT, 8, 0)),
          "!= 多值：命中集合成员则假");

    // ~= 只用于标签，按前缀命中
    const hng::FilterExpr nginx_prefix = atom(
        hng::FilterField::ROLE_LABEL, hng::FilterCompare::PREFIX, {}, {"nginx"});
    CHECK(nginx_prefix.matches(nginx), "~=：以该前缀开头的标签应命中");
    CHECK(nginx_prefix.matches(make_info(1, 10, hng::EventType::SYSCALL_EVENT, 0,
                                         0, "nginx:1.25-alpine")),
          "~=：以该前缀开头的标签应命中（更长标签）");
    CHECK(!nginx_prefix.matches(redis), "~=：不以该前缀开头不命中");
    CHECK(!nginx_prefix.matches(unsettled), "~=：空标签不命中该前缀");

    // 集合中的取值不必都是标签的前缀：较短的前缀仍须命中。单次 lower_bound
    // 会落在 "abcx"（它大于 "abcdef" 且不是前缀），从而漏掉 "ab"
    const hng::FilterExpr ab_abcx =
        atom(hng::FilterField::ROLE_LABEL, hng::FilterCompare::PREFIX, {},
             {"ab", "abcx"});
    CHECK(ab_abcx.matches(
              make_info(1, 10, hng::EventType::SYSCALL_EVENT, 0, 0, "abcdef")),
          "~=：集合中较短的前缀也应命中（单次 lower_bound 会漏）");
    CHECK(!atom(hng::FilterField::ROLE_LABEL, hng::FilterCompare::PREFIX, {},
                {"abcx"})
               .matches(make_info(1, 10, hng::EventType::SYSCALL_EVENT, 0, 0,
                                  "abcdef")),
          "~=：集合中没有该标签的前缀时不命中");

    // PREFIX 只对 ROLE_LABEL 有效：数值字段上的该组合在求值层不求值
    CHECK(!atom(hng::FilterField::PID, hng::FilterCompare::PREFIX, {7})
               .matches(make_info(7, 70, hng::EventType::SYSCALL_EVENT, 0, 0)),
          "PREFIX 用于数值字段是非法组合，不应命中");

    // 0 与空串在 not 下仍是字面值
    const hng::FilterExpr not_unsettled_role = hng::FilterExpr::make_not(
        atom(hng::FilterField::ROLE_ID, hng::FilterCompare::EQ, {0}));
    CHECK(!not_unsettled_role.matches(unsettled), "not roleID=0 不应命中未落定");
    CHECK(not_unsettled_role.matches(nginx), "not roleID=0 应命中已落定");

    const hng::FilterExpr not_empty_label = hng::FilterExpr::make_not(
        atom(hng::FilterField::ROLE_LABEL, hng::FilterCompare::EQ, {}, {""}));
    CHECK(!not_empty_label.matches(unsettled), "not role=\"\" 不应命中空标签");
    CHECK(not_empty_label.matches(nginx), "not role=\"\" 应命中非空标签");

    const hng::FilterExpr not_nginx_label = hng::FilterExpr::make_not(
        atom(hng::FilterField::ROLE_LABEL, hng::FilterCompare::EQ, {},
             {"nginx:1.25"}));
    CHECK(!not_nginx_label.matches(nginx), "not role=nginx 不应命中该标签");
    CHECK(not_nginx_label.matches(unsettled),
          "not role=nginx 会命中未落定（空标签），排除需配合 roleID!=0");
}

void run_parent_and_kind_atoms()
{
    const hng::RuntimeInformation exec_child =
        make_info(7, 70, hng::EventType::SYSCALL_EVENT, 0, 0, "",
                  hng::EventKind::EXEC, 900);
    const hng::RuntimeInformation file_child = make_info(
        8, 80, hng::EventType::FILE_EVENT, 0, 0, "", hng::EventKind::FILE, 0);

    CHECK(atom(hng::FilterField::PPID, hng::FilterCompare::EQ, {900})
              .matches(exec_child),
          "PPID 原子应取事件发生时刻的父进程 pid");
    CHECK(!atom(hng::FilterField::PPID, hng::FilterCompare::EQ, {901})
               .matches(exec_child),
          "父进程 pid 不在集合中不应命中");
    CHECK(atom(hng::FilterField::PPID, hng::FilterCompare::EQ, {0})
              .matches(file_child),
          "ppid=0 是合法取值，应能字面命中");
    CHECK(!atom(hng::FilterField::PPID, hng::FilterCompare::EQ, {0})
               .matches(exec_child),
          "ppid=0 不应命中父进程已存在的进程");
    CHECK(atom(hng::FilterField::PPID, hng::FilterCompare::NE, {0})
              .matches(exec_child),
          "PPID != 0 应命中父进程已存在的进程");

    CHECK(atom(hng::FilterField::KIND, hng::FilterCompare::EQ, {2})
              .matches(exec_child),
          "KIND 原子应取语义子类型");
    CHECK(!atom(hng::FilterField::KIND, hng::FilterCompare::EQ, {1})
               .matches(exec_child),
          "语义子类型不在集合中不应命中");
    CHECK(atom(hng::FilterField::KIND, hng::FilterCompare::EQ, {9})
              .matches(file_child),
          "file 流的语义子类型为 FILE");
    CHECK(atom(hng::FilterField::KIND, hng::FilterCompare::NE, {1})
              .matches(file_child),
          "KIND != 1 应命中非进程生命周期事件");
}

void run_expressions_intersect_dimensions()
{
    RuntimeInfoFilter filter;
    filter.set_process({7})
        .add_expression(atom(hng::FilterField::KIND, hng::FilterCompare::EQ, {2}))
        .add_expression(
            atom(hng::FilterField::ROLE_ID, hng::FilterCompare::EQ, {3}));

    CHECK(filter.should_take(make_info(7, 70, hng::EventType::SYSCALL_EVENT, 3, 0,
                                       "", hng::EventKind::EXEC)),
          "维度与各表达式全中应命中");
    CHECK(!filter.should_take(make_info(8, 80, hng::EventType::SYSCALL_EVENT, 3,
                                        0, "", hng::EventKind::EXEC)),
          "维度不中即不命中");
    CHECK(!filter.should_take(make_info(7, 70, hng::EventType::SYSCALL_EVENT, 3,
                                        0, "", hng::EventKind::PROCESS)),
          "表达式其一不中即不命中");
    CHECK(!filter.should_take(make_info(7, 70, hng::EventType::SYSCALL_EVENT, 4,
                                        0, "", hng::EventKind::EXEC)),
          "表达式其二不中即不命中");
}

void run_default_expression_is_true()
{
    const hng::FilterExpr take_all;
    CHECK(take_all.matches(make_info(1, 10, hng::EventType::FILE_EVENT, 0, 0)),
          "默认构造的表达式恒真");
    CHECK(take_all.matches(make_info(99, 990, hng::EventType::IPC_EVENT, 7, 8,
                                     "nginx:1.25", hng::EventKind::KERNEL, 5)),
          "默认构造的表达式恒真（任意信息）");

    RuntimeInfoFilter filter;
    filter.set_process({7}).add_expression(hng::FilterExpr{});
    CHECK(filter.should_take(make_info(7, 70, hng::EventType::FILE_EVENT, 0, 0)),
          "追加恒真表达式不改变结果");
}

void run_copy_keeps_expressions()
{
    RuntimeInfoFilter filter;
    filter.set_process({7}).add_expression(
        atom(hng::FilterField::KIND, hng::FilterCompare::EQ, {2}));

    const RuntimeInfoFilter copy = filter;
    CHECK(copy.should_take(make_info(7, 70, hng::EventType::SYSCALL_EVENT, 0, 0,
                                     "", hng::EventKind::EXEC)),
          "拷贝应保持表达式");
    CHECK(!copy.should_take(make_info(7, 70, hng::EventType::SYSCALL_EVENT, 0, 0,
                                      "", hng::EventKind::PROCESS)),
          "拷贝应保持表达式（语义子类型）");
    CHECK(!copy.should_take(make_info(8, 80, hng::EventType::SYSCALL_EVENT, 0, 0,
                                      "", hng::EventKind::EXEC)),
          "拷贝应保持维度");
}

}  // namespace

int main()
{
    run_take_all();
    run_empty_dimension_is_unlimited();
    run_process_dimension();
    run_role_dimension();
    run_role_label_dimension();
    run_role_label_only();
    run_context_dimension();
    run_etype_dimension();
    run_dimensions_are_intersected();
    run_zero_is_literal();
    run_copyable();
    run_unordered_duplicates_are_sorted();
    run_expression_logic();
    run_expression_compare_semantics();
    run_parent_and_kind_atoms();
    run_expressions_intersect_dimensions();
    run_default_expression_is_true();
    run_copy_keeps_expressions();

    if (g_fail) {
        std::fprintf(stderr, "TOTAL FAILURES: %d\n", g_fail);
        return 1;
    }
    std::printf("ALL PASS\n");
    return 0;
}
