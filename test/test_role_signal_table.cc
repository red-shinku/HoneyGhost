/**
 * @file test_role_signal_table.cc
 * @brief 角色存活状态表的表驱动单元测试
 * @details
 * 覆盖 agent/role_discovery 的 RoleSignalTable：
 *  - 进入观察的三条分支：不存在→加入、锚点相同→无产出、锚点不同→主进程更换；
 *  - 离开观察的三条分支：存活→退出、未知实例→无产出、重复离开→无产出；
 *  - 观察量序列：乱序、重复、重连后重放快照均不产出多余动作；
 *  - 载荷缓存：锚点更换后缓存被更新，退出事件的载荷由缓存回填；
 *  - 快照对账：缺席的存活项产出退出、新增项产出加入、段未走完不结算、
 *    范围外的条目与未知项不被清除、重复快照幂等、结算顺序确定。
 *
 * @author red_shinku
 * @date 2026.9.11
 */

#include "agent/role_discovery/src/role_signal_table.hpp"

#include <cstdio>
#include <optional>
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

using hng::role::RoleAction;
using hng::role::RoleEvent;
using hng::role::RoleObservation;
using hng::role::RolePayload;
using hng::role::RoleSignalTable;

/// 预置实例使用的实例键
constexpr const char* kSeedKey = "seed";

const char* action_name(RoleAction action)
{
    switch (action) {
        case RoleAction::JOIN:
            return "JOIN";
        case RoleAction::LEAVE:
            return "LEAVE";
        case RoleAction::MAIN_PROCESS_CHANGE:
            return "MAIN_PROCESS_CHANGE";
    }
    return "?";
}

/// 构造带完整补齐信息的载荷
RolePayload mk_payload(const char* key, uint32_t pid, uint64_t start)
{
    RolePayload payload;
    payload.identity.instance_key      = key;
    payload.identity.type_key          = "nginx";
    payload.identity.attributes["ns"]  = "hng";
    payload.identity.attributes["pod"] = "p1";
    payload.main_process               = hng::Process{pid, start};
    payload.cgroup_path      = "/sys/fs/cgroup/system.slice/nginx.service";
    payload.member_processes = {hng::Process{pid, start}};
    return payload;
}

/// 预置一个存活实例，返回其加入事件
RoleEvent seed(RoleSignalTable& table, uint32_t pid, uint64_t start)
{
    std::optional<RoleEvent> event =
        table.submit(hng::role::observe_enter(mk_payload(kSeedKey, pid, start)));
    CHECK(event.has_value() && event->action == RoleAction::JOIN,
          "预置实例应产出加入");
    return event.value_or(RoleEvent{});
}

// ---- 单步跃迁：三类事实各自的分支 ----
struct StepCase {
    const char* name;
    bool seeded;  // 是否预置存活实例
    uint32_t seed_pid;
    uint64_t seed_start;
    bool present;     // 本次观察的存在信号
    const char* key;  // 本次观察的实例键
    uint32_t pid;     // 本次观察的锚点
    uint64_t start;
    bool has_event;     // 期望是否产出事件
    RoleAction expect;  // 期望动作（无产出时无意义）
};

constexpr StepCase kEnterCases[] = {
    // 不存在 → 存在
    {"空表 + 进入 -> 加入", false, 0, 0, true, "seed", 100, 1000, true,
     RoleAction::JOIN},
    // 存在 & 锚点相同 → 无产出（重复观察 / 重连重放）
    {"存活 + 进入 & 锚点相同 -> 无产出", true, 100, 1000, true, "seed", 100, 1000,
     false, RoleAction::JOIN},
    // 存在 & 锚点不同 → 主进程更换（pid 变）
    {"存活 + 进入 & pid 变化 -> 主进程更换", true, 100, 1000, true, "seed", 101,
     1000, true, RoleAction::MAIN_PROCESS_CHANGE},
    // 存在 & 锚点不同 → 主进程更换（pid 复用，start_time 变）
    {"存活 + 进入 & start 变化 -> 主进程更换", true, 100, 1000, true, "seed", 100,
     2000, true, RoleAction::MAIN_PROCESS_CHANGE},
    // 存在但实例键不同 → 另一个实例的加入
    {"存活 + 进入(他键) -> 加入", true, 100, 1000, true, "other", 200, 2000, true,
     RoleAction::JOIN},
};

constexpr StepCase kLeaveCases[] = {
    // 不存在 → 无产出
    {"空表 + 离开 -> 无产出", false, 0, 0, false, "seed", 0, 0, false,
     RoleAction::LEAVE},
    // 存在 → 不存在
    {"存活 + 离开 -> 退出", true, 100, 1000, false, "seed", 0, 0, true,
     RoleAction::LEAVE},
    // 实例键不匹配 → 无产出
    {"存活 + 离开(他键) -> 无产出", true, 100, 1000, false, "other", 0, 0, false,
     RoleAction::LEAVE},
    // 离开观察携带的锚点不参与判定
    {"存活 + 离开(锚点陈旧) -> 退出", true, 100, 1000, false, "seed", 999, 9,
     true, RoleAction::LEAVE},
};

void check_step(const StepCase& c)
{
    RoleSignalTable table;
    if (c.seeded) {
        seed(table, c.seed_pid, c.seed_start);
    }
    RoleObservation observation =
        c.present ? hng::role::observe_enter(mk_payload(c.key, c.pid, c.start))
                  : hng::role::observe_leave(c.key);
    std::optional<RoleEvent> event = table.submit(observation);

    if (event.has_value() != c.has_event) {
        ++g_fail;
        std::fprintf(stderr, "[FAIL] %s: 产出=%d 期望=%d\n", c.name,
                     (int)event.has_value(), (int)c.has_event);
        return;
    }
    if (event.has_value() && event->action != c.expect) {
        ++g_fail;
        std::fprintf(stderr, "[FAIL] %s: 动作=%s 期望=%s\n", c.name,
                     action_name(event->action), action_name(c.expect));
    }
}

void run_steps()
{
    for (const StepCase& c : kEnterCases) {
        check_step(c);
    }
    for (const StepCase& c : kLeaveCases) {
        check_step(c);
    }
}

// ---- 观察量序列：乱序、重复、重连重放 ----
struct SeqStep {
    bool present;
    const char* key;
    uint32_t pid;
    uint64_t start;
};

struct SeqCase {
    const char* name;
    std::vector<SeqStep> steps;
    std::vector<RoleAction> expect;
};

const SeqCase kSeqCases[] = {
    {
        // 重连策略即「无条件重新快照 + 重新订阅」：重放已发布的快照不产出任何动作
        "重连重放快照无多余动作",
        {{true, "a", 100, 1000},
         {true, "b", 200, 2000},
         {false, "a", 0, 0},
         {true, "b", 200, 2000},
         {true, "b", 200, 2000}},
        {RoleAction::JOIN, RoleAction::JOIN, RoleAction::LEAVE},
    },
    {
        // 离开先到（乱序）不产出；重复的进入与离开也不产出
        "乱序与重复观察量",
        {{false, "a", 0, 0},
         {true, "a", 100, 1000},
         {true, "a", 100, 1000},
         {true, "a", 100, 1000},
         {false, "a", 0, 0},
         {false, "a", 0, 0}},
        {RoleAction::JOIN, RoleAction::LEAVE},
    },
    {
        // 锚点跃迁夹在存在性跃迁之间
        "锚点跃迁序列",
        {{true, "a", 100, 1000},
         {true, "a", 101, 1000},
         {true, "a", 101, 1000},
         {false, "a", 0, 0}},
        {RoleAction::JOIN, RoleAction::MAIN_PROCESS_CHANGE, RoleAction::LEAVE},
    },
    {
        // 同一实例键退出后重新进入：按新实例产出加入
        "退出后重新进入",
        {{true, "a", 100, 1000}, {false, "a", 0, 0}, {true, "a", 100, 2000}},
        {RoleAction::JOIN, RoleAction::LEAVE, RoleAction::JOIN},
    },
};

void run_sequences()
{
    for (const SeqCase& c : kSeqCases) {
        RoleSignalTable table;
        std::vector<RoleAction> got;
        for (const SeqStep& step : c.steps) {
            RoleObservation observation =
                step.present ? hng::role::observe_enter(
                                   mk_payload(step.key, step.pid, step.start))
                             : hng::role::observe_leave(step.key);
            if (std::optional<RoleEvent> event = table.submit(observation)) {
                got.push_back(event->action);
            }
        }
        if (got.size() != c.expect.size()) {
            ++g_fail;
            std::fprintf(stderr, "[FAIL] %s: 动作数=%zu 期望=%zu\n", c.name,
                         got.size(), c.expect.size());
            continue;
        }
        for (std::size_t i = 0; i < got.size(); ++i) {
            if (got[i] != c.expect[i]) {
                ++g_fail;
                std::fprintf(stderr, "[FAIL] %s: 第 %zu 个动作=%s 期望=%s\n",
                             c.name, i, action_name(got[i]),
                             action_name(c.expect[i]));
            }
        }
    }
}

// ---- 载荷缓存 ----
void run_payload_cache()
{
    // 加入事件的载荷逐个字段透传（含 cgroup 补齐）
    {
        RoleSignalTable table;
        RolePayload sent = mk_payload("a", 100, 1000);
        std::optional<RoleEvent> event =
            table.submit(hng::role::observe_enter(sent));
        CHECK(event.has_value(), "进入应产出加入");
        if (event.has_value()) {
            CHECK(event->payload.identity.type_key == "nginx", "加入应带类型键");
            CHECK(event->payload.identity.attributes == sent.identity.attributes,
                  "加入应带属性");
            CHECK(event->payload.cgroup_path == sent.cgroup_path,
                  "加入应带 cgroup 路径");
            CHECK(event->payload.member_processes.size() == 1,
                  "加入应带成员列表");
            CHECK(event->payload.main_process == sent.main_process,
                  "加入应带锚点");
        }
        CHECK(table.is_alive("a"), "加入后应存活");
    }

    // 锚点更换更新缓存：随后的退出事件带新锚点
    {
        RoleSignalTable table;
        seed(table, 100, 1000);
        std::optional<RoleEvent> changed = table.submit(
            hng::role::observe_enter(mk_payload(kSeedKey, 101, 2000)));
        CHECK(changed.has_value() &&
                  changed->action == RoleAction::MAIN_PROCESS_CHANGE,
              "锚点变化应产出主进程更换");
        auto cached = table.lookup(kSeedKey);
        CHECK(cached.has_value() && cached->main_process.pid == 101,
              "缓存锚点应更新");
    }

    // 退出事件的载荷由缓存回填：离开观察只带实例键
    {
        RoleSignalTable table;
        seed(table, 100, 1000);
        std::optional<RoleEvent> event =
            table.submit(hng::role::observe_leave(kSeedKey));
        CHECK(event.has_value() && event->action == RoleAction::LEAVE,
              "存活实例离开应产出退出");
        if (event.has_value()) {
            CHECK(event->payload.identity.type_key == "nginx",
                  "退出应回填类型键");
            CHECK(event->payload.identity.attributes.count("pod") == 1,
                  "退出应回填属性");
            CHECK(event->payload.cgroup_path ==
                      "/sys/fs/cgroup/system.slice/nginx.service",
                  "退出应回填 cgroup 路径");
            CHECK(event->payload.main_process.pid == 100, "退出应回填锚点");
            CHECK(event->payload.member_processes.empty(), "退出不应带成员列表");
        }
        CHECK(!table.is_alive(kSeedKey), "退出后不应存活");
        CHECK(!table.lookup(kSeedKey).has_value(), "退出后缓存应清空");
    }

    // 未存活实例的查找为空
    {
        RoleSignalTable table;
        CHECK(!table.lookup("nobody").has_value(), "未存活实例查找应为空");
        CHECK(!table.is_alive("nobody"), "未存活实例不应存活");
    }
}

// ---- 快照对账 ----
struct SnapStep {
    char op;  ///< 'b' 开段（key 为范围标签）、'e' 结算、'+' 进入、'-' 离开、'?'
              ///< 未知
    const char* key;  ///< 'b' 为范围标签，其余为实例键
};

struct SnapCase {
    const char* name;
    std::vector<SnapStep> steps;
    std::vector<const char*> expect;  ///< "动作:实例键"，顺序敏感
    std::vector<const char*> alive;   ///< 结束时应仍存活的实例键
};

/// 由实例键推导锚点：同一实例键的重复观察得到同一锚点，才谈得上重放
hng::Process anchor_of(const char* key)
{
    return hng::Process{static_cast<uint32_t>(100 + key[0]), 1000};
}

std::string describe(const RoleEvent& event)
{
    return std::string(action_name(event.action)) + ":" +
           event.payload.identity.instance_key;
}

bool submit_into(RoleSignalTable& table, const RoleObservation& observation,
                 std::vector<std::string>& produced)
{
    std::optional<RoleEvent> event = table.submit(observation);
    if (!event.has_value()) {
        return false;
    }
    produced.push_back(describe(*event));
    return true;
}

void expect_events(const char* name, const std::vector<std::string>& got,
                   const std::vector<const char*>& want)
{
    if (got.size() != want.size()) {
        ++g_fail;
        std::fprintf(stderr, "[FAIL] %s: 事件数=%zu 期望=%zu\n", name, got.size(),
                     want.size());
        for (const std::string& s : got) {
            std::fprintf(stderr, "        实际 %s\n", s.c_str());
        }
        return;
    }
    for (std::size_t i = 0; i < got.size(); ++i) {
        if (got[i] != want[i]) {
            ++g_fail;
            std::fprintf(stderr, "[FAIL] %s: 第 %zu 个事件=%s 期望=%s\n", name, i,
                         got[i].c_str(), want[i]);
        }
    }
}

const SnapCase kSnapCases[] = {
    {
        // 规则 1 的反例：只喂不结算则 B 永远存活
        "重连对账：缺席的存活项产出退出",
        {{'b', "k8s.io"},
         {'+', "a"},
         {'+', "b"},
         {'e', nullptr},
         {'b', "k8s.io"},
         {'+', "a"},
         {'e', nullptr}},
        {"JOIN:a", "JOIN:b", "LEAVE:b"},
        {"a"},
    },
    {
        "重连对账：新增项只产出加入",
        {{'b', "k8s.io"},
         {'+', "a"},
         {'+', "b"},
         {'e', nullptr},
         {'b', "k8s.io"},
         {'+', "a"},
         {'+', "b"},
         {'+', "c"},
         {'e', nullptr}},
        {"JOIN:a", "JOIN:b", "JOIN:c"},
        {"a", "b", "c"},
    },
    {
        // 不完整的快照不是权威状态，段没走完就断连时不得结算
        "段未走完不结算",
        {{'b', "k8s.io"},
         {'+', "a"},
         {'+', "b"},
         {'e', nullptr},
         {'b', "k8s.io"},
         {'+', "a"}},
        {"JOIN:a", "JOIN:b"},
        {"a", "b"},
    },
    {
        "空段不产出动作（首次连接）",
        {{'b', "k8s.io"}, {'e', nullptr}},
        {},
        {},
    },
    {
        // 另一 namespace 本轮没被枚举，既非退出也非确认，不能清
        "范围外的存活项不被对账清除",
        {{'b', "k8s.io"},
         {'+', "a"},
         {'e', nullptr},
         {'b', "moby"},
         {'+', "b"},
         {'e', nullptr},
         {'b', "k8s.io"},
         {'+', "a"},
         {'e', nullptr}},
        {"JOIN:a", "JOIN:b"},
        {"a", "b"},
    },
    {
        "重复快照幂等：第二段不产出动作",
        {{'b', "k8s.io"},
         {'+', "a"},
         {'+', "b"},
         {'e', nullptr},
         {'b', "k8s.io"},
         {'+', "a"},
         {'+', "b"},
         {'e', nullptr}},
        {"JOIN:a", "JOIN:b"},
        {"a", "b"},
    },
    {
        // 哈希遍历顺序不确定，结算产出必须按实例键定序
        "结算顺序按实例键升序",
        {{'b', "k8s.io"},
         {'+', "c"},
         {'+', "a"},
         {'+', "b"},
         {'e', nullptr},
         {'b', "k8s.io"},
         {'e', nullptr}},
        {"JOIN:c", "JOIN:a", "JOIN:b", "LEAVE:a", "LEAVE:b", "LEAVE:c"},
        {},
    },
    {
        // 未知既不推进载荷缓存也不产出跃迁，段外更是无处可依
        "段外未知观察无动作",
        {{'?', "a"}},
        {},
        {},
    },
};

void run_reconciliation()
{
    for (const SnapCase& c : kSnapCases) {
        RoleSignalTable table;
        std::vector<std::string> got;
        std::string scope;
        for (const SnapStep& step : c.steps) {
            switch (step.op) {
                case 'b':
                    table.begin_snapshot({step.key});
                    scope = step.key;
                    break;
                case 'e':
                    for (const RoleEvent& event : table.end_snapshot()) {
                        got.push_back(describe(event));
                    }
                    scope.clear();
                    break;
                case '+': {
                    const hng::Process anchor = anchor_of(step.key);
                    submit_into(table,
                                hng::role::observe_enter(
                                    mk_payload(step.key, anchor.pid,
                                               anchor.pid_start_time),
                                    scope),
                                got);
                    break;
                }
                case '-':
                    submit_into(table, hng::role::observe_leave(step.key), got);
                    break;
                case '?':
                    submit_into(table, hng::role::observe_unknown(step.key), got);
                    break;
                default:
                    break;
            }
        }
        expect_events(c.name, got, c.expect);
        for (const char* key : c.alive) {
            if (!table.is_alive(key)) {
                ++g_fail;
                std::fprintf(stderr, "[FAIL] %s: %s 应仍存活\n", c.name, key);
            }
        }
    }
}

/// 段内到达的流内观察刷新代际，结算不得把它清掉（P5 的表侧一半）
void run_snapshot_stream_inside()
{
    RoleSignalTable table;
    table.submit(
        hng::role::observe_enter(mk_payload(kSeedKey, 100, 1000), "k8s.io"));

    table.begin_snapshot({"k8s.io"});
    // 枚举行是段内较早的一笔
    table.submit(
        hng::role::observe_enter(mk_payload(kSeedKey, 100, 1000), "k8s.io"));
    // 段内流内到达的一笔比枚举新：主进程已换成 200
    std::optional<RoleEvent> live = table.submit(
        hng::role::observe_enter(mk_payload(kSeedKey, 200, 2000), "k8s.io"));
    CHECK(live.has_value() && live->action == RoleAction::MAIN_PROCESS_CHANGE,
          "段内流内观察应产出主进程更换");

    const std::vector<RoleEvent> settled = table.end_snapshot();
    CHECK(settled.empty(), "段内流内观察命中的条目不应被对账清除");
    CHECK(table.is_alive(kSeedKey), "段内流内观察命中的条目应仍存活");
    auto cached = table.lookup(kSeedKey);
    CHECK(cached.has_value() && cached->main_process.pid == 200,
          "载荷缓存应取段内流内观察的锚点");
}

/// 未知态的两条边界：段内计为已见且不推进载荷缓存，段外不刷代际
void run_unknown()
{
    // 段内取数失败：不产出退出，条目免于对账，缓存原样保留
    {
        RoleSignalTable table;
        table.submit(
            hng::role::observe_enter(mk_payload(kSeedKey, 100, 1000), "k8s.io"));
        table.begin_snapshot({"k8s.io"});
        CHECK(!table.submit(hng::role::observe_unknown(kSeedKey)).has_value(),
              "未知观察不应产出跃迁");
        const std::vector<RoleEvent> settled = table.end_snapshot();
        CHECK(settled.empty(), "未知不得被读成不存在：不应产出退出");
        CHECK(table.is_alive(kSeedKey), "未知项应计为本段已见");
        auto cached = table.lookup(kSeedKey);
        CHECK(cached.has_value() && cached->main_process.pid == 100,
              "未知不应推进载荷缓存");
    }

    // 段外未知：无处可依，条目照常被后续对账清掉
    {
        RoleSignalTable table;
        table.submit(
            hng::role::observe_enter(mk_payload(kSeedKey, 100, 1000), "k8s.io"));
        CHECK(!table.submit(hng::role::observe_unknown(kSeedKey)).has_value(),
              "段外未知观察不应产出跃迁");
        table.begin_snapshot({"k8s.io"});
        const std::vector<RoleEvent> settled = table.end_snapshot();
        CHECK(settled.size() == 1, "段外未知不得让条目免于对账");
    }
}

}  // namespace

int main()
{
    run_steps();
    run_sequences();
    run_payload_cache();
    run_reconciliation();
    run_snapshot_stream_inside();
    run_unknown();
    if (g_fail) {
        std::fprintf(stderr, "TOTAL FAILURES: %d\n", g_fail);
        return 1;
    }
    std::printf("ALL PASS (step=%zu seq=%zu snap=%zu)\n",
                sizeof(kEnterCases) / sizeof(StepCase) +
                    sizeof(kLeaveCases) / sizeof(StepCase),
                sizeof(kSeqCases) / sizeof(SeqCase),
                sizeof(kSnapCases) / sizeof(SnapCase));
    return 0;
}
