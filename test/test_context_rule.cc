/**
 * @file test_context_rule.cc
 * @brief context 派生规则表驱动单元测试
 * @details
 * 覆盖 agent/context_maintainer/rule 三块逻辑：
 *  - is_interpreter_exec：解释器家族的全路径 / basename 命中与负例；
 *  - decide_exec：纯判定表（解释器→派生、会话内普通命令→KEEP、其余→默认派生）；
 *  - PendingTable：fork 登记、exec 即时判定、事件配额耗尽派生、退出清理、
 *    重复登记忽略、非待决策 exec 不动作。
 *
 * @author red_shinku
 * @date 2026.9.5
 */

#include "agent/context_maintainer/src/rule/derive_types.hpp"
#include "agent/context_maintainer/src/rule/pending_table.hpp"

#include <cstdio>

namespace {

int g_fail = 0;

#define CHECK(cond, msg)                                                         \
    do {                                                                         \
        if (!(cond)) {                                                           \
            ++g_fail;                                                            \
            std::fprintf(stderr, "[FAIL] %s:%d  %s\n", __FILE__, __LINE__, msg); \
        }                                                                        \
    } while (0)

using hng::detail::DeriveReason;
using hng::detail::DeriveVerdict;

hng::Process mk(uint32_t pid, uint64_t start) { return hng::Process{pid, start}; }

// ---- 解释器家族命中表 ----
struct FamilyCase {
    const char* file;
    bool expect;
};
constexpr FamilyCase kFamilyCases[] = {
    // 全路径命中
    {"/bin/bash", true},
    {"/bin/sh", true},
    {"/bin/dash", true},
    {"/bin/zsh", true},
    {"/usr/bin/fish", true},
    {"/usr/bin/python", true},
    {"/usr/bin/python3", true},
    {"/usr/bin/perl", true},
    {"/usr/bin/ruby", true},
    {"/usr/bin/node", true},
    {"/usr/bin/php", true},
    // basename 命中：别名 / 符号链接 / 非常规安装路径
    {"bash", true},
    {"/opt/custom/bash", true},
    {"/tmp/bash", true},
    // 负例：普通命令 / 复制改名 / 空
    {"/usr/bin/ls", false},
    {"/usr/bin/whoami", false},
    {"/bin/busybox", false},
    {"/tmp/agent", false},
    {"/tmp/x", false},
    {"/usr/bin/bash2", false},
    {"", false},
};

void run_family()
{
    for (const FamilyCase& c : kFamilyCases) {
        if (hng::detail::is_interpreter_exec(c.file) != c.expect) {
            ++g_fail;
            std::fprintf(stderr, "[FAIL] is_interpreter_exec(%s) expect %d\n",
                         c.file, (int)c.expect);
        }
    }
}

// ---- 纯判定表 ----
struct DeriveCase {
    const char* file;     // 归一化 exec 目标
    bool pci;             // 父 context 是否解释器上下文
    bool derive;          // 期望：是否派生
    DeriveReason reason;  // 期望原因（不派生时为 NONE）
};
constexpr DeriveCase kDeriveCases[] = {
    // 解释器 exec → 派生，与父 context 无关
    {"/bin/bash", false, true, DeriveReason::EXEC_INTERPRETER},
    {"/bin/bash", true, true,
     DeriveReason::EXEC_INTERPRETER},  // 会话内再启解释器也派生
    {"/usr/bin/python3", true, true, DeriveReason::EXEC_INTERPRETER},
    // 普通命令 + 解释器父 context → KEEP
    {"/usr/bin/ls", true, false, DeriveReason::NONE},
    {"./deploy.sh", true, false,
     DeriveReason::NONE},  // shebang 脚本在会话内按命令并入
    {"/tmp/agent", true, false, DeriveReason::NONE},  // 会话内运行 → 并入该会话
    // 其余 → 默认派生
    {"/usr/bin/ls", false, true, DeriveReason::EXEC_UNMATCHED_DEFAULT},
    {"/tmp/agent", false, true,
     DeriveReason::EXEC_UNMATCHED_DEFAULT},  // 服务直接 exec 植入
    {"/tmp/x", false, true,
     DeriveReason::EXEC_UNMATCHED_DEFAULT},  // 复制改名解释器
};

void run_decide()
{
    for (const DeriveCase& c : kDeriveCases) {
        DeriveVerdict v =
            hng::detail::decide_exec(mk(1, 1), mk(2, 2), c.pci, c.file);
        if (v.derive != c.derive || (c.derive && v.reason != c.reason)) {
            ++g_fail;
            std::fprintf(stderr,
                         "[FAIL] decide_exec(%s, pci=%d) derive=%d reason=%d "
                         "(expect derive=%d reason=%d)\n",
                         c.file, (int)c.pci, (int)v.derive, (int)v.reason,
                         (int)c.derive, (int)c.reason);
        }
    }
}

// ---- 窗口表 ----
void run_pending()
{
    // 1. exec(解释器) 即时派生，附 parent/child，移除登记
    {
        hng::detail::PendingTable t;
        hng::Process ch = mk(100, 1000), pa = mk(50, 500);
        t.on_fork(ch, pa, true, 8);
        CHECK(t.is_pending(ch), "fork 后应待决策");
        auto v = t.on_exec(ch, "/bin/bash");
        CHECK(v.has_value() && v->derive &&
                  v->reason == DeriveReason::EXEC_INTERPRETER,
              "解释器 exec 应派生 EXEC_INTERPRETER");
        CHECK(!t.is_pending(ch), "exec 决策后应移出登记");
        CHECK(v->child.pid == ch.pid && v->parent.pid == pa.pid,
              "verdict 携带 child/parent");
    }
    // 2. exec(普通命令) + 解释器父 → KEEP：无派生动作，移出登记
    {
        hng::detail::PendingTable t;
        hng::Process ch = mk(101, 1001), pa = mk(50, 500);
        t.on_fork(ch, pa, true, 8);
        auto v = t.on_exec(ch, "/usr/bin/ls");
        CHECK(!v.has_value(), "KEEP 不应产生派生动作");
        CHECK(!t.is_pending(ch), "KEEP 后应移出登记");
    }
    // 3. 事件配额耗尽（窗口内无 exec）→ NO_EXEC_WINDOW 派生
    {
        hng::detail::PendingTable t;
        hng::Process ch = mk(102, 1002), pa = mk(50, 500);
        t.on_fork(ch, pa, false, 3);
        CHECK(!t.on_event(ch).has_value(), "配额未耗尽仍待决策");
        CHECK(!t.on_event(ch).has_value(), "配额未耗尽仍待决策(2)");
        auto v = t.on_event(ch);
        CHECK(v.has_value() && v->derive &&
                  v->reason == DeriveReason::NO_EXEC_WINDOW,
              "配额耗尽应派生 NO_EXEC_WINDOW");
        CHECK(!t.is_pending(ch), "派生后应移出登记");
    }
    // 4. window_size <= 0 按 1 处理：首个事件即派生
    {
        hng::detail::PendingTable t;
        hng::Process ch = mk(103, 1003);
        t.on_fork(ch, mk(50, 500), false, 0);
        auto v = t.on_event(ch);
        CHECK(v.has_value() && v->reason == DeriveReason::NO_EXEC_WINDOW,
              "window=0 首事件派生");
    }
    // 5. 退出清理：决策未完成即退出
    {
        hng::detail::PendingTable t;
        hng::Process ch = mk(104, 1004);
        t.on_fork(ch, mk(50, 500), false, 8);
        t.on_exit(ch);
        CHECK(!t.is_pending(ch), "退出后应清理");
    }
    // 6. 非待决策进程的 exec：不动作（既有进程原地重 exec）
    {
        hng::detail::PendingTable t;
        CHECK(!t.on_exec(mk(999, 9), "/usr/bin/foo").has_value(),
              "非待决策 exec 不动作");
        CHECK(!t.is_pending(mk(999, 9)), "非待决策进程不在表内");
    }
    // 7. 同 child 重复登记忽略（保留首次登记的父与配额）
    {
        hng::detail::PendingTable t;
        hng::Process ch = mk(105, 1005), pa1 = mk(50, 500), pa2 = mk(60, 600);
        t.on_fork(ch, pa1, false, 8);
        t.on_fork(ch, pa2, false, 2);
        auto e = t.lookup(ch);
        CHECK(e.has_value() && e->parent.pid == pa1.pid, "重复登记应保留首条");
        for (int i = 0; i < 7; ++i) {
            CHECK(!t.on_event(ch).has_value(), "配额按首条 8 计");
        }
        CHECK(t.on_event(ch).has_value(), "首条配额耗尽应派生");
    }
}

}  // namespace

int main()
{
    run_family();
    run_decide();
    run_pending();
    if (g_fail) {
        std::fprintf(stderr, "TOTAL FAILURES: %d\n", g_fail);
        return 1;
    }
    std::printf("ALL PASS (family=%zu decide=%zu pending)\n",
                sizeof(kFamilyCases) / sizeof(FamilyCase),
                sizeof(kDeriveCases) / sizeof(DeriveCase));
    return 0;
}
