/**
 * @file test_context_maintainer.cc
 * @brief ContextMaintainer 派生/归属单测（Fake ContextService）
 * @details
 * 用 FakeContextService 模拟控制平面 context 登记，验证：
 *  - lookup_contextID 纯查询（窗口期归父 / 派生后归自身 / 未登记为空）；
 *  - exec 派生入口（解释器 DERIVE、会话内普通命令 KEEP、原地重 exec 不派生、
 *    无诞生的惰性判定）；
 *  - on_event 窗口耗尽 → NO_EXEC 派生；
 *  - 乱序重复诞生事件被忽略（不重复开窗）。
 *
 * @author red_shinku
 * @date 2026.9.6
 */

#include "agent/context_maintainer/include/context_maintainer.hpp"

#include <cstdio>
#include <optional>
#include <unordered_map>

namespace {

int g_fail = 0;

#define CHECK(cond, msg)                                                         \
    do {                                                                         \
        if (!(cond)) {                                                           \
            ++g_fail;                                                            \
            std::fprintf(stderr, "[FAIL] %s:%d  %s\n", __FILE__, __LINE__, msg); \
        }                                                                        \
    } while (0)

hng::Process mk(uint32_t pid, uint64_t start) { return hng::Process{pid, start}; }

/// 控制平面 context 服务的极简替身：仅登记 context 根进程 → contextID
/// @note 一个替身同时充当查询 / 注册 / 更新三个接口；清理接口不属于本模块的注入面
class FakeContextService final : public ContextLookupService,
                                 public ContextJoinService,
                                 public ContextUpdateService {
   public:
    struct Key {
        hng::Process p;
        bool operator==(const Key& o) const { return p == o.p; }
    };
    struct KeyHash {
        std::size_t operator()(const Key& k) const
        {
            return std::hash<hng::Process>{}(k.p);
        }
    };

    std::unordered_map<Key, uint32_t, KeyHash> ctx;
    std::size_t register_calls = 0;

    void seed(hng::Process p, uint32_t id) { ctx[Key{p}] = id; }

    std::optional<uint32_t> lookup(hng::Process p) const override
    {
        auto it = ctx.find(Key{p});
        if (it == ctx.end()) {
            return std::nullopt;
        }
        return it->second;
    }
    std::optional<uint32_t> lookup_extra(hng::Process p) const override
    {
        (void)p;
        return std::nullopt;
    }
    std::vector<uint32_t> contexts_by_attr(hng::contextattr) const override
    {
        return {};
    }
    void register_contextID(hng::Process p, ContextDeriveDecision nd,
                            uint32_t) override
    {
        ++register_calls;
        ctx[Key{p}] = nd.contextID;
    }
    void unregister_contextID(hng::Process p) override { ctx.erase(Key{p}); }
    void bind_to_ctxroot(hng::Process, hng::Process) override {}
    void set_attr(hng::Process, uint32_t, hng::contextattr) override {}
};

/// 经三个接口注入同一个替身
void inject(ContextMaintainer& m, FakeContextService& svc)
{
    m.set_context_service(&svc, &svc, &svc);
}

// ---- 派生流程 ----
void run_derive()
{
    FakeContextService svc;
    ContextMaintainer m;
    inject(m, svc);

    // 父进程已有 context（如 nginx），非解释器
    hng::Process parent = mk(50, 500);
    svc.seed(parent, 100);

    // 1. 诞生 + exec 解释器 → DERIVE，注册新 context，回归自身
    hng::Process bash = mk(100, 1000);
    m.on_birth(bash, parent);
    CHECK(m.lookup_contextID(bash) == std::optional<uint32_t>(100),
          "窗口期归属父 context");
    auto d = m.should_derive_context(bash, parent, "/bin/bash");
    CHECK(d.has_value() && d->should_derive, "解释器 exec 应派生");
    CHECK(d->attr == hng::contextattr::UNKNOWN, "新派生默认 UNKNOWN");
    CHECK(m.lookup_contextID(bash) == std::optional<uint32_t>(d->contextID),
          "派生后归属自身新 context");
    CHECK(d->contextID == svc.lookup(bash), "新 context 已登记到服务");

    // 2. 已派生进程原地重 exec（bash 里 exec 别的）→ 不派生
    auto again = m.should_derive_context(bash, parent, "/usr/bin/python3");
    CHECK(!again.has_value(), "已有自身 context 的原地重 exec 不派生");
    CHECK(m.lookup_contextID(bash) == std::optional<uint32_t>(d->contextID),
          "重 exec 后仍归自身 context");
}

// ---- 会话内命令 KEEP ----
void run_keep()
{
    FakeContextService svc;
    ContextMaintainer m;
    inject(m, svc);

    // 先让父进程成为"解释器"：惰性 exec bash 派生并记录解释器类别
    hng::Process shell = mk(10, 100);
    auto sd            = m.should_derive_context(shell, mk(1, 1), "/bin/bash");
    CHECK(sd.has_value(), "父解释器派生成功");

    // 会话内普通命令 ls → KEEP（不派生，留在父）
    hng::Process ls = mk(11, 110);
    m.on_birth(ls, shell);
    auto ld = m.should_derive_context(ls, shell, "/usr/bin/ls");
    CHECK(!ld.has_value(), "解释器会话内普通命令应 KEEP");
    CHECK(!svc.lookup(ls).has_value(), "KEEP 进程不登记新 context");
    CHECK(m.lookup_contextID(ls) == std::nullopt,
          "KEEP 进程无自身 context（上行归属由调用方处理）");
}

// ---- 窗口耗尽 NO_EXEC ----
void run_noexec()
{
    FakeContextService svc;
    ContextMaintainer m(3);
    inject(m, svc);

    hng::Process parent = mk(50, 500);
    svc.seed(parent, 100);
    hng::Process worker = mk(200, 2000);
    m.on_birth(worker, parent);

    CHECK(!m.on_event(worker).has_value(), "配额未耗尽无派生");
    CHECK(!m.on_event(worker).has_value(), "配额未耗尽无派生(2)");
    auto d = m.on_event(worker);
    CHECK(d.has_value() && d->should_derive, "配额耗尽触发 NO_EXEC 派生");
    CHECK(m.lookup_contextID(worker) == std::optional<uint32_t>(d->contextID),
          "耗尽后归自身新 context");
    CHECK(!m.on_event(worker).has_value(), "派生后不再推进");
}

// ---- 惰性判定（exec 先于诞生 / 诞生丢失）----
void run_lazy()
{
    FakeContextService svc;
    ContextMaintainer m;
    inject(m, svc);

    // 无诞生事件直接 exec 解释器 → 惰性 DERIVE
    hng::Process node = mk(300, 3000);
    auto d            = m.should_derive_context(node, mk(1, 1), "/usr/bin/node");
    CHECK(d.has_value(), "无诞生的惰性 exec 解释器应派生");

    // 乱序：派生后补到的诞生事件应被忽略（不重复开窗）
    m.on_birth(node, mk(1, 1));
    CHECK(!m.on_event(node).has_value(), "重复诞生被忽略，不产生 NO_EXEC 派生");
    CHECK(m.lookup_contextID(node) == std::optional<uint32_t>(d->contextID),
          "乱序诞生后仍归自身 context");
}

// ---- 默认/非解释器父进程普通命令 → 默认派生 ----
void run_default_derive()
{
    FakeContextService svc;
    ContextMaintainer m;
    inject(m, svc);

    // 父进程非解释器（exec 普通二进制后派生为自身 context），fork
    // 子进程跑普通命令
    hng::Process server = mk(20, 200);
    auto sd = m.should_derive_context(server, mk(1, 1), "/usr/bin/nginx");
    CHECK(sd.has_value(), "服务进程自身派生");

    hng::Process curl = mk(21, 210);
    m.on_birth(curl, server);
    auto cd = m.should_derive_context(curl, server, "/usr/bin/curl");
    CHECK(cd.has_value(), "非解释器父的普通命令 exec → 默认派生");
}

}  // namespace

int main()
{
    run_derive();
    run_keep();
    run_noexec();
    run_lazy();
    run_default_derive();
    if (g_fail) {
        std::fprintf(stderr, "TOTAL FAILURES: %d\n", g_fail);
        return 1;
    }
    std::printf("ALL PASS (context_maintainer)\n");
    return 0;
}
