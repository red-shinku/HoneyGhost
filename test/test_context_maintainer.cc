/**
 * @file test_context_maintainer.cc
 * @brief ContextMaintainer 派生/归属单测（Fake ContextService）
 * @details
 * 用 FakeContextService 模拟控制平面 context 登记，验证：
 *  - lookup_contextID：决策窗口沿父链查询（上限 8 层）、DERIVE 本地 ID 立即
 *    生效、KEEP 只认控制平面已落地的挂靠；
 *  - exec 派生入口（解释器 DERIVE、会话内普通命令 KEEP、原地重 exec 不派生、
 *    无诞生的惰性判定）；
 *  - 登记未落地时 DERIVE 的本地归属与 KEEP 的空归属；
 *  - 父未观测的 KEEP 不挂靠并计数；
 *  - on_event 窗口耗尽 → NO_EXEC 派生；
 *  - 乱序重复诞生事件被忽略（不重复开窗）。
 *
 * @author red_shinku
 * @date 2026.9.6
 */

#include "agent/context_maintainer/include/context_maintainer.hpp"

#include <cstdint>
#include <cstdio>
#include <optional>
#include <unordered_map>
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

    /// 暂缓到 flush() 才应用的调用
    struct QueuedOp {
        enum class Kind { REGISTER, BIND };
        Kind kind;
        hng::Process p;
        uint32_t contextID = 0;
        hng::Process parent;
    };

    std::unordered_map<Key, uint32_t, KeyHash> ctx;
    std::size_t register_calls = 0;
    std::vector<hng::Process> registered_parents;
    std::vector<std::pair<hng::Process, hng::Process>> bound;
    std::vector<QueuedOp> queued;

    /// 为 true 时调用立即改变 ctx；为 false 时只记录调用，由 flush() 应用
    bool apply_immediately = true;

    void seed(hng::Process p, uint32_t id) { ctx[Key{p}] = id; }

    /// @brief 应用所有暂缓的登记与挂靠调用
    /// @note 按调用顺序应用，挂靠可解析到此前已应用的父 context
    void flush()
    {
        for (const QueuedOp& op : queued) {
            if (op.kind == QueuedOp::Kind::REGISTER) {
                ctx[Key{op.p}] = op.contextID;
            }
            else {
                apply_bind(op.p, op.parent);
            }
        }
        queued.clear();
    }

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
    std::optional<ContextProcessSet> members(uint32_t) const override
    {
        return std::nullopt;
    }
    ContextManagerStats stats() const override { return {}; }
    void register_context(hng::Process p, ContextDeriveDecision nd,
                          hng::Process parent) override
    {
        ++register_calls;
        registered_parents.push_back(parent);
        if (apply_immediately) {
            ctx[Key{p}] = nd.contextID;
            return;
        }
        queued.push_back(
            QueuedOp{QueuedOp::Kind::REGISTER, p, nd.contextID, parent});
    }
    void register_extra_context(hng::Process, uint32_t, hng::contextattr) override
    {
    }
    void unregister_context(hng::Process p) override { ctx.erase(Key{p}); }
    void bind_to_ctxroot(hng::Process p, hng::Process parent) override
    {
        bound.emplace_back(p, parent);
        if (apply_immediately) {
            apply_bind(p, parent);
            return;
        }
        queued.push_back(QueuedOp{QueuedOp::Kind::BIND, p, 0, parent});
    }
    void set_attr(hng::Process, uint32_t, hng::contextattr) override {}

   private:
    /// 模拟控制平面：进程归属父进程所在的 context
    void apply_bind(hng::Process p, hng::Process parent)
    {
        if (auto id = lookup(parent)) {
            ctx[Key{p}] = *id;
        }
    }
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
          "窗口期沿父链返回父 context");
    auto d = m.should_derive_context(bash, parent, "/bin/bash");
    CHECK(d.kind == ContextDecisionKind::DERIVE, "解释器 exec 应派生");
    CHECK(d.attr == hng::contextattr::UNKNOWN, "新派生默认 UNKNOWN");
    CHECK(m.lookup_contextID(bash) == std::optional<uint32_t>(d.contextID),
          "派生后归属自身新 context");
    CHECK(d.contextID == svc.lookup(bash), "新 context 已登记到服务");
    CHECK(
        svc.registered_parents.size() == 1 && svc.registered_parents[0] == parent,
        "父进程链接应原样交给控制平面解析");
    CHECK(svc.bound.empty(), "DERIVE 不挂靠父 context");

    // 2. 已派生进程原地重 exec（bash 里 exec 别的）→ 不派生
    auto again = m.should_derive_context(bash, parent, "/usr/bin/python3");
    CHECK(again.kind == ContextDecisionKind::NONE,
          "已有自身 context 的原地重 exec 不派生");
    CHECK(m.lookup_contextID(bash) == std::optional<uint32_t>(d.contextID),
          "重 exec 后仍归自身 context");
}

// ---- 登记未落地：DERIVE 本地 ID 立即可查，重 exec 不重复登记 ----
void run_derive_unlanded()
{
    FakeContextService svc;
    svc.apply_immediately = false;
    ContextMaintainer m;
    inject(m, svc);

    hng::Process parent = mk(50, 500);
    svc.seed(parent, 100);

    hng::Process bash = mk(100, 1000);
    m.on_birth(bash, parent);
    auto d = m.should_derive_context(bash, parent, "/bin/bash");
    CHECK(d.kind == ContextDecisionKind::DERIVE, "解释器 exec 应派生");
    CHECK(svc.register_calls == 1, "派生应登记一次");
    CHECK(!svc.lookup(bash).has_value(), "登记未落地时服务中不应有该 context");
    CHECK(m.lookup_contextID(bash) == std::optional<uint32_t>(d.contextID),
          "DERIVE 的归属不等落地，立即返回本地 ID");

    auto again = m.should_derive_context(bash, parent, "/usr/bin/ls");
    CHECK(again.kind == ContextDecisionKind::NONE,
          "已决策进程原地重 exec 应返回 NONE");
    CHECK(svc.register_calls == 1, "原地重 exec 不得再次登记");
    CHECK(m.lookup_contextID(bash) == std::optional<uint32_t>(d.contextID),
          "原地重 exec 后仍归本地 ID");
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
    CHECK(sd.kind == ContextDecisionKind::DERIVE, "父解释器派生成功");

    // 会话内普通命令 ls → KEEP（不派生，留在父）
    hng::Process ls = mk(11, 110);
    m.on_birth(ls, shell);
    CHECK(m.lookup_contextID(ls) == std::optional<uint32_t>(sd.contextID),
          "窗口期沿父链返回父的 context");
    auto ld = m.should_derive_context(ls, shell, "/usr/bin/ls");
    CHECK(ld.kind == ContextDecisionKind::KEEP, "解释器会话内普通命令应 KEEP");
    CHECK(svc.bound.size() == 1 && svc.bound[0].first == ls &&
              svc.bound[0].second == shell,
          "KEEP 进程应挂靠到父进程所属 context 根");
    CHECK(svc.register_calls == 1, "KEEP 进程不注册新 context");
    CHECK(m.lookup_contextID(ls) == std::optional<uint32_t>(sd.contextID),
          "KEEP 进程归属父 context");
}

// ---- KEEP 挂靠未落地：查询为空，落地后才可查 ----
void run_keep_unlanded()
{
    FakeContextService svc;
    svc.apply_immediately = false;
    ContextMaintainer m;
    inject(m, svc);

    hng::Process shell = mk(10, 100);
    auto sd            = m.should_derive_context(shell, mk(1, 1), "/bin/bash");
    CHECK(sd.kind == ContextDecisionKind::DERIVE, "父解释器派生成功");
    CHECK(m.lookup_contextID(shell) == std::optional<uint32_t>(sd.contextID),
          "DERIVE 的父进程在未落地时也归本地 ID");

    hng::Process ls = mk(11, 110);
    m.on_birth(ls, shell);
    CHECK(m.lookup_contextID(ls) == std::optional<uint32_t>(sd.contextID),
          "窗口期沿父链返回父的本地 ID");
    auto ld = m.should_derive_context(ls, shell, "/usr/bin/ls");
    CHECK(ld.kind == ContextDecisionKind::KEEP, "解释器会话内普通命令应 KEEP");
    CHECK(svc.bound.size() == 1, "父已观测时应发起挂靠");
    CHECK(!svc.lookup(ls).has_value(), "挂靠尚未落地");
    CHECK(!m.lookup_contextID(ls).has_value(),
          "KEEP 在挂靠落地前为空");
    CHECK(m.stats().keep_parent_unobserved == 0, "父已观测，不应计入未观测");

    svc.flush();
    CHECK(svc.lookup(shell) == std::optional<uint32_t>(sd.contextID),
          "flush 后父 context 落地");
    CHECK(m.lookup_contextID(ls) == std::optional<uint32_t>(sd.contextID),
          "挂靠落地后 KEEP 进程归属父 context");
}

// ---- 父未观测的 KEEP：不挂靠、计数、保持未归属 ----
void run_keep_parent_unobserved()
{
    FakeContextService svc;
    svc.apply_immediately = false;
    ContextMaintainer m;
    inject(m, svc);

    hng::Process parent = mk(70, 700);
    hng::Process child  = mk(71, 710);
    // 控制平面预置父 context；本模块此后会删除父状态，二者不同步
    svc.seed(parent, 100);

    // 1. 父先 exec 解释器：states_ 记录父的解释器标记
    auto pd = m.should_derive_context(parent, mk(1, 1), "/bin/bash");
    CHECK(pd.kind == ContextDecisionKind::DERIVE, "父解释器 exec 应派生");

    // 2. 开窗捕获父 context 为解释器；3. 父退出，其状态被删除
    m.on_birth(child, parent);
    m.on_exit(parent);

    // 4. 子 exec 普通命令：用开窗捕获的标记判 KEEP，但父已未观测
    auto cd = m.should_derive_context(child, parent, "/usr/bin/ls");
    CHECK(cd.kind == ContextDecisionKind::KEEP,
          "用开窗捕获的解释器标记应判定 KEEP");
    CHECK(svc.bound.empty(), "父未观测时不得挂靠");
    CHECK(m.stats().keep_parent_unobserved == 1, "应计入父未观测");
    CHECK(svc.lookup(parent) == std::optional<uint32_t>(100),
          "控制平面预置的父 context 仍在，但不得擅自使用");
    CHECK(!m.lookup_contextID(child).has_value(),
          "父未观测的 KEEP 进程保持未归属");
    CHECK(svc.register_calls == 1, "只有父进程的注册");
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

    CHECK(m.on_event(worker).kind == ContextDecisionKind::NONE,
          "配额未耗尽无派生");
    CHECK(m.on_event(worker).kind == ContextDecisionKind::NONE,
          "配额未耗尽无派生(2)");
    auto d = m.on_event(worker);
    CHECK(d.kind == ContextDecisionKind::DERIVE, "配额耗尽触发 NO_EXEC 派生");
    CHECK(m.lookup_contextID(worker) == std::optional<uint32_t>(d.contextID),
          "耗尽后归自身新 context");
    CHECK(m.on_event(worker).kind == ContextDecisionKind::NONE, "派生后不再推进");
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
    CHECK(d.kind == ContextDecisionKind::DERIVE,
          "无诞生的惰性 exec 解释器应派生");

    // 乱序：派生后补到的诞生事件应被忽略（不重复开窗）
    m.on_birth(node, mk(1, 1));
    CHECK(m.on_event(node).kind == ContextDecisionKind::NONE,
          "重复诞生被忽略，不产生 NO_EXEC 派生");
    CHECK(m.lookup_contextID(node) == std::optional<uint32_t>(d.contextID),
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
    CHECK(sd.kind == ContextDecisionKind::DERIVE, "服务进程自身派生");

    hng::Process curl = mk(21, 210);
    m.on_birth(curl, server);
    auto cd = m.should_derive_context(curl, server, "/usr/bin/curl");
    CHECK(cd.kind == ContextDecisionKind::DERIVE,
          "非解释器父的普通命令 exec → 默认派生");
}

// ---- 父链查询深度上限 ----
void run_lookup_depth_limit()
{
    FakeContextService svc;
    ContextMaintainer m;
    inject(m, svc);

    // 8 层窗口链恰好可达：chain[0] 经 8 跳查询到已 seed 的根
    hng::Process root = mk(2000, 20000);
    svc.seed(root, 500);
    std::vector<hng::Process> boundary;
    for (uint32_t i = 0; i < 8; ++i) {
        boundary.push_back(mk(2001 + i, 20001 + i));
    }
    for (uint32_t i = 0; i < boundary.size(); ++i) {
        const hng::Process parent =
            (i + 1 < boundary.size()) ? boundary[i + 1] : root;
        m.on_birth(boundary[i], parent);
    }
    CHECK(m.lookup_contextID(boundary[0]) == std::optional<uint32_t>(500),
          "8 层父链应在边界内解析到父 context");
    CHECK(m.stats().lookup_depth_limited == 0, "边界内不应计数");

    // 9 层窗口链超过上限
    std::vector<hng::Process> over;
    for (uint32_t i = 0; i < 10; ++i) {
        over.push_back(mk(2100 + i, 21000 + i));
    }
    for (uint32_t i = 0; i + 1 < over.size(); ++i) {
        m.on_birth(over[i], over[i + 1]);
    }
    CHECK(!m.lookup_contextID(over[0]).has_value(),
          "超过 8 层父链应返回空");
    CHECK(m.stats().lookup_depth_limited == 1, "应计入深度超限");
}

}  // namespace

int main()
{
    run_derive();
    run_derive_unlanded();
    run_keep();
    run_keep_unlanded();
    run_keep_parent_unobserved();
    run_noexec();
    run_lazy();
    run_default_derive();
    run_lookup_depth_limit();
    if (g_fail) {
        std::fprintf(stderr, "TOTAL FAILURES: %d\n", g_fail);
        return 1;
    }
    std::printf("ALL PASS (context_maintainer)\n");
    return 0;
}
