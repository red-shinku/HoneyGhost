/**
 * @file context_maintainer.cc
 * @brief ContextMaintainer 实现：派生决策、窗口推进与归属查询
 * @details
 * 输入事件 kind（exec / 诞生 / 退出 / 普通）由使用方识别并调用对应入口；本模块
 * 维护窗口与进程决策状态。每个进程只在首次 exec（或窗口耗尽）时决策一次：
 * DERIVE 分配 contextID、判定 attr（decide_attr 当前占位恒 UNKNOWN）并经
 * ContextService 注册；KEEP 不分配 contextID，仅当父已被观测时经 ContextService
 * 把进程挂靠到父进程所属 context 的根，否则保持未归属并计数。
 *
 * "父是否解释器"采用近似：以父进程自身最近一次 exec 目标是否解释器家族判定
 * （states_ 中的记录），未知按非解释器 → 落入默认派生（安全侧）。
 * @author red_shinku
 * @date 2026.9.6
 */

#include "agent/context_maintainer/include/context_maintainer.hpp"

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <memory>

#include "agent/context_maintainer/src/rule/derive_types.hpp"
#include "agent/context_maintainer/src/rule/pending_table.hpp"

ContextMaintainer::ContextMaintainer(uint32_t window_size)
    : pending_(std::make_unique<hng::detail::PendingTable>()),
      window_size_(window_size)
{
}

ContextMaintainer::~ContextMaintainer() {}

void ContextMaintainer::set_context_service(ContextLookupService* ctx_lookup_sv,
                                            ContextJoinService* ctx_join_sv,
                                            ContextUpdateService* ctx_update_sv)
{
    if (ctx_lookup_sv && ctx_join_sv && ctx_update_sv) {
        ctx_lookup_service_ = ctx_lookup_sv;
        ctx_join_service_   = ctx_join_sv;
        ctx_update_service_ = ctx_update_sv;
        return;
    }
    std::cerr << "pass in nullptr at ContextMaintainer::set_context_service\n";
    exit(2);
}

ContextDeriveDecision ContextMaintainer::should_derive_context(
    hng::Process p, hng::Process parent, const std::string& filename)
{
    // 记录该进程最近一次 exec 目标是否解释器（含原地重 exec 的图像变化）
    ProcessContextState& state = states_[ProcessKey{p}];
    state.exec_is_interpreter  = hng::detail::is_interpreter_exec(filename);

    // 每个进程只决策一次：已决策的进程为原地重 exec，不再查询控制平面
    if (state.decided) {
        return {};
    }

    std::optional<hng::detail::DeriveVerdict> verdict;
    if (pending_->is_pending(p)) {
        // 窗口期内的 exec：立即判定并移出登记（KEEP 亦移出）
        verdict = pending_->on_exec(p, filename);
    }
    else {
        // 惰性判定：exec 先于诞生事件到达 / 诞生事件丢失 / 冷启动
        verdict = hng::detail::decide_exec(
            p, parent, parent_is_interpreter(parent), filename);
    }

    if (!verdict) {
        return {};  // 防御：判定入口未返回结果
    }
    if (!verdict->derive) {
        // 留在父 context：记录 KEEP，父已被观测时才挂靠，否则保持未归属
        ProcessContextState& kept = states_[ProcessKey{verdict->child}];
        kept.decided              = true;
        kept.kind                 = ContextDecisionKind::KEEP;

        if (observed(verdict->parent, verdict->child)) {
            if (ctx_join_service_) {
                ctx_join_service_->bind_to_ctxroot(verdict->child,
                                                   verdict->parent);
            }
        }
        else {
            keep_parent_unobserved_.fetch_add(1, std::memory_order_relaxed);
        }

        ContextDeriveDecision d;
        d.kind = ContextDecisionKind::KEEP;
        return d;
    }
    return finalize_derive(*verdict);
}

void ContextMaintainer::on_birth(hng::Process child, hng::Process parent)
{
    // 已在窗口内或已产生决策（乱序 exec 先到 / 重复事件）→ 无需再开窗口
    if (pending_->is_pending(child) ||
        states_.count(ProcessKey{child}) != 0) {
        return;
    }
    pending_->on_fork(child, parent, parent_is_interpreter(parent), window_size_);
}

ContextDeriveDecision ContextMaintainer::on_event(hng::Process p)
{
    auto verdict = pending_->on_event(p);
    if (!verdict) {
        return {};  // 非待决策 / 仍待决策
    }
    return finalize_derive(*verdict);  // 窗口内无 exec，配额耗尽 → NO_EXEC 派生
}

void ContextMaintainer::on_exit(hng::Process p)
{
    pending_->on_exit(p);
    states_.erase(ProcessKey{p});
}

std::optional<uint32_t> ContextMaintainer::lookup_contextID(hng::Process p) const
{
    return lookup_contextID_at(p, 0);
}

std::optional<uint32_t> ContextMaintainer::lookup_contextID_at(
    hng::Process p, uint32_t depth) const
{
    if (depth > kLookupDepthLimit) {
        lookup_depth_limited_.fetch_add(1, std::memory_order_relaxed);
        return std::nullopt;
    }

    // 决策窗口内：沿父链查询，用于事件的暂时归因
    if (auto entry = pending_->lookup(p)) {
        return lookup_contextID_at(entry->parent, depth + 1);
    }

    auto state = states_.find(ProcessKey{p});
    if (state != states_.end() &&
        state->second.kind == ContextDecisionKind::DERIVE) {
        return state->second.contextID;  // 不等控制平面落地
    }
    return lookup_registered(p);
}

std::optional<uint32_t> ContextMaintainer::lookup_registered(
    hng::Process p) const
{
    if (!ctx_lookup_service_) {
        return std::nullopt;
    }
    return ctx_lookup_service_->lookup(p);
}

ContextMaintainerStats ContextMaintainer::stats() const
{
    ContextMaintainerStats snapshot;
    snapshot.keep_parent_unobserved =
        keep_parent_unobserved_.load(std::memory_order_relaxed);
    snapshot.lookup_depth_limited =
        lookup_depth_limited_.load(std::memory_order_relaxed);
    return snapshot;
}

bool ContextMaintainer::parent_is_interpreter(hng::Process parent) const
{
    auto it = states_.find(ProcessKey{parent});
    return it != states_.end() && it->second.exec_is_interpreter;
}

bool ContextMaintainer::observed(hng::Process p, hng::Process self) const
{
    if (p == self) {
        return false;  // 自指父不视为已观测
    }
    return pending_->is_pending(p) || states_.count(ProcessKey{p}) != 0;
}

hng::contextattr ContextMaintainer::decide_attr(hng::Process child,
                                                hng::Process parent)
{
    // 占位：派生 context 的属性判定规则待实现（将依据父 context 等信息），
    // 新派生的 context 一律先按 UNKNOWN 登记观察
    (void)child;
    (void)parent;
    return hng::contextattr::UNKNOWN;
}

ContextDeriveDecision ContextMaintainer::finalize_derive(
    const hng::detail::DeriveVerdict& v)
{
    ContextDeriveDecision d;
    d.kind      = ContextDecisionKind::DERIVE;
    d.contextID = allocate_context_id();
    d.attr      = decide_attr(v.child, v.parent);

    ProcessContextState& state = states_[ProcessKey{v.child}];
    state.decided              = true;
    state.kind                 = ContextDecisionKind::DERIVE;
    state.contextID            = d.contextID;

    if (ctx_join_service_) {
        // 父进程链接交给控制平面在落地时解析
        ctx_join_service_->register_context(v.child, d, v.parent);
    }
    return d;
}

uint32_t ContextMaintainer::allocate_context_id()
{
    uint32_t id = next_context_id_++;
    if (next_context_id_ == 0) {
        next_context_id_ = 1;  // 回绕规避哨兵 0
    }
    return id;
}
