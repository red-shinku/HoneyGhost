#include "agent/control_plane/src/context_manager.hpp"

#include <utility>

// 上下文关系管理

ContextManager::ContextManager(ContextStoreOptions options)
    : store_(std::move(options))
{
}

ContextManager::~ContextManager() {}

std::optional<uint32_t> ContextManager::lookup(hng::Process p) const
{
    return store_.lookup(p);
}

std::optional<uint32_t> ContextManager::lookup_extra(hng::Process p) const
{
    return store_.lookup_extra(p);
}

std::vector<uint32_t> ContextManager::contexts_by_attr(
    hng::contextattr attr) const
{
    return store_.contexts_by_attr(attr);
}

std::optional<ContextProcessSet> ContextManager::members(uint32_t contextID) const
{
    return store_.members(contextID);
}

void ContextManager::register_context(hng::Process p,
                                      ContextDeriveDecision newcontext,
                                      ContextParentRef parent)
{
    if (newcontext.kind != ContextDecisionKind::DERIVE) {
        return;  // 接口只接受派生决策
    }
    task.push(Task{AddTask{p, newcontext.contextID, newcontext.attr, parent}});
}

void ContextManager::register_extra_context(hng::Process p, uint32_t contextID,
                                            hng::contextattr attr)
{
    task.push(Task{ExtraTask{p, contextID, attr}});
}

void ContextManager::unregister_context(hng::Process p)
{
    task.push(Task{DelTask{p}});
}

void ContextManager::set_attr(hng::Process p, uint32_t contextID,
                              hng::contextattr attr)
{
    task.push(Task{SetAttrTask{p, contextID, attr}});
}

void ContextManager::bind_to_ctxroot(hng::Process p, ContextParentRef parent)
{
    task.push(Task{BindTask{p, parent}});
}

void ContextManager::on_process_exited(hng::Process p)
{
    task.push(Task{ExitedTask{p}});
}

void ContextManager::run()
{
    Task t;
    // 取与处理分离：队列临界区内没有任何表的读写
    while (task.wait_pop(t)) {
        land(t);
    }
}

void ContextManager::stop() { task.stop(); }

hng::ComponentState ContextManager::state() const
{
    return state_.load(std::memory_order_relaxed);
}

void ContextManager::land(Task& t)
{
    if (auto* add = std::get_if<AddTask>(&t)) {
        store_.add_context(add->process, add->contextID, add->attr, add->parent);
    }
    else if (auto* extra = std::get_if<ExtraTask>(&t)) {
        store_.add_extra_context(extra->process, extra->contextID, extra->attr);
    }
    else if (auto* del = std::get_if<DelTask>(&t)) {
        store_.remove_context(del->process);
    }
    else if (auto* attr = std::get_if<SetAttrTask>(&t)) {
        if (auto changed =
                store_.set_attr(attr->process, attr->contextID, attr->attr)) {
            apply_attr_hook_(*changed);
        }
    }
    else if (auto* bind = std::get_if<BindTask>(&t)) {
        store_.bind_to_root(bind->process, bind->parent);
    }
    else if (auto* exited = std::get_if<ExitedTask>(&t)) {
        store_.on_process_exited(exited->process);
    }
}

void ContextManager::apply_attr_hook_(hng::contextattr attr)
{
    switch (attr) {
        case hng::contextattr::ATTACK:
            // TODO: ATTACK 预留钩子
            break;
        case hng::contextattr::EXTRA_ATTACK:
            // TODO: EXTRA_ATTACK 预留钩子
            break;
        default:
            break;
    }
}

ContextManagerStats ContextManager::stats() const { return store_.stats(); }
