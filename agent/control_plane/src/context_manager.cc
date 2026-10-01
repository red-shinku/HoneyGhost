#include "agent/control_plane/src/context_manager.hpp"

#include <mutex>

// 上下文关系管理

ContextManager::ContextManager() {}

ContextManager::~ContextManager() {}

// hng::Process → ContextKey（contexts/extras 以 context
// 根进程复合键索引，需要此转换）
static ContextKey process_key(hng::Process p)
{
    return ContextKey{p.pid, p.pid_start_time};
}

// 查询某进程所属 context 的根进程；未落定返回空
static std::optional<ContextKey> root_of(const ToContextRootTable& table,
                                         hng::Process p)
{
    std::shared_lock lock(table.smtx);
    auto it = table.map.find(p);
    if (it == table.map.end()) {
        return std::nullopt;
    }
    return it->second;
}

std::optional<uint32_t> ContextManager::lookup(hng::Process p) const
{
    auto root = root_of(to_context_root, p);
    if (!root) {
        return std::nullopt;  // 进程尚未落定归属（含仍处派生观察窗口的进程）
    }
    std::shared_lock lock(contexts.smtx);
    auto it = contexts.map.find(*root);
    if (it == contexts.map.end()) {
        // 容错：根记录已被清理、其残留成员条目仍在索引中的良性滞后情形
        return std::nullopt;
    }
    return it->second.contextID;
}

std::optional<uint32_t> ContextManager::lookup_extra(hng::Process p) const
{
    auto root = root_of(to_context_root, p);
    if (!root) {
        return std::nullopt;
    }
    std::shared_lock lock(extras.smtx);
    auto it = extras.map.find(*root);
    if (it == extras.map.end()) {
        return std::nullopt;  // 该 context 无附属 context
    }
    return it->second.contextID;
}

void ContextManager::register_contextID(hng::Process p,
                                        ContextDeriveDecision newcontext,
                                        uint32_t pcontextID)
{
    task.push(
        Task{AddTask{p, newcontext.contextID, newcontext.attr, pcontextID}});
}

void ContextManager::unregister_contextID(hng::Process p)
{
    task.push(Task{DelTask{p}});
}

void ContextManager::set_attr(hng::Process p, uint32_t contextID,
                              hng::contextattr attr)
{
    task.push(Task{SetAttrTask{p, contextID, attr}});
}

void ContextManager::bind_to_ctxroot(hng::Process p, hng::Process parent)
{
    task.push(Task{BindTask{p, parent}});
}

void ContextManager::on_process_removed(hng::Process p)
{
    task.push(Task{RemovedTask{p}});
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

void ContextManager::land(Task& t)
{
    if (auto* add = std::get_if<AddTask>(&t)) {
        addContextID(add->process, add->contextID, add->attr,
                     add->parent_contextID);
    }
    else if (auto* del = std::get_if<DelTask>(&t)) {
        delContextID(del->process);
    }
    else if (auto* attr = std::get_if<SetAttrTask>(&t)) {
        set_attr_(attr->process, attr->contextID, attr->attr);
    }
    else if (auto* bind = std::get_if<BindTask>(&t)) {
        bind_to_ctxroot_(bind->process, bind->parent);
    }
    else if (auto* removed = std::get_if<RemovedTask>(&t)) {
        on_process_removed_(removed->process);
    }
}

void ContextManager::addContextID(hng::Process p, uint32_t contextID,
                                  hng::contextattr attr, uint32_t pcontextID)
{
    ContextKey key{p.pid, p.pid_start_time};

    {
        std::unique_lock lock(contexts.smtx);

        auto it = contexts.map.find(key);
        if (it == contexts.map.end()) {
            contexts.map.emplace(key, ContextMessage{contextID, attr, false});
            // 根进程也是其 context 的一员：登记 进程→自身根，使 lookup/挂靠可用
            std::unique_lock tlock(to_context_root.smtx);
            to_context_root.map[p] = key;
        }
        else if (it->second.contextID == contextID) {
            // 幂等:主 context 已注册过同一 contextID,不再重复插入
            return;
        }
        else {
            // (pid, start_time) 已被主 context 占用,该 contextID 归属附属 context
            std::unique_lock xlock(extras.smtx);
            if (extras.map.find(key) != extras.map.end()) {
                // 幂等:附属 context 已注册过,不再重复插入
                return;
            }
            extras.map.emplace(key, ContextMessage{contextID, attr, false});
            it->second.has_extra = true;
        }
    }  // 释放 contexts/extras 锁后再记录 parent 关系

    if (pcontextID != 0) {
        std::unique_lock lock(parent.smtx);
        parent.map.emplace(contextID, pcontextID);
    }
}

void ContextManager::delContextID(hng::Process p)
{
    ContextKey key{p.pid, p.pid_start_time};
    std::optional<uint32_t> primaryID;
    std::optional<uint32_t> attachedID;

    {
        std::unique_lock lock(contexts.smtx);

        auto it = contexts.map.find(key);
        if (it == contexts.map.end()) {
            // 注销先于注册到达：该次注销被丢弃，随后的注册会留下永不删除的
            // context（见 ContextManagerStats::unknown_unregister）
            ++unknown_unregister_;
            return;
        }
        primaryID = it->second.contextID;
        contexts.map.erase(it);
    }  // 释放 contexts 锁后再更新 extras,避免持锁顺序问题

    {
        std::unique_lock lock(extras.smtx);

        auto eit = extras.map.find(key);
        if (eit != extras.map.end()) {
            attachedID = eit->second.contextID;
            extras.map.erase(eit);
        }
    }

    {
        std::unique_lock lock(parent.smtx);
        if (primaryID.has_value()) {
            parent.map.erase(*primaryID);
        }
        if (attachedID.has_value()) {
            parent.map.erase(*attachedID);
        }
    }
}

void ContextManager::set_attr_(hng::Process p, uint32_t contextID,
                               hng::contextattr attr)
{
    bool changed = false;
    {
        std::unique_lock lock(contexts.smtx);

        auto it = contexts.map.find(ContextKey{p.pid, p.pid_start_time});
        if (it == contexts.map.end()) {
            return;
        }

        if (it->second.contextID == contextID) {
            // 目标在主 context
            if (it->second.attr == hng::contextattr::UNKNOWN) {
                it->second.attr = attr;
                changed         = true;
            }
        }
        else if (it->second.has_extra) {
            // TODO: 这里也许应该删除，附属 context 设计无属性变更
            // 目标不在主 context,查附属 context
            std::unique_lock xlock(extras.smtx);
            auto eit = extras.map.find(ContextKey{p.pid, p.pid_start_time});
            if (eit != extras.map.end() && eit->second.contextID == contextID) {
                if (eit->second.attr == hng::contextattr::UNKNOWN) {
                    eit->second.attr = attr;
                    changed          = true;
                }
            }
        }
    }

    if (!changed) {
        return;
    }

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

// 归属落定（KEEP）：p 继承父进程所属 context 的根。父进程未落定（登记竞态）
// 时为空操作 —— 归属保持待定，待父进程落定后再由工作平面补调。
void ContextManager::bind_to_ctxroot_(hng::Process p, hng::Process parent)
{
    std::unique_lock lock(to_context_root.smtx);
    auto it = to_context_root.map.find(parent);
    if (it == to_context_root.map.end()) {
        // 父进程尚未落定归属：登记竞态，该次挂靠为空操作，待工作平面补调
        // （见 ContextManagerStats::ctxroot_parent_unsettled）
        ++ctxroot_parent_unsettled_;
        return;
    }
    // 归属不可变：同一进程重复挂靠时写入相同值，幂等
    to_context_root.map[p] = it->second;
}

ContextManagerStats ContextManager::stats() const
{
    ContextManagerStats snapshot;
    snapshot.ctxroot_parent_unsettled =
        ctxroot_parent_unsettled_.load(std::memory_order_relaxed);
    snapshot.unknown_unregister =
        unknown_unregister_.load(std::memory_order_relaxed);
    return snapshot;
}

void ContextManager::on_process_removed_(hng::Process p)
{
    ContextKey pk = process_key(p);

    bool is_root;
    {
        std::shared_lock lock(contexts.smtx);
        is_root = contexts.map.find(pk) != contexts.map.end();
    }
    {
        std::unique_lock lock(to_context_root.smtx);
        to_context_root.map.erase(p);
    }
    if (is_root) {
        delContextID(p);
    }
}
