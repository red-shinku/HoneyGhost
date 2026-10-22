#include "agent/control_plane/src/context_manager.hpp"

#include <algorithm>
#include <mutex>

// 上下文关系管理

ContextManager::ContextManager() {}

ContextManager::~ContextManager() {}

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

using AttrIndex =
    std::unordered_map<hng::contextattr, std::unordered_set<uint32_t>>;

/// 从属性索引中移除一个 contextID；调用方须已持该表的锁
static void erase_from_attr_index(AttrIndex& index, hng::contextattr attr,
                                  uint32_t context_id)
{
    auto it = index.find(attr);
    if (it == index.end()) {
        return;
    }
    it->second.erase(context_id);
    if (it->second.empty()) {
        index.erase(it);
    }
}

/// @brief 按根键组装成员集；取 roots 的共享锁
/// @note 成员集只含仍为实进程的成员；已退出的根不补回
static ContextProcessSet process_set_of(const ContextKey& key,
                                        const ToContextRootTable& roots)
{
    ContextProcessSet result;
    result.root = hng::Process{key.pid, key.start_time};

    {
        std::shared_lock lock(roots.smtx);
        auto it = roots.processes_by_root.find(key);
        if (it != roots.processes_by_root.end()) {
            result.members.assign(it->second.begin(), it->second.end());
        }
    }

    std::sort(result.members.begin(), result.members.end(),
              [](const hng::Process& lhs, const hng::Process& rhs) {
                  if (lhs.pid != rhs.pid) {
                      return lhs.pid < rhs.pid;
                  }
                  return lhs.pid_start_time < rhs.pid_start_time;
              });
    return result;
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

std::vector<uint32_t> ContextManager::contexts_by_attr(
    hng::contextattr attr) const
{
    std::vector<uint32_t> result;
    {
        std::shared_lock lock(contexts.smtx);
        auto it = contexts.by_attr.find(attr);
        if (it != contexts.by_attr.end()) {
            result.assign(it->second.begin(), it->second.end());
        }
    }
    {
        std::shared_lock lock(extras.smtx);
        auto it = extras.by_attr.find(attr);
        if (it != extras.by_attr.end()) {
            result.insert(result.end(), it->second.begin(), it->second.end());
        }
    }
    std::sort(result.begin(), result.end());
    return result;
}

std::optional<ContextProcessSet> ContextManager::members(uint32_t contextID) const
{
    {
        std::shared_lock lock(contexts.smtx);
        auto it = contexts.id_to_key.find(contextID);
        if (it != contexts.id_to_key.end()) {
            return process_set_of(it->second, to_context_root);
        }
    }
    {
        std::shared_lock lock(extras.smtx);
        auto it = extras.id_to_key.find(contextID);
        if (it != extras.id_to_key.end()) {
            return process_set_of(it->second, to_context_root);
        }
    }
    return std::nullopt;
}

void ContextManager::register_context(hng::Process p,
                                      ContextDeriveDecision newcontext,
                                      hng::Process parent)
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

void ContextManager::bind_to_ctxroot(hng::Process p, hng::Process parent)
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

void ContextManager::land(Task& t)
{
    if (auto* add = std::get_if<AddTask>(&t)) {
        addContextID(add->process, add->contextID, add->attr, add->parent);
    }
    else if (auto* extra = std::get_if<ExtraTask>(&t)) {
        addExtraContext(extra->process, extra->contextID, extra->attr);
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
    else if (auto* exited = std::get_if<ExitedTask>(&t)) {
        on_process_exited_(exited->process);
    }
}

void ContextManager::addContextID(hng::Process p, uint32_t contextID,
                                  hng::contextattr attr, hng::Process parent_p)
{
    ContextKey key{p.pid, p.pid_start_time};

    // 父 context 在落地时解析；父未落定（登记竞态）时按森林根处理
    uint32_t pcontextID = 0;
    if (parent_p.pid != 0) {
        if (auto parent_id = lookup(parent_p)) {
            pcontextID = *parent_id;
        }
        else {
            // 父进程已退出：归属索引会移除父键，但若它是 context 根且仍有
            // 实成员，context 记录仍在，按其键直接取 contextID
            std::shared_lock lock(contexts.smtx);
            auto it = contexts.map.find(
                ContextKey{parent_p.pid, parent_p.pid_start_time});
            if (it != contexts.map.end()) {
                pcontextID = it->second.contextID;
            }
        }
    }

    {
        std::unique_lock lock(contexts.smtx);

        // 主 context 键唯一：同键已存在时直接返回，不在此处转为附属 context
        if (contexts.map.find(key) != contexts.map.end()) {
            return;
        }

        contexts.map.emplace(key, ContextMessage{contextID, attr, false});
        contexts.by_attr[attr].insert(contextID);
        contexts.id_to_key[contextID] = key;
        // 根进程也是其 context 的一员：登记 进程→自身根，使 lookup/挂靠可用
        std::unique_lock tlock(to_context_root.smtx);
        to_context_root.map[p] = key;
        to_context_root.processes_by_root[key].insert(p);
    }  // 释放 contexts/to_context_root 锁后再记录 parent 关系

    if (pcontextID != 0) {
        std::unique_lock lock(parent.smtx);
        parent.map.emplace(contextID, pcontextID);
    }
}

void ContextManager::addExtraContext(hng::Process p, uint32_t contextID,
                                     hng::contextattr attr)
{
    ContextKey key{p.pid, p.pid_start_time};
    uint32_t primaryID = 0;

    {
        std::unique_lock lock(contexts.smtx);

        auto it = contexts.map.find(key);
        if (it == contexts.map.end()) {
            return;  // 无主 context：不能登记附属 context
        }
        primaryID = it->second.contextID;

        std::unique_lock xlock(extras.smtx);
        if (extras.map.find(key) != extras.map.end()) {
            return;  // 已有附属 context：保留首个
        }

        extras.map.emplace(key, ContextMessage{contextID, attr, false});
        extras.by_attr[attr].insert(contextID);
        extras.id_to_key[contextID] = key;
        it->second.has_extra        = true;
    }  // 释放 contexts/extras 锁后再记录 parent 关系

    std::unique_lock lock(parent.smtx);
    parent.map.emplace(contextID, primaryID);
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
        const uint32_t primary_id = it->second.contextID;
        primaryID                 = primary_id;
        erase_from_attr_index(contexts.by_attr, it->second.attr, primary_id);
        contexts.id_to_key.erase(primary_id);
        contexts.map.erase(it);
    }  // 释放 contexts 锁后再更新 extras,避免持锁顺序问题

    {
        std::unique_lock lock(extras.smtx);

        auto eit = extras.map.find(key);
        if (eit != extras.map.end()) {
            const uint32_t attached_id = eit->second.contextID;
            attachedID                 = attached_id;
            erase_from_attr_index(extras.by_attr, eit->second.attr, attached_id);
            extras.id_to_key.erase(attached_id);
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
                erase_from_attr_index(contexts.by_attr, it->second.attr,
                                      contextID);
                it->second.attr = attr;
                contexts.by_attr[attr].insert(contextID);
                changed = true;
            }
        }
        else if (it->second.has_extra) {
            // TODO: 这里也许应该删除，附属 context 设计无属性变更
            // 目标不在主 context,查附属 context
            std::unique_lock xlock(extras.smtx);
            auto eit = extras.map.find(ContextKey{p.pid, p.pid_start_time});
            if (eit != extras.map.end() && eit->second.contextID == contextID) {
                if (eit->second.attr == hng::contextattr::UNKNOWN) {
                    erase_from_attr_index(extras.by_attr, eit->second.attr,
                                          contextID);
                    eit->second.attr = attr;
                    extras.by_attr[attr].insert(contextID);
                    changed = true;
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
    auto parent_it = to_context_root.map.find(parent);
    if (parent_it == to_context_root.map.end()) {
        // 父进程尚未落定归属：登记竞态，该次挂靠为空操作，待工作平面补调
        // （见 ContextManagerStats::ctxroot_parent_unsettled）
        ++ctxroot_parent_unsettled_;
        return;
    }
    const ContextKey key = parent_it->second;

    auto it              = to_context_root.map.find(p);
    if (it == to_context_root.map.end()) {
        to_context_root.map.emplace(p, key);
    }
    else if (!(it->second == key)) {
        // 归属不可变；防御性清理旧键的反向索引
        auto old = to_context_root.processes_by_root.find(it->second);
        if (old != to_context_root.processes_by_root.end()) {
            old->second.erase(p);
            if (old->second.empty()) {
                to_context_root.processes_by_root.erase(old);
            }
        }
        it->second = key;
    }
    to_context_root.processes_by_root[key].insert(p);
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

void ContextManager::on_process_exited_(hng::Process p)
{
    std::optional<ContextKey> emptied_root;

    {
        std::unique_lock lock(to_context_root.smtx);
        auto it = to_context_root.map.find(p);
        if (it == to_context_root.map.end()) {
            return;  // 未归属或已清理：重复投递无副作用
        }

        const ContextKey root = it->second;
        to_context_root.map.erase(it);

        auto members = to_context_root.processes_by_root.find(root);
        if (members == to_context_root.processes_by_root.end()) {
            return;  // 索引不一致：不据此删除 context
        }
        members->second.erase(p);
        if (members->second.empty()) {
            to_context_root.processes_by_root.erase(members);
            emptied_root = root;
        }
    }

    if (!emptied_root.has_value()) {
        return;  // 仍有实成员：context 保留，键仍指向原根
    }

    // 显式注销可能已删除该 context；此处只处理仍然存在的情形，避免
    // unknown_unregister 误计
    const hng::Process root{emptied_root->pid, emptied_root->start_time};
    {
        std::shared_lock lock(contexts.smtx);
        if (contexts.map.find(*emptied_root) == contexts.map.end()) {
            return;
        }
    }
    delContextID(root);
}
