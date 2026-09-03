#include "./include/context_manager.hpp"

#include <mutex>

// 上下文关系管理

ContextManager::ContextManager(/* args */) {}

ContextManager::~ContextManager() {}

std::optional<uint32_t> ContextManager::lookup(hng::Process p) const
{
    std::shared_lock lock(contexts.smtx);
    auto it = contexts.map.find(ContextKey{p.pid, p.pid_start_time});
    if (it == contexts.map.end()) {
        return std::nullopt;
    }
    return it->second.contextID;
}

std::optional<uint32_t> ContextManager::lookup_extra(hng::Process p) const
{
    std::shared_lock lock(extras.smtx);
    auto it = extras.map.find(ContextKey{p.pid, p.pid_start_time});
    if (it == extras.map.end()) {
        return std::nullopt;
    }
    return it->second.contextID;
}

// TODO: 接入任务队列后，注册/注销/改属性 走异步
void ContextManager::register_contextID(hng::Process p,
                                        ContextDeriveDecision newcontext,
                                        uint32_t pcontextID)
{
    addContextID(p, newcontext.contextID, newcontext.attr, pcontextID);
}

void ContextManager::unregister_contextID(hng::Process p) { delContextID(p); }

void ContextManager::set_attr(hng::Process p, uint32_t contextID,
                              hng::contextattr attr)
{
    set_attr_(p, contextID, attr);
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
            if (it->second.attr == hng::UNKNOWN) {
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
                if (eit->second.attr == hng::UNKNOWN) {
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
        case hng::ATTACK:
            // TODO: ATTACK 预留钩子
            break;
        case hng::EXTRA_ATTACK:
            // TODO: EXTRA_ATTACK 预留钩子
            break;
        default:
            break;
    }
}
