#include "agent/control_plane/src/process_manager.hpp"

#include <mutex>

// 进程关系管理

ProcessManager::ProcessManager() {}

ProcessManager::~ProcessManager() {}

void ProcessManager::set_context_service(ContextClearService* c_svc)
{
    ctx_clear_service_ = c_svc;
}

void ProcessManager::set_role_join_service(RoleJoinService* service)
{
    role_join_service_ = service;
}

void ProcessManager::set_role_clear_service(RoleClearService* service)
{
    role_clear_service_ = service;
}

std::optional<hng::ProcessMessage> ProcessManager::lookup(hng::Process p) const
{
    // 先查存活进程树
    auto& shard_ref = ptree_shard[shard_index(p.pid)];
    std::shared_lock lock(shard_ref.smtx);
    auto it = shard_ref.process.find(p.pid);
    if (it != shard_ref.process.end() &&
        it->second.pid_start_time == p.pid_start_time) {
        return it->second;
    }
    // 未命中则回退虚拟根树(父进程已退出的后台进程)
    auto& vshard_ref = vptree_root[shard_index(p.pid)];
    std::shared_lock vlock(vshard_ref.smtx);
    auto vit = vshard_ref.vprocess.find(VProcessKey{p.pid, p.pid_start_time});
    if (vit == vshard_ref.vprocess.end()) {
        return std::nullopt;
    }
    return vit->second;
}

void ProcessManager::register_pid(hng::event_head ehead)
{
    task.push(Task{Task::Kind::ADD, hng::ProcessMessage(ehead), {}});
}

void ProcessManager::unregister_pid(hng::Process p)
{
    task.push(Task{Task::Kind::REMOVE, {}, p});
}

void ProcessManager::run()
{
    Task t;
    // 取与处理分离：队列临界区内没有进程树操作，也没有对外通知
    while (task.wait_pop(t)) {
        land(t);
    }
}

void ProcessManager::stop() { task.stop(); }

void ProcessManager::land(Task& t)
{
    switch (t.kind) {
        case Task::Kind::ADD:
            addPID(std::move(t.add));
            break;
        case Task::Kind::REMOVE:
            deletePID(t.remove);
            break;
    }
}

void ProcessManager::addPID(hng::ProcessMessage&& data)
{
    uint32_t ppid    = data.ppid;
    uint64_t ppid_st = data.ppid_start_time;
    uint32_t pid     = data.pid;
    uint64_t pid_st  = data.pid_start_time;
    auto& shard_ref  = ptree_shard[shard_index(pid)];

    std::optional<hng::ProcessMessage> retired;
    {
        std::unique_lock lock(shard_ref.smtx);

        auto it = shard_ref.process.find(pid);
        if (it == shard_ref.process.end()) {
            shard_ref.process.insert(std::make_pair(pid, data));
        }
        else if (pid_st != it->second.pid_start_time) {
            // pid 复用：旧实例已死，只是它的退出事件没到（丢了或晚于本条）。
            // 按与 deletePID 相同的路径退役它，再让新实例顶上
            retired.emplace(std::move(it->second));
            it->second = std::move(data);
            pid_reused_.fetch_add(1, std::memory_order_relaxed);
        }
        else {
            // 幂等:同 pid + start_time 已存在,不再重复插入
            return;
        }
    }  // 释放本分片锁后再退役旧实例、更新父进程计数,避免同线程重入自锁

    if (retired.has_value()) {
        retire(std::move(*retired));
    }

    update_child_count_add(hng::Process{ppid, ppid_st});

    // 子进程继承父进程的角色归属；父进程未归属时由对端丢弃。
    // 幂等分支不走到这里：那是同一条 fork 事件的重复投递。
    if (role_join_service_) {
        role_join_service_->bind_to_role(hng::Process{pid, pid_st},
                                         hng::Process{ppid, ppid_st});
    }
}

void ProcessManager::deletePID(hng::Process p)
{
    auto& shard_ref = ptree_shard[shard_index(p.pid)];
    std::optional<hng::ProcessMessage> retired;

    {
        std::unique_lock lock(shard_ref.smtx);

        auto it = shard_ref.process.find(p.pid);
        if (it == shard_ref.process.end()) {
            return;
        }
        if (p.pid_start_time != it->second.pid_start_time) {
            // 该 pid 已被复用：本条是旧实例迟到的退出事件，实例早已退役，
            // 忽略即可（重复投递）
            return;
        }
        retired.emplace(std::move(it->second));
        shard_ref.process.erase(it);
    }  // 释放本分片锁后再退役,避免同线程重入自锁

    retire(std::move(*retired));
}

void ProcessManager::retire(hng::ProcessMessage&& old)
{
    const hng::Process self{old.pid, old.pid_start_time};
    const hng::Process parent{old.ppid, old.ppid_start_time};
    const bool keep_as_vroot = old.child_count > 0;

    if (keep_as_vroot) {
        auto& vshard_ref = vptree_root[shard_index(old.pid)];
        std::unique_lock vlock(vshard_ref.smtx);
        vshard_ref.vprocess.emplace(VProcessKey{old.pid, old.pid_start_time},
                                    std::move(old));
    }
    else {
        // 无存活子进程：不保留虚拟根，进程被完全删除。
        // 先报自己再递减父计数：后者可能引发父的虚拟根驱逐与通知，
        // 由此通知沿子到父的次序发出
        notify_process_fully_removed(self);
    }

    // 父进程可能在 ptree(存活)或虚拟根(已退出)中,由函数内部回退处理
    update_child_count_decrease(parent);
}

void ProcessManager::update_child_count_add(hng::Process p)
{
    // 父进程存活:递增其 ptree 计数
    {
        auto& shard_ref = ptree_shard[shard_index(p.pid)];
        std::unique_lock lock(shard_ref.smtx);

        auto it = shard_ref.process.find(p.pid);
        if (it != shard_ref.process.end() &&
            it->second.pid_start_time == p.pid_start_time) {
            it->second.child_count += 1;
            return;
        }
    }
    // 父进程已退出:回退递增虚拟根计数(事件乱序时保持计数一致)
    auto& vshard_ref = vptree_root[shard_index(p.pid)];
    std::unique_lock lock(vshard_ref.smtx);

    auto it = vshard_ref.vprocess.find(VProcessKey{p.pid, p.pid_start_time});
    if (it != vshard_ref.vprocess.end()) {
        it->second.child_count += 1;
    }
}

void ProcessManager::update_child_count_decrease(hng::Process p)
{
    {
        auto& shard_ref = ptree_shard[shard_index(p.pid)];
        std::unique_lock lock(shard_ref.smtx);

        auto it = shard_ref.process.find(p.pid);
        if (it != shard_ref.process.end() &&
            it->second.pid_start_time == p.pid_start_time) {
            if (it->second.child_count > 0) {
                it->second.child_count -= 1;
            }
            return;
        }
    }

    update_vroot_child_count_decrease(hng::Process{p.pid, p.pid_start_time});
}

void ProcessManager::update_vroot_child_count_decrease(hng::Process p)
{
    auto& vshard_ref = vptree_root[shard_index(p.pid)];
    bool evicted     = false;  // 虚拟根被逐出 → 进程被完全删除

    {
        std::unique_lock lock(vshard_ref.smtx);

        auto it = vshard_ref.vprocess.find(VProcessKey{p.pid, p.pid_start_time});
        if (it == vshard_ref.vprocess.end()) {
            return;
        }
        if (it->second.child_count > 0) {
            it->second.child_count -= 1;
        }
        if (it->second.child_count == 0) {
            // 子进程计数归零,不再被追溯,清理虚拟根节点
            vshard_ref.vprocess.erase(it);
            evicted = true;
        }
    }  // 释放分片锁后再上报,避免跨组件持锁

    if (evicted) {
        notify_process_fully_removed(p);
    }
}

ProcessManagerStats ProcessManager::stats() const
{
    ProcessManagerStats snapshot;
    snapshot.pid_reused = pid_reused_.load(std::memory_order_relaxed);
    return snapshot;
}

void ProcessManager::notify_process_fully_removed(hng::Process p)
{
    if (ctx_clear_service_) {
        ctx_clear_service_->on_process_removed(p);
    }
    if (role_clear_service_) {
        role_clear_service_->on_process_removed(p);
    }
}
