#include "agent/control_plane/src/process_manager.hpp"

#include <chrono>
#include <mutex>
#include <utility>
#include <variant>

// 进程关系管理

ProcessManager::ProcessManager(ProcessManagerOptions options)
    : options_(std::move(options)), tombstones_(options_.tombstones)
{
}

ProcessManager::~ProcessManager() {}

void ProcessManager::add_process_lifecycle_sink(ProcessLifecycleSink* sink)
{
    if (sink == nullptr) {
        return;
    }
    lifecycle_sinks_.push_back(sink);
}

void ProcessManager::set_role_join_service(RoleJoinService* service)
{
    role_join_service_ = service;
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

std::optional<hng::Process> ProcessManager::resolve(uint32_t pid) const
{
    if (pid == 0) {
        return std::nullopt;
    }

    // 存活进程优先：同一 pid 在实进程树中至多一个当前实例
    {
        auto& shard_ref = ptree_shard[shard_index(pid)];
        std::shared_lock lock(shard_ref.smtx);
        auto it = shard_ref.process.find(pid);
        if (it != shard_ref.process.end()) {
            return hng::Process{pid, it->second.pid_start_time};
        }
    }

    // 未命中则查虚拟根；同一 pid 可能有多个已退出实例，取最新的
    auto& vshard_ref = vptree_root[shard_index(pid)];
    std::shared_lock vlock(vshard_ref.smtx);
    std::optional<hng::Process> latest;
    for (const auto& entry : vshard_ref.vprocess) {
        if (entry.first.pid != pid) {
            continue;
        }
        if (!latest || entry.first.pid_start_time > latest->pid_start_time) {
            latest = hng::Process{entry.first.pid, entry.first.pid_start_time};
        }
    }
    return latest;
}

void ProcessManager::register_pid(hng::event_head ehead)
{
    Task t;
    t.kind = Task::Kind::ADD;
    t.add  = hng::ProcessMessage(ehead);
    task.push(std::move(t));
}

void ProcessManager::unregister_pid(hng::Process p)
{
    Task t;
    t.kind   = Task::Kind::REMOVE;
    t.remove = p;
    task.push(std::move(t));
}

void ProcessManager::update_exe_image(hng::Process p, std::string exe)
{
    Task t;
    t.kind          = Task::Kind::UPDATE_IMAGE;
    t.image_process = p;
    t.image_exe     = std::move(exe);
    task.push(std::move(t));
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
        case Task::Kind::UPDATE_IMAGE:
            update_exe_image_(t.image_process, std::move(t.image_exe));
            break;
    }
    expire_tombstones_();
}

void ProcessManager::addPID(hng::ProcessMessage&& data)
{
    uint32_t ppid    = data.ppid;
    uint64_t ppid_st = data.ppid_start_time;
    uint32_t pid     = data.pid;
    uint64_t pid_st  = data.pid_start_time;

    // 退出先于 ADD：该身份已退出，整条事件丢弃
    if (is_exited(hng::Process{pid, pid_st})) {
        stale_add_.fetch_add(1, std::memory_order_relaxed);
        return;
    }

    auto& shard_ref = ptree_shard[shard_index(pid)];

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
        if (it != shard_ref.process.end() &&
            p.pid_start_time == it->second.pid_start_time) {
            retired.emplace(std::move(it->second));
            shard_ref.process.erase(it);
        }
    }  // 释放本分片锁后再退役,避免同线程重入自锁

    if (!retired.has_value()) {
        // 未登记、已退役，或同 pid 的迟到退出：先写墓碑再转发，供下游清理
        // 陈旧归属；下游按身份匹配，不影响同 pid 的新实例
        add_tombstone_(p);
        notify_process_exited(p);
        return;
    }

    retire(std::move(*retired));
}

void ProcessManager::update_exe_image_(hng::Process p, std::string exe)
{
    // 存活进程优先；身份不符表示 pid 已被新实例复用，不得改写
    {
        auto& shard_ref = ptree_shard[shard_index(p.pid)];
        std::unique_lock lock(shard_ref.smtx);

        auto it = shard_ref.process.find(p.pid);
        if (it != shard_ref.process.end() &&
            it->second.pid_start_time == p.pid_start_time) {
            it->second.exe = std::move(exe);
            return;
        }
    }

    // 已转入虚拟根：保留最后镜像
    auto& vshard_ref = vptree_root[shard_index(p.pid)];
    std::unique_lock vlock(vshard_ref.smtx);

    auto it = vshard_ref.vprocess.find(VProcessKey{p.pid, p.pid_start_time});
    if (it != vshard_ref.vprocess.end()) {
        it->second.exe = std::move(exe);
    }
}

void ProcessManager::retire(hng::ProcessMessage&& old)
{
    const hng::Process self{old.pid, old.pid_start_time};
    const hng::Process parent{old.ppid, old.ppid_start_time};
    const bool keep_as_vroot = old.child_count > 0;

    // 实进程已退出：先写墓碑再通知，订阅回调内即可查到该身份已退出
    add_tombstone_(self);
    notify_process_exited(self);

    if (keep_as_vroot) {
        old.kind         = hng::ProcessKind::VIRTUAL;
        auto& vshard_ref = vptree_root[shard_index(old.pid)];
        std::unique_lock vlock(vshard_ref.smtx);
        vshard_ref.vprocess.emplace(VProcessKey{old.pid, old.pid_start_time},
                                    std::move(old));
    }

    // 父进程可能在 ptree(存活)或虚拟根(已退出)中,由函数内部回退处理
    update_child_count_decrease(parent);
}

void ProcessManager::update_child_count_add(hng::Process p)
{
    if (p.pid == 0) {
        // 森林根：没有父进程可计数
        return;
    }

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
    {
        auto& vshard_ref = vptree_root[shard_index(p.pid)];
        std::unique_lock lock(vshard_ref.smtx);

        auto it = vshard_ref.vprocess.find(VProcessKey{p.pid, p.pid_start_time});
        if (it != vshard_ref.vprocess.end()) {
            it->second.child_count += 1;
            return;
        }
    }

    // 父身份缺失：不更新任何计数，留给统计暴露输入契约被破坏
    parent_missing_.fetch_add(1, std::memory_order_relaxed);
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
    }
}

ProcessManagerStats ProcessManager::stats() const
{
    ProcessManagerStats snapshot;
    snapshot.pid_reused     = pid_reused_.load(std::memory_order_relaxed);
    snapshot.stale_add      = stale_add_.load(std::memory_order_relaxed);
    snapshot.parent_missing = parent_missing_.load(std::memory_order_relaxed);
    {
        std::lock_guard lock(tombstone_mutex_);
        snapshot.tombstone_depth = tombstones_.size();
    }
    return snapshot;
}

hng::RelationTimePoint ProcessManager::now() const
{
    if (options_.now) {
        return options_.now();
    }
    return std::chrono::steady_clock::now();
}

void ProcessManager::add_tombstone_(hng::Process p)
{
    std::lock_guard lock(tombstone_mutex_);
    tombstones_.add(p, std::monostate{}, now());
}

void ProcessManager::expire_tombstones_()
{
    std::lock_guard lock(tombstone_mutex_);
    tombstones_.expire(now());
}

bool ProcessManager::is_exited(hng::Process p) const
{
    std::unique_lock lock(tombstone_mutex_);  // find 会惰性清除过期项
    return tombstones_.find(p, now()).has_value();
}

void ProcessManager::notify_process_exited(hng::Process p)
{
    for (ProcessLifecycleSink* sink : lifecycle_sinks_) {
        sink->on_process_exited(p);
    }
}
