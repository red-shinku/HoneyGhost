#include "./include/process_manager.hpp"

#include <mutex>

// 进程关系管理

ProcessManager::ProcessManager(/* args */) {}

ProcessManager::~ProcessManager() {}

std::optional<Process> ProcessManager::lookup(uint32_t pid,
                                              uint64_t pid_start_time) const
{
    auto& shard_ref = ptree_shard[shard_index(pid)];

    std::shared_lock lock(shard_ref.smtx);
    auto it = shard_ref.process.find(pid);
    if (it == shard_ref.process.end()) {
        return std::nullopt;
    }
    if (pid_start_time != it->second.pid_start_time) {
        return std::nullopt;
        // TODO: pid 检查不通过处理（需要通知工作面该事件处理延迟）
    }
    return it->second;
}

std::optional<Process> ProcessManager::lookup_vroot(uint32_t pid,
                                                    uint64_t pid_start_time) const
{
    auto& vshard_ref = vptree_root[shard_index(pid)];

    std::shared_lock lock(vshard_ref.smtx);

    auto it = vshard_ref.vprocess.find(VProcessKey{pid, pid_start_time});
    if (it == vshard_ref.vprocess.end()) {
        return std::nullopt;
    }
    return it->second;
}

void ProcessManager::register_pid(hng::event_head ehead)
{
    auto t = [this, ehead]() {
        Process p = Process(ehead);
        addPID(std::move(p));
    };
    task.push(t);
}

void ProcessManager::unregister_pid(uint32_t pid, uint64_t pid_start_time)
{
    auto t = [this, pid, pid_start_time]() { deletePID(pid, pid_start_time); };
    task.push(t);
}

void ProcessManager::addPID(Process&& data)
{
    uint32_t ppid    = data.ppid;
    uint64_t ppid_st = data.ppid_start_time;
    auto& shard_ref  = ptree_shard[shard_index(data.pid)];

    std::shared_lock lock(shard_ref.smtx);

    auto it = shard_ref.process.find(data.pid);
    if (it == shard_ref.process.end()) {
        shard_ref.process.insert(std::make_pair(data.pid, data));
    }
    else {
        if (data.pid_start_time != it->second.pid_start_time)
            shard_ref.process[data.pid] = data;
        else
            return;
    }
    update_child_count_add(ppid, ppid_st);
}

void ProcessManager::deletePID(uint32_t pid, uint64_t pid_start_time)
{
    uint32_t ppid    = 0;
    uint64_t ppid_st = 0;
    auto& shard_ref  = ptree_shard[shard_index(pid)];

    std::shared_lock lock(shard_ref.smtx);

    auto it = shard_ref.process.find(pid);
    if (it == shard_ref.process.end()) {
        return;
    }
    if (pid_start_time != it->second.pid_start_time) {
        return;
    }
    ppid    = it->second.ppid;
    ppid_st = it->second.ppid_start_time;

    // 检查是否需要保留为虚拟根进程

    if (it->second.child_count == 0) {
        shard_ref.process.erase(pid);
        update_child_count_decrease(ppid, ppid_st);
    }
    else {
        auto& vshard_ref = vptree_root[shard_index(pid)];
        std::unique_lock vlock(vshard_ref.smtx);

        Process proc = std::move(it->second);
        shard_ref.process.erase(it);
        vshard_ref.vprocess.emplace(VProcessKey{pid, pid_start_time},
                                    std::move(proc));
    }
}

std::optional<Process&> ProcessManager::lookup_ref(uint32_t pid,
                                                   uint64_t pid_start_time)
{
    auto& shard_ref = ptree_shard[shard_index(pid)];
    std::shared_lock lock(shard_ref.smtx);
    auto it = shard_ref.process.find(pid);
    if (it == shard_ref.process.end()) {
        return std::nullopt;
    }
    return it->second;
}

std::optional<Process&> ProcessManager::lookup_vroot_ref(uint32_t pid,
                                                         uint64_t pid_start_time)
{
    auto& vshard_ref = vptree_root[shard_index(pid)];

    std::shared_lock lock(vshard_ref.smtx);

    auto it = vshard_ref.vprocess.find(VProcessKey{pid, pid_start_time});
    if (it == vshard_ref.vprocess.end()) {
        return std::nullopt;
    }
    return it->second;
}

void ProcessManager::update_child_count_add(uint32_t pid, uint64_t pid_start_time)
{
    auto& process        = lookup_ref(pid, pid_start_time).value();
    process.child_count += 1;
}

void ProcessManager::update_child_count_decrease(uint32_t pid,
                                                 uint64_t pid_start_time)
{
    auto& process        = lookup_ref(pid, pid_start_time).value();
    process.child_count -= 1;
}
