#include "./include/process_manager.hpp"

#include <mutex>

using namespace hng;

// 进程关系管理

ProcessManager::ProcessManager() : task(kTaskQueueCapacity) {}

ProcessManager::~ProcessManager() {}

std::optional<Process> ProcessManager::lookup(uint32_t pid,
                                              uint64_t pid_start_time) const
{
    // 先查存活进程树
    auto& shard_ref = ptree_shard[shard_index(pid)];
    std::shared_lock lock(shard_ref.smtx);
    auto it = shard_ref.process.find(pid);
    if (it != shard_ref.process.end() &&
        it->second.pid_start_time == pid_start_time) {
        return it->second;
    }
    // 未命中则回退虚拟根树(父进程已退出的后台进程)
    auto& vshard_ref = vptree_root[shard_index(pid)];
    std::shared_lock vlock(vshard_ref.smtx);
    auto vit = vshard_ref.vprocess.find(VProcessKey{pid, pid_start_time});
    if (vit == vshard_ref.vprocess.end()) {
        return std::nullopt;
    }
    return vit->second;
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

    {
        std::unique_lock lock(shard_ref.smtx);

        auto it = shard_ref.process.find(data.pid);
        if (it == shard_ref.process.end()) {
            shard_ref.process.insert(std::make_pair(data.pid, data));
        }
        else if (data.pid_start_time != it->second.pid_start_time) {
            shard_ref.process.insert_or_assign(data.pid, std::move(data));
        }
        else {
            // 幂等:同 pid + start_time 已存在,不再重复插入
            return;
        }
    }  // 释放本分片锁后再更新父进程计数,避免同线程重入自锁

    update_child_count_add(ppid, ppid_st);
}

void ProcessManager::deletePID(uint32_t pid, uint64_t pid_start_time)
{
    uint32_t ppid              = 0;
    uint64_t ppid_st           = 0;
    auto& shard_ref            = ptree_shard[shard_index(pid)];

    bool need_parent_decrement = false;
    std::optional<Process> vroot_proc;

    {
        std::unique_lock lock(shard_ref.smtx);

        auto it = shard_ref.process.find(pid);
        if (it == shard_ref.process.end()) {
            return;
        }
        if (pid_start_time != it->second.pid_start_time) {
            return;
        }
        ppid    = it->second.ppid;
        ppid_st = it->second.ppid_start_time;

        // 直接删除节点，或移动至 虚拟根
        if (it->second.child_count == 0) {
            shard_ref.process.erase(it);
        }
        else {
            vroot_proc.emplace(std::move(it->second));
            shard_ref.process.erase(it);
        }
        need_parent_decrement = true;
    }  // 释放本分片锁后再更新父进程计数与虚拟根,避免重入自锁

    if (vroot_proc.has_value()) {
        auto& vshard_ref = vptree_root[shard_index(pid)];
        std::unique_lock vlock(vshard_ref.smtx);
        vshard_ref.vprocess.emplace(VProcessKey{pid, pid_start_time},
                                    std::move(*vroot_proc));
    }

    if (need_parent_decrement) {
        // 父进程可能在 ptree(存活)或虚拟根(已退出)中,由函数内部回退处理
        update_child_count_decrease(ppid, ppid_st);
    }
}

void ProcessManager::update_child_count_add(uint32_t pid, uint64_t pid_start_time)
{
    // 父进程存活:递增其 ptree 计数
    {
        auto& shard_ref = ptree_shard[shard_index(pid)];
        std::unique_lock lock(shard_ref.smtx);

        auto it = shard_ref.process.find(pid);
        if (it != shard_ref.process.end() &&
            it->second.pid_start_time == pid_start_time) {
            it->second.child_count += 1;
            return;
        }
    }
    // 父进程已退出:回退递增虚拟根计数(事件乱序时保持计数一致)
    auto& vshard_ref = vptree_root[shard_index(pid)];
    std::unique_lock lock(vshard_ref.smtx);

    auto it = vshard_ref.vprocess.find(VProcessKey{pid, pid_start_time});
    if (it != vshard_ref.vprocess.end()) {
        it->second.child_count += 1;
    }
}

void ProcessManager::update_child_count_decrease(uint32_t pid,
                                                 uint64_t pid_start_time)
{
    {
        auto& shard_ref = ptree_shard[shard_index(pid)];
        std::unique_lock lock(shard_ref.smtx);

        auto it = shard_ref.process.find(pid);
        if (it != shard_ref.process.end() &&
            it->second.pid_start_time == pid_start_time) {
            if (it->second.child_count > 0) {
                it->second.child_count -= 1;
            }
            return;
        }
    }

    update_vroot_child_count_decrease(pid, pid_start_time);
}

void ProcessManager::update_vroot_child_count_decrease(uint32_t pid,
                                                       uint64_t pid_start_time)
{
    auto& vshard_ref = vptree_root[shard_index(pid)];
    std::unique_lock lock(vshard_ref.smtx);

    auto it = vshard_ref.vprocess.find(VProcessKey{pid, pid_start_time});
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
