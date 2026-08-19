#include "./include/process_manager.hpp"

// 进程关系管理

ProcessManager::ProcessManager(/* args */) {}

ProcessManager::~ProcessManager() {}

std::optional<Process> ProcessManager::lookup(uint32_t pid,
                                              uint64_t start_time) const
{
    auto& shard_ref = shard[shard_index(pid)];

    std::shared_lock lock(shard_ref.smtx);

    auto it = shard_ref.process.find(pid);
    if (it == shard_ref.process.end()) {
        return std::nullopt;
    }
    // TODO: pid 检查不通过处理
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

void ProcessManager::unregister_pid(uint32_t pid, uint64_t start_time)
{
    auto t = [this, pid, start_time]() { deletePID(pid, start_time); };
    task.push(t);
}

void ProcessManager::addPID(Process&& data)
{
    auto& shard_ref = shard[shard_index(data.pid)];

    std::shared_lock lock(shard_ref.smtx);

    auto it = shard_ref.process.find(data.pid);
    if (it == shard_ref.process.end()) {
        shard_ref.process.insert(std::make_pair(data.pid, data));
    }
    else {
        if (data.start_time != it->second.start_time)
            shard_ref.process[data.pid] = data;
    }
}

void ProcessManager::deletePID(uint32_t pid, uint64_t start_time)
{
    auto& shard_ref = shard[shard_index(pid)];

    std::shared_lock lock(shard_ref.smtx);

    auto it = shard_ref.process.find(pid);
    if (it == shard_ref.process.end()) {
        return;
    }
    if (start_time != it->second.start_time) {
        return;
    }
    shard_ref.process.erase(pid);
    // TODO: 如果子进程计数不为零，虚拟化
}

std::optional<Process&> ProcessManager::lookup_ref(uint32_t pid,
                                                   uint64_t start_time)
{
    auto& shard_ref = shard[shard_index(pid)];
    std::shared_lock lock(shard_ref.smtx);
    auto it = shard_ref.process.find(pid);
    if (it == shard_ref.process.end()) {
        return std::nullopt;
    }
    return it->second;
}

void ProcessManager::update_child_count_add(uint32_t pid, uint64_t start_time)
{
    auto& process        = lookup_ref(pid, start_time).value();
    process.child_count += 1;
}

void ProcessManager::update_child_count_decrease(uint32_t pid,
                                                 uint64_t start_time)
{
    auto& process        = lookup_ref(pid, start_time).value();
    process.child_count -= 1;
}