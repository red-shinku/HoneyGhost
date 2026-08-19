#include "./include/process_manager.hpp"

// 进程结构

Process::Process(/* args */) {}

Process::~Process() {}

// 进程关系管理

ProcessManager::ProcessManager(/* args */) {}

ProcessManager::~ProcessManager() {}

std::optional<Process> ProcessManager::lookup(uint32_t pid) const
{
    auto& shard_ref = shard[shard_index(pid)];

    std::shared_lock lock(shard_ref.smtx);

    auto it = shard_ref.process.find(pid);

    if (it == shard_ref.process.end()) {
        return std::nullopt;
    }

    return it->second;
}