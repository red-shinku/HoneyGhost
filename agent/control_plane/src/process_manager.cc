#include "agent/control_plane/src/process_manager.hpp"

#include <utility>

// 进程关系管理

ProcessManager::ProcessManager(ProcessStoreOptions options)
    : store_(std::move(options))
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
    return store_.lookup(p);
}

std::optional<hng::Process> ProcessManager::resolve(uint32_t pid) const
{
    return store_.resolve(pid);
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

ProcessSeedReport ProcessManager::seed(const hng::ProcessSeedBatch& batch)
{
    ProcessSeedReport report;
    if (state_.load(std::memory_order_acquire) !=
        hng::ComponentState::CONSTRUCTED) {
        report.rejected_state = 1;
        return report;
    }

    report = store_.seed(batch);
    state_.store(hng::ComponentState::READY, std::memory_order_release);
    return report;
}

void ProcessManager::run()
{
    if (state_.load(std::memory_order_acquire) != hng::ComponentState::READY) {
        return;
    }
    state_.store(hng::ComponentState::RUNNING, std::memory_order_release);

    Task t;
    // 取与处理分离：队列临界区内没有进程树操作，也没有对外通知
    while (task.wait_pop(t)) {
        land(t);
    }

    state_.store(hng::ComponentState::STOPPED, std::memory_order_release);
}

void ProcessManager::stop()
{
    task.stop();
    if (state_.load(std::memory_order_acquire) != hng::ComponentState::RUNNING) {
        state_.store(hng::ComponentState::STOPPED, std::memory_order_release);
    }
}

hng::ComponentState ProcessManager::state() const
{
    return state_.load(std::memory_order_relaxed);
}

void ProcessManager::land(Task& t)
{
    ProcessChange change;
    switch (t.kind) {
        case Task::Kind::ADD:
            change = store_.add(std::move(t.add));
            break;
        case Task::Kind::REMOVE:
            change = store_.remove(t.remove);
            break;
        case Task::Kind::UPDATE_IMAGE:
            store_.update_image(t.image_process, std::move(t.image_exe));
            break;
    }
    if (change.exited.has_value()) {
        notify_process_exited(*change.exited);
    }
    if (change.kind == ProcessChange::Kind::ADDED && role_join_service_) {
        role_join_service_->bind_to_role(change.child, change.parent);
    }
}

bool ProcessManager::is_exited(hng::Process p) const
{
    return store_.is_exited(p);
}

ProcessManagerStats ProcessManager::stats() const { return store_.stats(); }

void ProcessManager::notify_process_exited(hng::Process p)
{
    for (ProcessLifecycleSink* sink : lifecycle_sinks_) {
        sink->on_process_exited(p);
    }
}
