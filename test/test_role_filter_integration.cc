#include "agent/control_plane/src/role_manager.hpp"
#include "agent/role_filter/include/role_filter.hpp"

#include <condition_variable>
#include <cstdio>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <unordered_set>

namespace {
using namespace hng;

struct Map final : ProcessFilterMap {
    std::unordered_set<Process> values;
    std::error_code allow(Process p) noexcept override { values.insert(p); return {}; }
    std::error_code erase(Process p) noexcept override { values.erase(p); return {}; }
};

class Barrier final : public RoleLifecycleSink {
   public:
    void on_role_joined(const Role&) override { notify(); }
    void on_role_left(const Role&) override { notify(); }
    void on_role_main_process_changed(const Role&) override { notify(); }
    void wait(int count)
    {
        std::unique_lock lock(mutex_);
        if (!cv_.wait_for(lock, std::chrono::seconds(2), [&] { return count_ >= count; }))
            throw std::runtime_error("RoleManager 通知超时");
    }
   private:
    void notify() { { std::lock_guard lock(mutex_); ++count_; } cv_.notify_one(); }
    std::mutex mutex_;
    std::condition_variable cv_;
    int count_ = 0;
};

void require(bool condition) { if (!condition) throw std::runtime_error("角色管理器对接断言失败"); }
}  // namespace

int main()
{
    try {
        using namespace hng;
        const Process first{501, 700}, second{502, 701}, child{503, 702};
        std::mutex probe_mutex;
        std::vector<Process> observed{first};
        RoleManager manager({[&](const std::string&) {
            std::lock_guard lock(probe_mutex); return observed;
        }});
        auto map = std::make_unique<Map>(); auto* view = map.get();
        std::istringstream input("[whitelist]\nexact: nginx.service\nexact: registry/app:v1\n");
        RoleFilterOptions options;
        options.liveness = [](Process) { return ProcessLiveness::ALIVE; };
        RoleFilter filter(manager, RoleFilterPolicy(parse_role_filter_config(input)), std::move(map), options);
        Barrier barrier;
        manager.add_lifecycle_sink(&filter);
        manager.add_lifecycle_sink(&barrier);
        std::thread worker([&] { manager.run(); });
        struct Runner { RoleManager& m; std::thread& t; ~Runner() { m.stop(); t.join(); } } runner{manager, worker};

        role::RoleEvent event{};
        event.action = role::RoleAction::JOIN;
        event.payload.identity.source = role::RoleSource::SYSTEMD;
        event.payload.identity.instance_key = "nginx.service";
        event.payload.identity.type_key = "nginx";
        event.payload.main_process = first;
        event.payload.cgroup_path = "/test";
        manager.on_role_event(event); barrier.wait(1); filter.drain();
        require(manager.lookup(first).has_value()); require(view->values.count(first));

        { std::lock_guard lock(probe_mutex); observed.push_back(child); }
        filter.drain(); require(view->values.count(child)); // 无新生命周期通知仍能补齐 fork

        // image 标签取完整镜像引用，不拿 type_key/nginx 聚合键做名单匹配。
        event.action = role::RoleAction::MAIN_PROCESS_CHANGE;
        event.payload.identity.source = role::RoleSource::CONTAINERD;
        event.payload.identity.attributes["image"] = "registry/app:v1";
        event.payload.main_process = second;
        { std::lock_guard lock(probe_mutex); observed = {second}; }
        manager.on_role_event(event); barrier.wait(2); filter.drain();
        require(view->values.count(second));
        auto id = manager.lookup(second); require(id.has_value());
        require(manager.role(*id)->roleLabel == "registry/app:v1");

        filter.replace_policy(RoleFilterPolicy()); filter.drain();
        require(view->values.empty()); require(manager.lookup(second).has_value());
        event.action = role::RoleAction::LEAVE;
        manager.on_role_event(event); barrier.wait(3); filter.drain();
        require(view->values.empty()); require(filter.stats().roles == 0);
        require(!manager.lookup(second));
        std::puts("PASS: RoleManager -> RoleFilter -> process map integration");
        return 0;
    } catch (const std::exception& e) { std::fprintf(stderr, "FAIL: %s\n", e.what()); return 1; }
}
