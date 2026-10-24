/**
 * @file
 * @brief 最新版真实 RoleManager 与过滤维护器的角色生命周期集成测试。
 * @note 成员枚举与 map 使用可控替身，不依赖特权或真实 cgroup。
 * @author inless427
 */
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
int checks = 0;
void require(bool value, const char* message = "RoleManager 过滤集成检查失败")
{
    ++checks;
    if (!value) throw std::runtime_error(message);
}
struct Map final : ProcessFilterMap {
    std::unordered_set<Process> values;
    std::error_code allow(Process process) noexcept override
    {
        values.insert(process);
        return {};
    }
    std::error_code erase(Process process) noexcept override
    {
        values.erase(process);
        return {};
    }
};
class Barrier final : public RoleLifecycleSink {
   public:
    void on_role_joined(const Role&) override { notify(); }
    void on_role_left(const Role&) override { notify(); }
    void on_role_main_process_changed(const Role&) override { notify(); }
    void on_role_members_changed(const Role&,
                                 const std::vector<Process>&) override
    {
        notify();
    }
    void wait(int count)
    {
        std::unique_lock lock(mutex_);
        if (!cv_.wait_for(lock, std::chrono::seconds(2),
                          [&] { return count_ >= count; }))
            throw std::runtime_error("RoleManager 通知超时");
    }

   private:
    void notify()
    {
        {
            std::lock_guard lock(mutex_);
            ++count_;
        }
        cv_.notify_one();
    }
    std::mutex mutex_;
    std::condition_variable cv_;
    int count_ = 0;
};
}  // namespace
int main()
{
    try {
        const Process first{501, 700}, second{502, 701}, child{503, 702};
        std::mutex probe_mutex;
        std::vector<Process> observed{first};
        RoleManagerProbe probe;
        probe.read_members = [&](const std::string&) {
            std::lock_guard lock(probe_mutex);
            return observed;
        };
        RoleManager manager(probe);
        auto map   = std::make_unique<Map>();
        auto* view = map.get();
        std::istringstream input(
            "[whitelist]\nexact: nginx.service\nexact: registry/app:v1\n");
        RoleFilterOptions options;
        options.liveness = [](Process) { return ProcessLiveness::ALIVE; };
        RoleFilter filter(manager,
                          RoleFilterPolicy(parse_role_filter_config(input)),
                          std::move(map), options);
        filter.set_supervision_service(&manager);
        Barrier barrier;
        manager.add_lifecycle_sink(&filter);
        manager.add_lifecycle_sink(&barrier);
        struct Runner {
            RoleManager& manager;
            std::thread thread;
            explicit Runner(RoleManager& value)
                : manager(value), thread([&value] { value.run(); })
            {
            }
            ~Runner()
            {
                manager.stop();
                thread.join();
            }
        } runner(manager);
        role::RoleEvent event{};
        event.action                        = role::RoleAction::JOIN;
        event.payload.identity.source       = role::RoleSource::SYSTEMD;
        event.payload.identity.instance_key = "nginx.service";
        event.payload.identity.type_key     = "nginx";
        event.payload.main_process          = first;
        event.payload.cgroup_path           = "/test";
        manager.on_role_event(event);
        barrier.wait(2);  // 加入 + 本次落地的新增成员
        filter.drain();
        require(manager.lookup(first).has_value());
        require(view->values.count(first));
        auto first_id = manager.lookup(first);
        require(first_id.has_value());
        auto supervised = manager.supervised_roles();
        require(supervised.size() == 1 && supervised[0].roleID == *first_id,
                "关注角色应登记监管");

        // 周期 JOIN 携带 cgroup 重读看不到的成员：只有成员通知能把它带进名单
        const Process notified{504, 704};
        event.payload.member_processes = {first, notified};
        manager.on_role_event(event);
        barrier.wait(3);
        filter.drain();
        require(view->values.count(notified), "成员新增通知应更新名单");

        {
            std::lock_guard lock(probe_mutex);
            observed.push_back(child);
        }
        filter.drain();
        require(view->values.count(child));
        /** @note 使用完整镜像引用作为标签，不使用 type_key 聚合键。 */
        event.action                  = role::RoleAction::MAIN_PROCESS_CHANGE;
        event.payload.identity.source = role::RoleSource::CONTAINERD;
        event.payload.identity.attributes["image"] = "registry/app:v1";
        event.payload.main_process                 = second;
        event.payload.member_processes.clear();
        {
            std::lock_guard lock(probe_mutex);
            observed = {second};
        }
        manager.on_role_event(event);
        barrier.wait(5);  // 锚点更换 + 新锚点的成员通知
        filter.drain();
        require(view->values.count(second));
        auto id = manager.lookup(second);
        require(id.has_value() &&
                manager.role(*id)->roleLabel == "registry/app:v1");
        supervised = manager.supervised_roles();
        require(supervised.size() == 1 && supervised[0].roleID == *id &&
                    supervised[0].roleLabel == "registry/app:v1",
                "监管快照应跟随角色标签");
        filter.replace_policy(RoleFilterPolicy());
        filter.drain();
        require(view->values.empty());
        require(manager.lookup(second).has_value());
        require(manager.supervised_roles().empty(), "策略清空应撤销监管");
        event.action = role::RoleAction::LEAVE;
        manager.on_role_event(event);
        barrier.wait(6);
        filter.drain();
        require(view->values.empty() && filter.stats().roles == 0);
        require(!manager.lookup(second));
        require(manager.supervised_roles().empty(), "角色退出后不应残留监管");
        std::printf("PASS: RoleManager -> RoleFilter integration, %d checks\n",
                    checks);
        return 0;
    }
    catch (const std::exception& error) {
        std::fprintf(stderr, "FAIL: %s\n", error.what());
        return 1;
    }
}
