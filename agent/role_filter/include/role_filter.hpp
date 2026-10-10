#ifndef HNG_ROLE_FILTER_HPP_
#define HNG_ROLE_FILTER_HPP_

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include "agent/control_plane/include/role_lifecycle_sink.hpp"
#include "agent/control_plane/include/role_service.hpp"
#include "agent/role_filter/include/process_filter_map.hpp"
#include "agent/role_filter/include/role_filter_policy.hpp"

namespace hng {
namespace detail { class RoleFilterState; }

enum class ProcessLiveness { ALIVE, DEAD, UNKNOWN };

struct RoleFilterOptions {
    std::chrono::milliseconds refresh_interval{1000};
    // 空函数使用 /proc 身份核对。UNKNOWN 不删除；用于测试或特殊 procfs 部署。
    std::function<ProcessLiveness(Process)> liveness;
};

struct RoleFilterStats {
    uint64_t roles = 0;
    uint64_t applied_processes = 0;
    uint64_t map_errors = 0;
    uint64_t lookup_errors = 0;
    uint64_t empty_members = 0;
    uint64_t queue_rejected = 0;
    int last_map_error = 0;
};

/* 回调只入队；cgroup IO、正则匹配和 map 写入在消费线程进行。
 * lookup 必须活到析构后，map 由本对象独占。run() 线程由装配方管理。
 * 在 RoleManager::run() 之前注册，避免漏初始 JOIN；不反向注册/删除角色。
 */
class RoleFilter final : public RoleLifecycleSink {
   public:
    RoleFilter(const RoleLookupService& lookup, RoleFilterPolicy policy,
               std::unique_ptr<ProcessFilterMap> map, RoleFilterOptions options = {});
    ~RoleFilter() override;
    RoleFilter(const RoleFilter&) = delete;
    RoleFilter& operator=(const RoleFilter&) = delete;

    void on_role_joined(const Role& role) override;
    void on_role_left(const Role& role) override;
    void on_role_main_process_changed(const Role& role) override;
    void request_refresh();
    // 调用方先解析并编译策略，失败不影响旧配置；新策略经同一队列串行应用。
    void replace_policy(RoleFilterPolicy policy);
    void run();
    void stop();
    // 不启动线程时用于阶段验证；与 run() 不能并发。处理现有队列并刷新一次。
    void drain();
    RoleFilterStats stats() const;

   private:
    std::unique_ptr<detail::RoleFilterState> state_;
};

}  // namespace hng
#endif
