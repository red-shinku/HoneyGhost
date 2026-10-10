#ifndef HNG_ROLE_FILTER_STATE_HPP_
#define HNG_ROLE_FILTER_STATE_HPP_

#include <atomic>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include "agent/role_filter/include/role_filter.hpp"

namespace hng::detail {
using ProcessSet = std::unordered_set<Process>;

struct FilterTask {
    enum class Kind { UPDATE, LEAVE, REFRESH, POLICY };
    Kind kind;
    Role role{};
    std::shared_ptr<RoleFilterPolicy> policy;
};

class RoleFilterState {
   public:
    RoleFilterState(const RoleLookupService& lookup, RoleFilterPolicy policy,
                    std::unique_ptr<ProcessFilterMap> map, RoleFilterOptions options);
    void enqueue(FilterTask task);
    void run();
    void stop();
    void drain();
    void land(const FilterTask& task);
    void refresh();
    RoleFilterStats stats() const;

   private:
    const RoleLookupService& lookup_;
    RoleFilterPolicy policy_;
    std::unique_ptr<ProcessFilterMap> map_;
    RoleFilterOptions options_;
    std::unordered_map<uint32_t, Role> roles_;
    std::unordered_map<uint32_t, ProcessSet> members_;
    ProcessSet applied_;
    // 有些 backend 已写入部分探针才报错：必须记录并重试，不能在策略改变后漏删。
    ProcessSet uncertain_;

    std::mutex queue_mutex_;
    std::condition_variable cv_;
    std::deque<FilterTask> queue_;
    bool stopped_ = false;
    std::atomic<uint64_t> roles_count_{0}, applied_count_{0};
    std::atomic<uint64_t> map_errors_{0}, lookup_errors_{0}, empty_members_{0}, rejected_{0};
    std::atomic<int> last_map_error_{0};
};

ProcessLiveness proc_liveness(Process p, const std::string& proc_root = "/proc");
}  // namespace hng::detail
#endif
