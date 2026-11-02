/**
 * @file
 * @brief 名单维护器的私有任务与消费线程状态。
 * @author inless427
 * @internal 仅供 role_filter 模块内部使用。 @endinternal
 */
#ifndef HNG_ROLE_FILTER_STATE_HPP_
#define HNG_ROLE_FILTER_STATE_HPP_
#include <atomic>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include "agent/role_filter/src/role_filter.hpp"

namespace hng::detail {
using ProcessSet = std::unordered_set<Process>;

/** @brief 角色更新、退出、成员新增、刷新或策略替换任务。 */
struct FilterTask {
    enum class Kind { UPDATE, LEAVE, REFRESH, POLICY, MEMBERS };
    Kind kind;
    Role role{};
    std::shared_ptr<RoleFilterPolicy> policy;
    std::vector<Process> members;  ///< MEMBERS：本次新归属该角色的进程
};

/** @brief 单消费线程持有缓存，短临界区仅保护任务队列。 */
class RoleFilterState {
   public:
    RoleFilterState(const ::RoleLookupService& lookup, RoleFilterPolicy policy,
                    std::unique_ptr<ProcessFilterMap> map,
                    RoleFilterOptions options);
    void enqueue(FilterTask task);
    void run();
    void stop();
    void drain();
    void land(const FilterTask& task);
    void refresh();
    RoleFilterStats stats() const;
    void set_supervision_service(::RoleSupervisionService* service);
    /// @brief 借用的角色查询服务；供组件层播种时枚举角色全集
    const ::RoleLookupService& lookup() const;

   private:
    /** @brief 按状态变化登记或移除监管；未注入服务时为空操作。 */
    void sync_supervision(uint32_t role_id, bool supervised);
    /** @brief 按成员缓存与策略重算名单差异并同步 map。 */
    void apply();
    const ::RoleLookupService& lookup_;
    RoleFilterPolicy policy_;
    std::unique_ptr<ProcessFilterMap> map_;
    RoleFilterOptions options_;
    ::RoleSupervisionService* supervision_ = nullptr;
    /** @brief 已登记为监管的 roleID；只在状态变化时写 RoleManager。 */
    std::unordered_set<uint32_t> supervised_;
    std::unordered_map<uint32_t, Role> roles_;
    std::unordered_map<uint32_t, ProcessSet> members_;
    ProcessSet applied_;
    /** @brief 可能仅写入部分探针的身份，后续须重试或撤销，不能漏删。 */
    ProcessSet uncertain_;
    std::mutex queue_mutex_;
    std::condition_variable cv_;
    std::deque<FilterTask> queue_;
    bool stopped_ = false;
    std::atomic<uint64_t> roles_count_{0}, applied_count_{0};
    std::atomic<uint64_t> map_errors_{0}, lookup_errors_{0}, empty_members_{0},
        rejected_{0};
    std::atomic<int> last_map_error_{0};
};

/**
 * @brief 核对 procfs 中的进程身份。
 * @param[in] process 完整进程身份。
 * @param[in] proc_root procfs 根目录，可替换为测试目录。
 * @return 身份匹配为 ALIVE，退出或 PID 复用为 DEAD，无法确认时为 UNKNOWN。
 */
ProcessLiveness proc_liveness(Process process,
                              const std::string& proc_root = "/proc");

}  // namespace hng::detail
#endif
