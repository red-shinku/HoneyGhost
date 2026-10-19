/**
 * @file
 * @brief 接收角色生命周期通知并维护进程采集白名单。
 */
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
/** @brief 进程身份存活状态；UNKNOWN 不能作为撤销许可的依据。 */
enum class ProcessLiveness { ALIVE, DEAD, UNKNOWN };
/** @brief 刷新周期与可替换的存活检查。 */
struct RoleFilterOptions {
    std::chrono::milliseconds refresh_interval{1000}; ///< 必须为正，默认每秒刷新。
    /** @brief 空函数时通过 /proc 核对 PID 和启动时间；UNKNOWN 保留原记录。 */
    std::function<ProcessLiveness(Process)> liveness;
};
/** @brief 各字段独立读取的统计结果，不保证来自同一刷新时刻。 */
struct RoleFilterStats {
    uint64_t roles = 0; ///< 上次刷新结束时记录的角色数，包含不关注的角色。
    uint64_t applied_processes = 0; ///< 已确认成功同步到所有 map 的进程数。
    uint64_t map_errors = 0; ///< 累计 map 操作错误次数。
    uint64_t lookup_errors = 0; ///< 累计查询或存活检查异常次数。
    uint64_t empty_members = 0; ///< 累计关注角色返回空成员集合的次数。
    uint64_t queue_rejected = 0; ///< 停止后拒绝的入队请求数。
    int last_map_error = 0; ///< 最近一次 map 错误值，初始为零。
};

/**
 * @brief 由角色通知和周期刷新驱动的进程名单维护器。
 * @details 回调只入队，成员枚举、正则匹配与 map 写入由单消费线程执行。
 * 实现最新版全局 RoleLifecycleSink，借用全局 RoleLookupService。
 * @pre 在 RoleManager::run() 前注册，lookup 必须活到本对象析构后。
 * @note 不负责反向创建或删除 RoleManager 记录；消费线程由装配方创建。
 */
class RoleFilter final : public ::RoleLifecycleSink {
   public:
    /**
     * @brief 创建维护器并接管 map 后端。
     * @param[in] lookup 借用的角色查询服务。
     * @param[in] policy 初始标签策略。
     * @param[in] map 非空的独占 map 后端。
     * @param[in] options 刷新周期与进程存活检查。
     * @throws std::invalid_argument map 为空或刷新周期不为正。
     */
    RoleFilter(const ::RoleLookupService& lookup, RoleFilterPolicy policy,
               std::unique_ptr<ProcessFilterMap> map, RoleFilterOptions options = {});
    /**
     * @brief 释放维护器和 map 后端，不负责 join 外部线程。
     * @pre 已停止通知来源、调用 stop() 并等待 run() 线程退出。
     */
    ~RoleFilter() override;
    RoleFilter(const RoleFilter&) = delete;
    RoleFilter& operator=(const RoleFilter&) = delete;
    /**
     * @brief 将角色加入通知入队。
     * @param[in] role 当前角色快照。
     */
    void on_role_joined(const Role& role) override;
    /**
     * @brief 将角色退出通知入队。
     * @param[in] role 退出的角色快照。
     */
    void on_role_left(const Role& role) override;
    /**
     * @brief 将主进程变更通知入队。
     * @param[in] role 更新后的角色快照。
     */
    void on_role_main_process_changed(const Role& role) override;
    /** @brief 入队一次立即刷新请求。 */
    void request_refresh();
    /**
     * @brief 将已构造成功的新策略入队，串行替换旧策略。
     * @param[in] policy 新策略；解析或编译失败应由调用方保留旧策略。
     */
    void replace_policy(RoleFilterPolicy policy);
    /**
     * @brief 阻塞消费直到 stop()，退出前排空已接收任务并刷新一次。
     * @pre 不得与另一个 run() 或 drain() 并发；停止后不可重启。
     */
    void run();
    /** @brief 拒绝新任务并唤醒消费线程，不等待线程退出。 */
    void stop();
    /** @brief 同步处理当前任务并刷新一次；不得与其他消费者并发。 */
    void drain();
    /**
     * @brief 读取统计值。
     * @return 各独立计数器的快照。
     */
    RoleFilterStats stats() const;
   private:
    std::unique_ptr<detail::RoleFilterState> state_;
};
}  // namespace hng
#endif
