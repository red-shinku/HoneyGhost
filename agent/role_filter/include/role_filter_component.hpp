/**
 * @file role_filter_component.hpp
 * @brief 角色过滤组件的公共句柄、构造选项与观测类型。
 * @details 装配层经工厂构造并持有该句柄；名单维护器实现仍在 src/。
 */

#ifndef HNG_ROLE_FILTER_COMPONENT_HPP_
#define HNG_ROLE_FILTER_COMPONENT_HPP_

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>

#include "agent/role_filter/include/process_filter_map.hpp"
#include "agent/role_filter/include/role_filter_policy.hpp"
#include "agent/util/include/component.hpp"

class RoleLifecycleSink;
class RoleLookupService;
class RoleSupervisionService;

namespace hng {

/** @brief 进程身份存活状态；UNKNOWN 不能作为撤销许可的依据。 */
enum class ProcessLiveness { ALIVE, DEAD, UNKNOWN };

/** @brief 刷新周期与可替换的存活检查。 */
struct RoleFilterOptions {
    std::chrono::milliseconds refresh_interval{
        1000};  ///< 必须为正，默认每秒刷新。
    /** @brief 空函数时通过 /proc 核对 PID 和启动时间；UNKNOWN 保留原记录。 */
    std::function<ProcessLiveness(Process)> liveness;
};

/** @brief 各字段独立读取的统计结果，不保证来自同一刷新时刻。 */
struct RoleFilterStats {
    uint64_t roles = 0;  ///< 上次刷新结束时记录的角色数，包含不关注的角色。
    uint64_t applied_processes = 0;  ///< 已确认成功同步到所有 map 的进程数。
    uint64_t map_errors        = 0;  ///< 累计 map 操作错误次数。
    uint64_t lookup_errors     = 0;  ///< 累计查询或存活检查异常次数。
    uint64_t empty_members     = 0;  ///< 累计关注角色返回空成员集合的次数。
    uint64_t queue_rejected    = 0;  ///< 停止后拒绝的入队请求数。
    int last_map_error         = 0;  ///< 最近一次 map 错误值，初始为零。
};

/**
 * @brief 角色过滤组件的构造选项。
 * @details lookup 与 map 为必需依赖；其余为空时按未接线处理。
 */
struct RoleFilterComponentOptions {
    /// 借用的角色查询服务，必需
    const ::RoleLookupService* lookup     = nullptr;
    /// 借用的监管登记写入侧；为空时只维护采集名单
    ::RoleSupervisionService* supervision = nullptr;
    /// 初始标签策略
    RoleFilterPolicy policy;
    /// 非空的独占 map 后端
    std::unique_ptr<ProcessFilterMap> map;
    /// 刷新周期与进程存活检查
    RoleFilterOptions filter_options;
};

/**
 * @brief 角色过滤组件的公共句柄。
 * @details 转发名单维护器的生命周期通知、初始播种、刷新与统计；组件不持线程。
 * @note 生命周期只沿 CONSTRUCTED → READY → RUNNING → STOPPED 前进。
 * @see hng::Component, RoleFilterComponentOptions, RoleFilterFactory
 */
class RoleFilterComponent final : public hng::Component {
   public:
    ~RoleFilterComponent() override;

    RoleFilterComponent(const RoleFilterComponent&)            = delete;
    RoleFilterComponent& operator=(const RoleFilterComponent&) = delete;
    RoleFilterComponent(RoleFilterComponent&&)                 = delete;
    RoleFilterComponent& operator=(RoleFilterComponent&&)      = delete;

    /// @brief 注册到 RoleManager 的生命周期出口
    /// @return 与组件同寿命的 sink 引用
    /// @note 须在 RoleManager::run() 前注册
    ::RoleLifecycleSink& lifecycle_sink() noexcept;

    /// @brief 用 RoleManager 当前角色全集播种第一份名单，并置 READY
    /// @pre RoleManager 已完成初始角色 drain
    /// @pre 尚未 run()，map 后端已由采集器 prepare() 后的空 map fd 创建
    /// @note 只调用一次；状态不是 CONSTRUCTED 时为空操作
    void seed_initial_roles();

    /// @brief 同步处理当前任务并刷新一次
    /// @note 不得与该组件的 run() 并发；可在 seed_initial_roles() 与 run() 前使用
    void drain();

    /// @brief 入队一次立即刷新请求
    void request_refresh();

    /// @brief 入队已构造成功的新策略，串行替换旧策略
    /// @param policy 新策略；解析或编译失败应由调用方保留旧策略
    void replace_policy(RoleFilterPolicy policy);

    /// @brief 读取统计值
    /// @return 各独立计数器的快照
    RoleFilterStats stats() const;

    /// @brief 当前生命周期状态
    /// @see hng::Component::state
    hng::ComponentState state() const override;

    /// @brief 组件线程入口
    /// @see hng::Component::run
    void run() override;

    /// @brief 停止组件
    /// @see hng::Component::stop
    void stop() override;

   private:
    struct Impl;

    explicit RoleFilterComponent(std::unique_ptr<Impl> impl);

    friend class RoleFilterFactory;

    std::unique_ptr<Impl> impl_;
};

}  // namespace hng

#endif  // HNG_ROLE_FILTER_COMPONENT_HPP_
