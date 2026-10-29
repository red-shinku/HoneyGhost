/**
 * @file
 * @brief 接收角色生命周期通知并维护进程采集白名单。
 * @author inless427
 */
#ifndef HNG_ROLE_FILTER_HPP_
#define HNG_ROLE_FILTER_HPP_
#include <atomic>
#include <memory>
#include <vector>
#include "agent/control_plane/include/role_lifecycle_sink.hpp"
#include "agent/control_plane/include/role_service.hpp"
#include "agent/role_filter/include/role_filter_component.hpp"

namespace hng {

namespace detail {
class RoleFilterState;
}

/**
 * @brief 由角色通知和周期刷新驱动的进程名单维护器。
 * @details 回调只入队；成员枚举、正则匹配、map 写入与监管登记由单消费线程执行。
 * 成员新增通知在消费线程上直接并入成员缓存并重算名单差异，不重查权威源。
 * 实现最新版全局 RoleLifecycleSink，借用全局 RoleLookupService；可通过
 * set_supervision_service 注入监管登记写入侧。
 * @pre 在 RoleManager::run() 前注册，lookup 必须活到本对象析构后。
 * @note 不负责反向创建或删除 RoleManager 记录；消费线程由装配方创建。
 *       生命周期只沿 CONSTRUCTED → READY → RUNNING → STOPPED 前进。
 * @see hng::Component
 */
class RoleFilter final : public ::RoleLifecycleSink, public hng::Component {
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
               std::unique_ptr<ProcessFilterMap> map,
               RoleFilterOptions options = {});
    /**
     * @brief 释放维护器和 map 后端，不负责 join 外部线程。
     * @pre 已停止通知来源、调用 stop() 并等待 run() 线程退出。
     */
    ~RoleFilter() override;
    RoleFilter(const RoleFilter&)            = delete;
    RoleFilter& operator=(const RoleFilter&) = delete;
    /**
     * @brief 注入监管登记写入侧。
     * @param[in] service 可为空；为空时只维护采集名单，不向 RoleManager 登记。
     * @pre 须在 run() / drain() 之前调用；service 须活到本对象析构后。
     */
    void set_supervision_service(::RoleSupervisionService* service);
    /**
     * @brief 用 RoleManager 当前角色全集播种第一份名单，并置 READY。
     * @pre 尚未 run()；RoleManager 已完成初始角色 drain
     * @pre map 后端已由采集器 prepare() 后的空 map fd 创建
     * @note 只调用一次；状态不是 CONSTRUCTED 时为空操作。
     * @note 对每个角色投递 UPDATE 任务、对可取得的锚点投递 MEMBERS 任务，
     *       再同步 drain()；不启动线程。成员仍由 refresh() 经
     *       members(roleID) 重新枚举，不复制 RoleManager 内部表。
     *       map 写入失败保留 uncertain_ 并计数，不阻止 READY，后续刷新重试。
     * @note 协调器中 PM seed 之后的 RM reconcile 结果经 RoleManager 的成员与
     *       生命周期通知补入名单，不在播种时读取。
     * @see RoleFilter::run
     */
    void seed_initial_roles();
    /**
     * @brief 当前生命周期状态。
     * @note 可从任意线程读取。
     * @see hng::Component::state
     */
    hng::ComponentState state() const override;
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
    /**
     * @brief 将角色成员新增通知入队。
     * @param[in] role 当前角色快照。
     * @param[in] added 本次新归属该角色的进程。
     * @note 只并入成员缓存；成员移除仍由周期刷新中的存活核对收敛。
     */
    void on_role_members_changed(const Role& role,
                                 const std::vector<Process>& added) override;
    /** @brief 入队一次立即刷新请求。 */
    void request_refresh();
    /**
     * @brief 将已构造成功的新策略入队，串行替换旧策略。
     * @param[in] policy 新策略；解析或编译失败应由调用方保留旧策略。
     */
    void replace_policy(RoleFilterPolicy policy);
    /**
     * @brief 阻塞消费直到 stop()，退出前排空已接收任务并刷新一次。
     * @pre state() 为 READY；否则立即返回且不改状态
     * @pre 不得与另一个 run() 或 drain() 并发；停止后不可重启
     */
    void run() override;
    /**
     * @brief 拒绝新任务并唤醒消费线程，不等待线程退出。
     * @note 当前不是 RUNNING 时立即置 STOPPED。
     */
    void stop() override;
    /**
     * @brief 同步处理当前任务并刷新一次；不得与其他消费者并发。
     * @note 可在 seed_initial_roles() 与 run() 之前使用。
     */
    void drain();
    /**
     * @brief 读取统计值。
     * @return 各独立计数器的快照。
     */
    RoleFilterStats stats() const;

   private:
    std::unique_ptr<detail::RoleFilterState> state_;
    std::atomic<hng::ComponentState> lifecycle_{hng::ComponentState::CONSTRUCTED};
};
}  // namespace hng
#endif
