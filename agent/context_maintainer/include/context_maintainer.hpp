/**
 * @file context_maintainer.hpp
 * @brief context 的派生决策与归属查询维护模块
 * @details
 *
 * 本模块是「工具箱」：以进程身份与事件的 kind 为输入，维护待决策进程的派生
 * 观察窗口（rule::PendingTable）与每个进程的决策状态，在生命周期 / exec 边界
 * 产出派生决策并登记到控制平面；
 *
 * @author red_shinku
 * @date 2026.9.6
 */

#ifndef CONTEXT_MAINTAINER_HPP_
#define CONTEXT_MAINTAINER_HPP_

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>

#include "agent/control_plane/include/context_service.hpp"
#include "agent/detector/include/score.hpp"
#include "agent/event_data/include/process.hpp"
#include "agent/event_data/include/event_type.hpp"
#include "agent/context_maintainer/include/context_maintainer_decision.hpp"

// rule 派生规则是本模块的实现细节（src/rule/），此处只前置声明其类型，
// 不得改为包含定义——公共头一旦引入 src 头，该细节就随之外泄。
namespace hng {
namespace detail {
class PendingTable;
struct DeriveVerdict;
}  // namespace detail
}  // namespace hng

/**
 * @brief 工作平面的累计统计快照
 */
struct ContextMaintainerStats {
    uint64_t keep_parent_unobserved = 0;  ///< 累计：KEEP 的父未被观测，未挂靠
    uint64_t lookup_depth_limited   = 0;  ///< 累计：事件归因查询超过父链深度上限
};

class ContextMaintainer {
   public:
    /// @param window_size 待决策进程的事件窗口配额
    ContextMaintainer(uint32_t window_size = kDefaultWindow);
    ~ContextMaintainer();

    /// @brief 注入 ContextManager 服务接口
    /// @param ctx_lookup_sv 查询接口
    /// @param ctx_join_sv 注册接口
    /// @param ctx_update_sv 更新接口
    void set_context_service(ContextLookupService* ctx_lookup_sv,
                             ContextJoinService* ctx_join_sv,
                             ContextUpdateService* ctx_update_sv);

    /**
     * \defgroup Participate_in_derive_decision !!!
     *   接口：输入事件并参与派生 context 的决策。
     *   调用者需根据事件类型决定使用哪个方法，所有事件都需要过一遍该组
     *   接口，而其中只有那些所属进程在本模块 pending_table 中的事件，
     *   才会参与决策。
     */
    /**@{*/

    /// @brief 立即决策是否需要派生 context，exec 类事件导向此方法
    /// @details 每个进程只决策一次：已决策的进程为原地重 exec，直接返回 NONE。
    /// 尚未决策的进程在本次 exec 上按规则定 KEEP 或 DERIVE：DERIVE 分配
    /// contextID、判定 attr 并经 ContextService 注册；KEEP 不分配 contextID，仅在
    /// 父已被观测时经 ContextService 挂靠到父进程所属 context 的根。
    /// @param p 执行 exec 的进程
    /// @param parent 父进程（pending 记录缺失/乱序时惰性判定用）
    /// @param filename 归一化的 exec 目标路径
    /// @return DERIVE 或 KEEP 的决策；已决策进程与判定入口无结果时 kind 为 NONE
    /// \ingroup Participate_in_derive_decision
    ContextDeriveDecision should_derive_context(hng::Process p,
                                                hng::Process parent,
                                                const std::string& filename);

    /// @brief 把新线程组进程登记进观察窗口，fork类事件导向此方法
    /// @param child 新进程（诞生事件 head.pid）
    /// @param parent 父进程（诞生事件 head.ppid）
    /// \ingroup Participate_in_derive_decision
    void on_birth(hng::Process child, hng::Process parent);

    /// @brief 推进进程 pending 窗口期，非 exec / 非生命周期类型事件导向此方法
    /// @details 仅对窗口期内的进程消耗配额；配额耗尽触发 NO_EXEC 派生。
    /// @param p 事件所属进程
    /// @return 触发 NO_EXEC 派生时为该新 context 的注册决策；其余 kind 为 NONE
    /// \ingroup Participate_in_derive_decision
    ContextDeriveDecision on_event(hng::Process p);

    /// @brief 兜底清理观察窗口与决策状态，exit 事件导向此方法
    /// @param p 退出的进程
    /// \ingroup Participate_in_derive_decision
    void on_exit(hng::Process p);

    /**
     * @} endgroup Participate_in_derive_decision
     */

    /// @brief TODO: 是否进入附属 Context（分值判定）
    ContextExtraDecision should_extra_context(hng::EventType type, Score score);

    /// @brief TODO: 尝试更新 UNKNOWN Context 的属性 （分值判定）
    void try_update_context_attributes(Score score);

    /// @brief contextID 查询（事件归因）
    /// @details 决策窗口内的进程没有最终归属，沿父链取事件归因用的 context；
    /// 该结果不代表该进程的最终归属，需要最终归属的调用方应直接查控制平面。
    /// 超过 8 层父链时返回空并计数。已决策的进程中，DERIVE 返回本地分配的
    /// contextID；KEEP 与其余进程只查控制平面中的登记结果。
    /// @param p 进程身份
    std::optional<uint32_t> lookup_contextID(hng::Process p) const;

    /// @brief 累计统计快照
    /// @return 当前累计计数器，读取不改变统计
    ContextMaintainerStats stats() const;

   private:
    /// 默认事件窗口配额
    static constexpr uint32_t kDefaultWindow = 8;

    /// @brief 该进程最近一次 exec 目标是否解释器家族（近似父是否解释器）
    /// @param parent 待查询的父进程
    /// @return 状态表中不存在该进程或最近一次 exec 非解释器时为 false
    bool parent_is_interpreter(hng::Process parent) const;

    /// @brief 进程是否已被本模块观测
    /// @param p 待检查的进程
    /// @param self 发起判定的进程；p 与 self 相同视为未观测
    bool observed(hng::Process p, hng::Process self) const;

    /// @brief 决定新派生 context 的属性
    /// @details 依据是父 context 的属性，ATTACK 生 ATTACK，NORMAL 生 UNKNOWN
    hng::contextattr decide_attr(hng::Process child, hng::Process parent);

    /// @brief 派生决策落定：分配 contextID、判定 attr、记录状态并注册
    /// @param v 规则层派生判定
    /// @return kind 为 DERIVE 的决策
    ContextDeriveDecision finalize_derive(const hng::detail::DeriveVerdict& v);

    /// @brief 分配下一个 contextID（0 保留作"无父 context"哨兵，故从 1 起）
    uint32_t allocate_context_id();

    /// @brief 归属查询的父链深度上限
    static constexpr uint32_t kLookupDepthLimit = 8;

    /// @brief 追溯输入进程所属 context 的根进程
    /// @param p 要进行追溯的进程
    /// @return 本 context 根进程
    hng::Process trace_context_root_process(hng::Process p);

    /// @brief 带深度上限的归属查询递归实现
    /// @param p 待查询的进程
    /// @param depth 已递归的父链深度
    /// @return 归属的 contextID；无归属或超过深度上限时为 std::nullopt
    std::optional<uint32_t> lookup_contextID_at(hng::Process p,
                                                uint32_t depth) const;

    /// @brief 仅查询控制平面中已登记的 context
    /// @param p 待查询的进程
    std::optional<uint32_t> lookup_registered(hng::Process p) const;

    /// 以进程身份为键的包装结构，比较与哈希沿用 hng::Process 的定义
    struct ProcessKey {
        hng::Process p;
        bool operator==(const ProcessKey& o) const { return p == o.p; }
    };
    struct KeyHash {
        std::size_t operator()(const ProcessKey& k) const
        {
            return std::hash<hng::Process>{}(k.p);
        }
    };

    /// @brief 进程在本模块的决策状态
    struct ProcessContextState {
        bool exec_is_interpreter = false;  ///< 最近一次 exec 目标是否解释器家族
        bool decided             = false;  ///< 是否已产生 KEEP/DERIVE 决策
        ContextDecisionKind kind = ContextDecisionKind::NONE;
        uint32_t contextID       = 0;  ///< kind 为 DERIVE 时有效
    };

    ContextLookupService* ctx_lookup_service_ = nullptr;
    ContextJoinService* ctx_join_service_     = nullptr;
    ContextUpdateService* ctx_update_service_ = nullptr;

    ///< 待决策进程观察窗口；指向不完整类型，定义见 src/rule/pending_table.hpp
    std::unique_ptr<hng::detail::PendingTable> pending_;

    // 进程 → 决策状态；键含 pid_start_time，KEEP 判定的"父是否解释器"亦取自此表
    std::unordered_map<ProcessKey, ProcessContextState, KeyHash> states_;
    //TODO: 初始化 seed 落地时在 run() 前填充 states_，入口由初始化任务定义。

    mutable std::atomic<uint64_t> keep_parent_unobserved_{0};
    mutable std::atomic<uint64_t> lookup_depth_limited_{0};

    uint32_t next_context_id_ = 1;  ///< 单调 contextID 分配游标
    uint32_t window_size_;          ///< 事件窗口配额
};

#endif  // CONTEXT_MAINTAINER_HPP_
