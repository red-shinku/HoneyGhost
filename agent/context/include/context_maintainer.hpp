/**
 * @file context_maintainer.hpp
 * @brief context 的派生决策与归属查询维护模块
 * @details
 *
 * 本模块是「工具箱」：以进程身份与事件的 kind 为输入，维护待决策进程的派生
 * 观察窗口（rule::PendingTable），在生命周期 / exec 边界产出派生决策并登记到
 * 控制平面；
 *
 * @author red_shinku
 * @date 2026.9.6
 */

#ifndef CONTEXT_MAINTAINER_HPP_
#define CONTEXT_MAINTAINER_HPP_

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <unordered_map>

#include "agent/control_plane/include/process_service.hpp"
#include "agent/control_plane/include/context_service.hpp"
#include "agent/context/rule/include/derive_types.hpp"
#include "agent/context/rule/include/pending_table.hpp"
#include "agent/detector/include/score.hpp"
#include "agent/event_data/process.hpp"
#include "agent/event_data/event_type.hpp"
#include "./context_maintainer_decision.hpp"

class ContextMaintainer {
   public:
    /// @param p_service 控制平面 process 服务
    /// @param ctx_service 控制平面 context 服务
    /// @param window_size 待决策进程的事件窗口配额
    ContextMaintainer(ProcessService* p_service, ContextService* ctx_service,
                      uint32_t window_size = kDefaultWindow);
    ~ContextMaintainer();

    /**
     * \defgroup Participate_in_derive_decision !!!
     *   接口：输入事件并参与派生 context 的决策。
     *   调用者需根据事件类型决定使用哪个方法，所有事件都需要过一遍该组
     *   接口，而其中只有那些所属进程在本模块 pending_table 中的事件，
     *   才会参与决策。
     */
    /**@{*/

    /// @brief 立即决策是否需要派生 context，exec 类事件导向此方法
    /// @details 输入为一次 exec：该进程尚未拥有自身 context 时（pending 或惰性
    /// 首次判定），按规则决策；已拥有自身 context 的进程为原地重 exec，不决策。
    /// 派生发生时分配 contextID、判定 attr 并经 ContextService 注册。
    /// @param p 执行 exec 的进程
    /// @param parent 父进程（pending 记录缺失/乱序时惰性判定用）
    /// @param filename 归一化的 exec 目标路径
    /// @return 派生发生时返回该新 context 的注册决策；KEEP / 原地重 exec 为空
    /// \ingroup Participate_in_derive_decision
    std::optional<ContextDeriveDecision> should_derive_context(
        hng::Process p, hng::Process parent, const std::string& filename);

    /// @brief 把新线程组进程登记进观察窗口，fork类事件导向此方法
    /// @param child 新进程（诞生事件 head.pid）
    /// @param parent 父进程（诞生事件 head.ppid）
    /// \ingroup Participate_in_derive_decision
    void on_birth(hng::Process child, hng::Process parent);

    /// @brief 推进进程 pending 窗口期，非 exec / 非生命周期类型事件导向此方法
    /// @details 仅对窗口期内的进程消耗配额；配额耗尽触发 NO_EXEC 派生。
    /// @param p 事件所属进程
    /// @return 触发 NO_EXEC 派生时为该新 context 的注册决策；其余为空
    /// \ingroup Participate_in_derive_decision
    std::optional<ContextDeriveDecision> on_event(hng::Process p);

    /// @brief 兜底清理观察窗口，exit 事件导向此方法
    /// @param p 退出的进程
    /// \ingroup Participate_in_derive_decision
    void on_exit(hng::Process p);

    /**
     * @} endgroup Participate_in_derive_decision
     */

    /// @brief 是否进入附属 Context（分值判定，本任务不实现）
    ContextExtraDecision should_extra_context(hng::EventType type, Score score);

    /// @brief 尝试更新 UNKNOWN Context 的属性（本任务不实现）
    void try_update_context_attributes(Score score);

    /// @brief contextID 归属查询（纯查询，无副作用）
    /// @details 窗口期内的进程归父 context（经 ContextService 查父进程）；
    /// 其余进程返回自身已登记的 context（未登记返回空）。
    /// @param p 进程身份
    std::optional<uint32_t> lookup_contextID(hng::Process p) const;

   private:
    /// 默认事件窗口配额
    static constexpr uint32_t kDefaultWindow = 8;

    /// @brief 该进程最近一次 exec 目标是否解释器家族（近似父是否解释器）
    bool parent_is_interpreter(hng::Process parent) const;

    /// @brief 决定新派生 context 的属性
    /// @details 依据是父 context 的属性，ATTACK 生 ATTACK，NORMAL 生 UNKNOWN
    hng::contextattr decide_attr(hng::Process child, hng::Process parent);

    /// @brief 派生决策落定：分配 contextID、判定 attr、经 ContextService 注册
    /// @param v 规则层派生判定
    std::optional<ContextDeriveDecision> finalize_derive(
        const hng::rule::DeriveVerdict& v);

    /// @brief 分配下一个 contextID（0 保留作"无父 context"哨兵，故从 1 起）
    uint32_t allocate_context_id();

    /// 以 (pid, start_time) 为键的进程包装结构
    struct ProcessKey {
        hng::Process p;
        bool operator==(const ProcessKey& o) const
        {
            return p.pid == o.p.pid && p.pid_start_time == o.p.pid_start_time;
        }
    };
    struct KeyHash {
        std::size_t operator()(const ProcessKey& k) const
        {
            return std::hash<uint32_t>{}(k.p.pid) ^
                   (std::hash<uint64_t>{}(k.p.pid_start_time) << 1);
        }
    };

    ProcessService* process_service_;  ///< 控制平面进程服务
    ContextService* context_service_;  ///< 控制平面 context 服务
    hng::rule::PendingTable pending_;  ///< 待决策进程观察窗口

    // 进程 → 其最近一次 exec 目标是否解释器（KEEP 判定的"父是否解释器"近似来源）
    std::unordered_map<ProcessKey, bool, KeyHash> exec_is_interpreter_;

    uint32_t next_context_id_ = 1;  ///< 单调 contextID 分配游标
    uint32_t window_size_;          ///< 事件窗口配额
};

#endif  // CONTEXT_MAINTAINER_HPP_
