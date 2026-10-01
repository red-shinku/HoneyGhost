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
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>

#include "agent/control_plane/include/process_service.hpp"
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

class ContextMaintainer {
   public:
    /// @param p_service 控制平面 process 服务
    /// @param ctx_service 控制平面 context 服务
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

    /// @brief TODO: 是否进入附属 Context（分值判定）
    ContextExtraDecision should_extra_context(hng::EventType type, Score score);

    /// @brief TODO: 尝试更新 UNKNOWN Context 的属性 （分值判定）
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
        const hng::detail::DeriveVerdict& v);

    /// @brief 分配下一个 contextID（0 保留作"无父 context"哨兵，故从 1 起）
    uint32_t allocate_context_id();

    /// @brief 追溯输入进程所属 context 的根进程
    /// @param p 要进行追溯的进程
    /// @return 本 context 根进程
    hng::Process trace_context_root_process(hng::Process p);

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

    ContextLookupService* ctx_lookup_service_ = nullptr;
    ContextJoinService* ctx_join_service_     = nullptr;
    ContextUpdateService* ctx_update_service_ = nullptr;

    ///< 待决策进程观察窗口；指向不完整类型，定义见 src/rule/pending_table.hpp
    std::unique_ptr<hng::detail::PendingTable> pending_;

    // 进程 → 其最近一次 exec 目标是否解释器（KEEP 判定的"父是否解释器"近似来源）
    std::unordered_map<ProcessKey, bool, KeyHash> exec_is_interpreter_;

    uint32_t next_context_id_ = 1;  ///< 单调 contextID 分配游标
    uint32_t window_size_;          ///< 事件窗口配额
};

#endif  // CONTEXT_MAINTAINER_HPP_
