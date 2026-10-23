/**
 * @file context_service.hpp
 * @brief 包含上下文相关的服务接口，是工作平面访问控制平面中上下文服务的方式
 *  context_manager.hpp 中 ContextManager 实现了这些接口
 * @author red_shinku
 * @date 2026.8.20
 */

#ifndef _CONTROL_PLANE_CONTEXTSERVICE_HPP
#define _CONTROL_PLANE_CONTEXTSERVICE_HPP

#include <optional>
#include <cstdint>
#include <vector>

#include "agent/control_plane/include/context_stats.hpp"
#include "agent/event_data/include/context.hpp"
#include "agent/event_data/include/process.hpp"
#include "agent/context_maintainer/include/context_maintainer_decision.hpp"

/// @brief 一个 context 的根进程与成员集
struct ContextProcessSet {
    hng::Process root;                  ///< context 根进程
    std::vector<hng::Process> members;  ///< 成员进程，含根进程
};

/**
 * @brief 查询 Context 的接口
 * 1) 查询 contextID
 * 2) 查询 extra_contextID
 * 3) 按属性枚举 contextID
 * 4) 按 contextID 取成员集
 */
class ContextLookupService {
   protected:
    virtual ~ContextLookupService() = default;

   public:
    /// @brief 查询进程所属主 context 的 ID
    /// @param p 任意进程；无需是 context 根进程，归属经内部 process→根 映射解析
    /// @return 命中的主 contextID；进程未归属任何 context 时返回 std::nullopt
    virtual std::optional<uint32_t> lookup(hng::Process p) const       = 0;

    /// @brief 查询进程所属 附属 Context 的 ID
    /// @param p 任意进程；归属的根进程存在附属 context 时返回其 ID
    /// @return 命中的 extraContextID
    virtual std::optional<uint32_t> lookup_extra(hng::Process p) const = 0;

    /// @brief 指定属性的 contextID 集合，按 ID 升序
    /// @details 同时覆盖主 context 与附属 context
    virtual std::vector<uint32_t> contexts_by_attr(
        hng::contextattr attr) const = 0;

    /// @brief 按 contextID 取根进程与成员集；未知 ID 返回空
    /// @return 根进程与成员进程（含根进程，按 pid 升序）
    virtual std::optional<ContextProcessSet> members(
        uint32_t contextID) const             = 0;

    /// @brief 异常态观测快照
    virtual ContextManagerStats stats() const = 0;
};

/**
 * @brief 注册新 Context、或为 Context 注册新进程 的接口
 * 1) 注册 context
 * 2) 注销 context
 * 3) 将进程与 context 根进程绑定
 */
class ContextJoinService {
   protected:
    virtual ~ContextJoinService() = default;

   public:
    /// @brief 其他组件通知注册新的主 contextID
    /// @param p context代表进程的唯一性表示
    /// @param newcontext 新的 context 及其信息，由工作平面 context 维护工具生成；
    ///        kind 须为 DERIVE
    /// @param parent 父进程；实现方在落地时解析其 contextID，未落定时按森林根
    /// @note 主 context 键唯一；同键的重复注册不产生附属 context，附属 context
    ///       须经 register_extra_context 登记
    virtual void register_context(hng::Process p,
                                  ContextDeriveDecision newcontext,
                                  hng::Process parent)                = 0;

    /// @brief 其他组件通知注册附属 context
    /// @param p context代表进程的唯一性表示；须已有主 context
    /// @param contextID 附属 contextID
    /// @param attr 附属 context 属性
    /// @note 主 context 未落定或已有附属 context 时丢弃/保留首个；不解决竞态
    virtual void register_extra_context(hng::Process p, uint32_t contextID,
                                        hng::contextattr attr)        = 0;

    /// @brief 其他组件通知注销 contextID
    /// @param p context代表进程的唯一性表示
    virtual void unregister_context(hng::Process p)                   = 0;

    /// @brief 归属落定：不派生的进程挂靠到其父进程所属的 context
    /// @details 派生决策为 KEEP（留在父 context）时由工作平面调用。实现方把 p
    /// 归入父进程所属的 context 根，使后续 lookup(p) 直接命中。父进程尚未落定
    /// 归属时（登记竞态）本调用为空操作，归属保持待定。
    virtual void bind_to_ctxroot(hng::Process p, hng::Process parent) = 0;
};

/**
 * @brief 更新 context 信息的接口
 * 1) 更改context属性
 */
class ContextUpdateService {
   protected:
    virtual ~ContextUpdateService() = default;

   public:
    /// @brief 通知修改 context 属性
    /// @param p context代表进程的唯一性表示
    /// @param contextID 目标 context 的 ID，用于区分主/附属 context
    /// @param attr 目标属性
    virtual void set_attr(hng::Process p, uint32_t contextID,
                          hng::contextattr attr) = 0;
};

#endif  //_CONTROL_PLANE_CONTEXTSERVICE_HPP