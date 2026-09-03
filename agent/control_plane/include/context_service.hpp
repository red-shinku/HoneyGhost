/**
 * @file context_service.hpp
 * @brief 包含一个接口类，是工作平面访问控制平面中进程相关服务的方式
 *  context_manager.hpp 中 ContextManager 实现了该接口
 * @author red_shinku
 * @date 2026.8.20
 */

#ifndef _CONTROL_PLANE_CONTEXTSERVICE_HPP
#define _CONTROL_PLANE_CONTEXTSERVICE_HPP

#include <optional>
#include <cstdint>

#include "agent/event_data/context.hpp"
#include "agent/event_data/process.hpp"
#include "agent/context/include/context_maintainer_decision.hpp"

class ContextService {
   protected:
    virtual ~ContextService() = default;

   public:
    /// @brief 按代表进程查询其所属的 contextID
    /// @param p context代表进程的唯一性表示
    /// @return 命中的 contextID；进程未归属任何 context 时返回 std::nullopt
    virtual std::optional<uint32_t> lookup(hng::Process p) const       = 0;

    /// @brief 查询 附属 Context 的 ID
    /// @param p context代表进程的唯一性表示
    /// @return 命中的 extraContextID
    virtual std::optional<uint32_t> lookup_extra(hng::Process p) const = 0;

    /// @brief 其他组件通知注册新的 contextID
    /// @param p context代表进程的唯一性表示
    /// @param newcontext 新的 context 及其信息，由工作平面 context 维护工具生成
    /// @param pcontextID 父 context ID
    virtual void register_contextID(hng::Process p,
                                    ContextDeriveDecision newcontext,
                                    uint32_t pcontextID)               = 0;

    /// @brief 其他组件通知注销 contextID
    /// @param p context代表进程的唯一性表示
    virtual void unregister_contextID(hng::Process p)                  = 0;

    /// @brief 通知修改 context 属性
    /// @param p context代表进程的唯一性表示
    /// @param contextID 目标 context 的 ID，用于区分主/附属 context
    /// @param attr 目标属性
    virtual void set_attr(hng::Process p, uint32_t contextID,
                          hng::contextattr attr)                       = 0;
};

#endif  //_CONTROL_PLANE_CONTEXTSERVICE_HPP