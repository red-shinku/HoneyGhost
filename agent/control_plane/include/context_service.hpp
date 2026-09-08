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

/**
 * @brief 查询 Context 的接口
 * 1) 查询 contextID
 * 2) 查询 extra_contextID
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
    /// @brief 其他组件通知注册新的 contextID
    /// @param p context代表进程的唯一性表示
    /// @param newcontext 新的 context 及其信息，由工作平面 context 维护工具生成
    /// @param pcontextID 父 context ID
    virtual void register_contextID(hng::Process p,
                                    ContextDeriveDecision newcontext,
                                    uint32_t pcontextID)              = 0;

    /// @brief 其他组件通知注销 contextID
    /// @param p context代表进程的唯一性表示
    virtual void unregister_contextID(hng::Process p)                 = 0;

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

/**
 * @brief 清理 ContextManager 内关系数据的接口
 * 1) 尝试删除与某进程相关的管理器内部条目
 */
class ContextClearService {
   protected:
    virtual ~ContextClearService() = default;

   public:
    /// @brief 当进程被删除时，清理相关条目
    virtual void on_process_removed(hng::Process p) = 0;
};

#endif  //_CONTROL_PLANE_CONTEXTSERVICE_HPP