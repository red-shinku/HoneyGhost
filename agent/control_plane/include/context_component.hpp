/**
 * @file context_component.hpp
 * @brief 上下文管理组件的公共句柄
 * @details 装配层经工厂构造并持有该句柄；具体 ContextManager 仍在 src/。
 * @author red_shinku
 * @date 2026.10.25
 */

#ifndef HNG_CONTEXT_COMPONENT_HPP_
#define HNG_CONTEXT_COMPONENT_HPP_

#include <memory>

#include "agent/control_plane/include/context_service.hpp"
#include "agent/control_plane/include/context_stats.hpp"
#include "agent/control_plane/include/process_lifecycle_sink.hpp"
#include "agent/util/include/component.hpp"

namespace hng {

/**
 * @brief 上下文管理组件
 * @details 提供 context 查询、注册与更新服务，并转发组件的生命周期。组件
 *          自身不持线程。
 * @see hng::Component
 */
class ContextComponent final : public hng::Component {
   public:
    ~ContextComponent() override;

    ContextComponent(const ContextComponent&)            = delete;
    ContextComponent& operator=(const ContextComponent&) = delete;

    /// @brief context 查询服务
    /// @see ContextLookupService
    ContextLookupService& lookup_service() noexcept;

    /// @brief context 注册与挂靠服务
    /// @see ContextJoinService
    ContextJoinService& join_service() noexcept;

    /// @brief context 属性更新服务
    /// @see ContextUpdateService
    ContextUpdateService& update_service() noexcept;

    /// @brief 进程退出的下游接收方
    /// @note 供进程管理组件的装配者登记，须存活到 run() 返回之后
    ProcessLifecycleSink& lifecycle_sink() noexcept;

    /// @brief 异常态观测快照
    /// @see ContextManagerStats
    ContextManagerStats stats() const;

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

    explicit ContextComponent(std::unique_ptr<Impl> impl);

    friend std::unique_ptr<ContextComponent> make_context_component();

    std::unique_ptr<Impl> impl_;
};

/// @brief 构造上下文管理组件
/// @return 状态为 CONSTRUCTED 的组件；服务接口可直接取用
std::unique_ptr<ContextComponent> make_context_component();

}  // namespace hng

#endif  // HNG_CONTEXT_COMPONENT_HPP_
