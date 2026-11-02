/**
 * @file role_filter_component.cc
 * @brief 角色过滤组件：存活名额与名单维护器转发。
 */
#include "agent/role_filter/include/role_filter_component.hpp"

#include "agent/role_filter/include/role_filter_factory.hpp"
#include "agent/role_filter/src/role_filter.hpp"
#include "agent/util/include/single_instance_guard.hpp"

#include <atomic>
#include <memory>
#include <stdexcept>
#include <utility>

namespace hng {

struct RoleFilterComponent::Impl {
    /**
     * @brief 先占用存活名额，再把选项转交名单维护器。
     * @param taken 本创建方法的存活标志
     * @param options 借用的服务、策略、map 后端与刷新选项
     * @throws std::logic_error 名额已被占用
     * @pre options.lookup 与 options.map 非空
     */
    Impl(std::atomic<bool>& taken, RoleFilterComponentOptions options)
        : guard(taken, "RoleFilterComponent"),
          filter(*options.lookup, std::move(options.policy),
                 std::move(options.map), std::move(options.filter_options))
    {
        filter.set_supervision_service(options.supervision);
    }

    hng::detail::SingleInstanceGuard guard;
    RoleFilter filter;
};

RoleFilterComponent::RoleFilterComponent(std::unique_ptr<Impl> impl)
    : impl_(std::move(impl))
{
}

RoleFilterComponent::~RoleFilterComponent() = default;

::RoleLifecycleSink& RoleFilterComponent::lifecycle_sink() noexcept
{
    return static_cast<::RoleLifecycleSink&>(impl_->filter);
}

void RoleFilterComponent::seed_initial_roles()
{
    impl_->filter.seed_initial_roles();
}

void RoleFilterComponent::drain() { impl_->filter.drain(); }

void RoleFilterComponent::request_refresh() { impl_->filter.request_refresh(); }

void RoleFilterComponent::replace_policy(RoleFilterPolicy policy)
{
    impl_->filter.replace_policy(std::move(policy));
}

RoleFilterStats RoleFilterComponent::stats() const
{
    return impl_->filter.stats();
}

hng::ComponentState RoleFilterComponent::state() const
{
    return impl_->filter.state();
}

void RoleFilterComponent::run() { impl_->filter.run(); }

void RoleFilterComponent::stop() { impl_->filter.stop(); }

std::unique_ptr<RoleFilterComponent> RoleFilterFactory::create(
    RoleFilterComponentOptions options)
{
    if (options.lookup == nullptr) {
        throw std::invalid_argument("角色查询服务不可为空");
    }
    if (options.map == nullptr) throw std::invalid_argument("名单 map 不可为空");

    static std::atomic<bool> taken{false};
    auto impl =
        std::make_unique<RoleFilterComponent::Impl>(taken, std::move(options));
    return std::unique_ptr<RoleFilterComponent>(
        new RoleFilterComponent(std::move(impl)));
}

}  // namespace hng
