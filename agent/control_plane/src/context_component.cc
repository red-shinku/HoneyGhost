#include "agent/control_plane/include/context_component.hpp"

#include <atomic>
#include <utility>

#include "agent/control_plane/include/control_plane_factory.hpp"
#include "agent/control_plane/src/context_manager.hpp"
#include "agent/util/include/single_instance_guard.hpp"

namespace hng {

struct ContextComponent::Impl {
    /**
     * @brief 先占用存活名额，再构造上下文管理器。
     * @param taken 本创建方法的存活标志
     * @throws std::logic_error 名额已被占用
     */
    explicit Impl(std::atomic<bool>& taken) : guard(taken, "ContextComponent") {}

    hng::detail::SingleInstanceGuard guard;
    ContextManager manager;
};

ContextComponent::ContextComponent(std::unique_ptr<Impl> impl)
    : impl_(std::move(impl))
{
}

ContextComponent::~ContextComponent() = default;

ContextLookupService& ContextComponent::lookup_service() noexcept
{
    return static_cast<ContextLookupService&>(impl_->manager);
}

ContextJoinService& ContextComponent::join_service() noexcept
{
    return static_cast<ContextJoinService&>(impl_->manager);
}

ContextUpdateService& ContextComponent::update_service() noexcept
{
    return static_cast<ContextUpdateService&>(impl_->manager);
}

ContextSeedService& ContextComponent::seed_service() noexcept
{
    return static_cast<ContextSeedService&>(impl_->manager);
}

ProcessLifecycleSink& ContextComponent::lifecycle_sink() noexcept
{
    return static_cast<ProcessLifecycleSink&>(impl_->manager);
}

ContextManagerStats ContextComponent::stats() const
{
    return impl_->manager.stats();
}

hng::ComponentState ContextComponent::state() const
{
    return impl_->manager.state();
}

void ContextComponent::run() { impl_->manager.run(); }

void ContextComponent::stop() { impl_->manager.stop(); }

std::unique_ptr<ContextComponent> ControlPlaneFactory::create_context()
{
    static std::atomic<bool> taken{false};
    auto impl = std::make_unique<ContextComponent::Impl>(taken);
    return std::unique_ptr<ContextComponent>(
        new ContextComponent(std::move(impl)));
}

}  // namespace hng
