#include "agent/control_plane/include/context_component.hpp"

#include <utility>

#include "agent/control_plane/src/context_manager.hpp"

namespace hng {

struct ContextComponent::Impl {
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

std::unique_ptr<ContextComponent> make_context_component()
{
    auto impl = std::make_unique<ContextComponent::Impl>();
    return std::unique_ptr<ContextComponent>(
        new ContextComponent(std::move(impl)));
}

}  // namespace hng
