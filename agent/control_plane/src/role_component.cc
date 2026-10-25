#include "agent/control_plane/include/role_component.hpp"

#include <utility>

#include "agent/control_plane/src/role_manager.hpp"

namespace hng {

struct RoleComponent::Impl {
    RoleManager manager;
};

RoleComponent::RoleComponent(std::unique_ptr<Impl> impl) : impl_(std::move(impl))
{
}

RoleComponent::~RoleComponent() = default;

RoleLookupService& RoleComponent::lookup_service() noexcept
{
    return static_cast<RoleLookupService&>(impl_->manager);
}

RoleJoinService& RoleComponent::join_service() noexcept
{
    return static_cast<RoleJoinService&>(impl_->manager);
}

RoleSupervisionService& RoleComponent::supervision_service() noexcept
{
    return static_cast<RoleSupervisionService&>(impl_->manager);
}

ProcessLifecycleSink& RoleComponent::lifecycle_sink() noexcept
{
    return static_cast<ProcessLifecycleSink&>(impl_->manager);
}

void RoleComponent::add_lifecycle_sink(RoleLifecycleSink* sink)
{
    impl_->manager.add_lifecycle_sink(sink);
}

RoleManagerStats RoleComponent::stats() const { return impl_->manager.stats(); }

hng::ComponentState RoleComponent::state() const
{
    return impl_->manager.state();
}

void RoleComponent::run() { impl_->manager.run(); }

void RoleComponent::stop() { impl_->manager.stop(); }

std::unique_ptr<RoleComponent> make_role_component()
{
    auto impl = std::make_unique<RoleComponent::Impl>();
    return std::unique_ptr<RoleComponent>(new RoleComponent(std::move(impl)));
}

}  // namespace hng
