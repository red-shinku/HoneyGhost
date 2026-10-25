#include "agent/control_plane/include/process_component.hpp"

#include <utility>

#include "agent/control_plane/src/process_manager.hpp"

namespace hng {

struct ProcessComponent::Impl {
    ProcessManager manager;
};

ProcessComponent::ProcessComponent(std::unique_ptr<Impl> impl)
    : impl_(std::move(impl))
{
}

ProcessComponent::~ProcessComponent() = default;

ProcessLookupService& ProcessComponent::lookup_service() noexcept
{
    return static_cast<ProcessLookupService&>(impl_->manager);
}

ProcessJoinService& ProcessComponent::join_service() noexcept
{
    return static_cast<ProcessJoinService&>(impl_->manager);
}

ProcessUpdateService& ProcessComponent::update_service() noexcept
{
    return static_cast<ProcessUpdateService&>(impl_->manager);
}

ProcessLivenessService& ProcessComponent::liveness_service() noexcept
{
    return static_cast<ProcessLivenessService&>(impl_->manager);
}

ProcessSeedService& ProcessComponent::seed_service() noexcept
{
    return static_cast<ProcessSeedService&>(impl_->manager);
}

void ProcessComponent::add_process_lifecycle_sink(ProcessLifecycleSink* sink)
{
    impl_->manager.add_process_lifecycle_sink(sink);
}

void ProcessComponent::set_role_join_service(RoleJoinService* service)
{
    impl_->manager.set_role_join_service(service);
}

ProcessManagerStats ProcessComponent::stats() const
{
    return impl_->manager.stats();
}

hng::ComponentState ProcessComponent::state() const
{
    return impl_->manager.state();
}

void ProcessComponent::run() { impl_->manager.run(); }

void ProcessComponent::stop() { impl_->manager.stop(); }

std::unique_ptr<ProcessComponent> make_process_component()
{
    auto impl = std::make_unique<ProcessComponent::Impl>();
    return std::unique_ptr<ProcessComponent>(
        new ProcessComponent(std::move(impl)));
}

}  // namespace hng
