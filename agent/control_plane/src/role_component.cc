#include "agent/control_plane/include/role_component.hpp"

#include <atomic>
#include <utility>

#include "agent/control_plane/include/control_plane_factory.hpp"
#include "agent/control_plane/src/role_manager.hpp"
#include "agent/util/include/single_instance_guard.hpp"

namespace hng {

struct RoleComponent::Impl {
    /**
     * @brief 先占用存活名额，再把探针转交角色管理器。
     * @param probe cgroup 读取与存活核对的注入点
     * @param taken 本创建方法的存活标志
     * @throws std::logic_error 名额已被占用
     */
    Impl(RoleManagerProbe probe, std::atomic<bool>& taken)
        : guard(taken, "RoleComponent"), manager(std::move(probe))
    {
    }

    hng::detail::SingleInstanceGuard guard;
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

RoleSeedService& RoleComponent::seed_service() noexcept
{
    return static_cast<RoleSeedService&>(impl_->manager);
}

void RoleComponent::drain() { impl_->manager.drain(); }

bool RoleComponent::barrier(std::chrono::milliseconds timeout)
{
    return impl_->manager.barrier(timeout);
}

ProcessLifecycleSink& RoleComponent::lifecycle_sink() noexcept
{
    return static_cast<ProcessLifecycleSink&>(impl_->manager);
}

hng::role::RoleEventSink& RoleComponent::event_sink() noexcept
{
    return static_cast<hng::role::RoleEventSink&>(impl_->manager);
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

std::unique_ptr<RoleComponent> ControlPlaneFactory::create_role(
    RoleComponentOptions options)
{
    static std::atomic<bool> taken{false};

    RoleManagerProbe probe;
    probe.read_members = std::move(options.read_members);
    probe.is_exited    = std::move(options.is_exited);
    auto impl = std::make_unique<RoleComponent::Impl>(std::move(probe), taken);
    return std::unique_ptr<RoleComponent>(new RoleComponent(std::move(impl)));
}

}  // namespace hng
