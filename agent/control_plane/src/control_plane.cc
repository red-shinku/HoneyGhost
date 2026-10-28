#include "agent/control_plane/include/control_plane.hpp"

#include <utility>

#include "agent/control_plane/include/context_component.hpp"
#include "agent/control_plane/include/control_plane_factory.hpp"
#include "agent/control_plane/include/process_component.hpp"
#include "agent/control_plane/include/role_component.hpp"

namespace hng {

ControlPlane::ControlPlane(std::unique_ptr<RoleComponent> role,
                           std::unique_ptr<ProcessComponent> process,
                           std::unique_ptr<ContextComponent> context)
    : context_(std::move(context)),
      role_(std::move(role)),
      process_(std::move(process))
{
    process_->set_role_join_service(&role_->join_service());
    process_->add_process_lifecycle_sink(&context_->lifecycle_sink());
    process_->add_process_lifecycle_sink(&role_->lifecycle_sink());
}

ControlPlane::~ControlPlane() = default;

RoleComponent& ControlPlane::role() noexcept { return *role_; }

ProcessComponent& ControlPlane::process() noexcept { return *process_; }

ContextComponent& ControlPlane::context() noexcept { return *context_; }

std::unique_ptr<ControlPlane> ControlPlaneFactory::create(
    RoleComponentOptions options)
{
    auto role    = create_role(std::move(options));
    auto process = create_process();
    auto context = create_context();
    return std::unique_ptr<ControlPlane>(new ControlPlane(
        std::move(role), std::move(process), std::move(context)));
}

}  // namespace hng
