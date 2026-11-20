/**
 * @file runtime_pipeline.cc
 * @brief 流水线的第一段实现
 * @author red-shinku
 * @date 2026.10.11
 */

#include "agent/runtime_engine/src/runtime_pipeline.hpp"

#include <optional>
#include <utility>
#include <variant>

#include "agent/runtime_engine/src/runtime_packaging.hpp"

namespace {

/// 进程生命周期载荷中表示退出的语义名（与语义模块 syscall_name_str 一致）
constexpr char kExitGroupName[] = "exit_group";

}  // namespace

RuntimePipeline::RuntimePipeline(
    hng::EventChannelReader<hng::syscall_semantic_data>* syscall_input,
    ContextMaintainer* ctx_maintainer, ProcessJoinService* process_join,
    ProcessUpdateService* process_update, ProcessLookupService* process_lookup,
    RoleJoinService* role_join, RoleLookupService* role_lookup)
    : syscall_input_(syscall_input),
      ctx_maintainer_(ctx_maintainer),
      process_join_(process_join),
      process_update_(process_update),
      process_lookup_(process_lookup),
      role_join_(role_join),
      role_lookup_(role_lookup)
{
}

std::size_t RuntimePipeline::take_round(RuntimeDraft* out, std::size_t capacity)
{
    if (syscall_input_ == nullptr || capacity == 0) {
        return 0;
    }

    hng::syscall_semantic_data src;
    if (!syscall_input_->try_pop(src)) {
        return 0;
    }
    handle_syscall(std::move(src), out[0]);
    return 1;
}

int RuntimePipeline::syscall_fd() const noexcept
{
    return syscall_input_ == nullptr ? -1 : syscall_input_->fd();
}

std::uint64_t RuntimePipeline::syscall_dropped() const noexcept
{
    return syscall_input_ == nullptr
               ? 0
               : syscall_input_->dropped() + syscall_input_->rejected();
}

void RuntimePipeline::handle_syscall(hng::syscall_semantic_data src,
                                     RuntimeDraft& out)
{
    const hng::Process self{src.head.pid, src.head.pid_start_time};
    const hng::Process parent{src.head.ppid, src.head.ppid_start_time};

    ContextDeriveDecision decision{};
    switch (src.data.index()) {
        case kProcessPayload: {
            // 诞生与退出共用一种载荷，以语义名区分（头即主体进程自身）
            const hng::process_semantic_data& payload =
                std::get<hng::process_semantic_data>(src.data);
            if (payload.syscall_name() == kExitGroupName) {
                process_join_->unregister_pid(self);
                ctx_maintainer_->on_exit(self);
            }
            else {
                process_join_->register_pid(src.head);
                role_join_->bind_to_role(self, parent);
                ctx_maintainer_->on_birth(self, parent);
            }
            break;
        }
        case kExecPayload: {
            const hng::exec_semantic_data& payload =
                std::get<hng::exec_semantic_data>(src.data);
            // 进程镜像落库真实绝对路径；语义化路径只供规则与基线
            process_update_->update_exe_image(self, payload.image());
            decision = ctx_maintainer_->should_derive_context(
                self, parent, payload.semantic_filename());
            break;
        }
        default: {
            decision = ctx_maintainer_->on_event(self);
            break;
        }
    }

    RoleSnapshot role = role_of(self, parent);
    std::string exe   = exe_of(src, self, parent);
    out.event =
        RuntimePackaging::pack(std::move(src), role.id, std::move(role.label),
                               context_id_of(self), std::move(exe));
    out.decision = decision;
}

std::string RuntimePipeline::exe_of(const hng::syscall_semantic_data& src,
                                    const hng::Process& self,
                                    const hng::Process& parent) const
{
    // 1. EXEC 事件自身刚换上的镜像：不等 update_exe_image 异步落库
    if (src.data.index() == kExecPayload) {
        const hng::exec_semantic_data& payload =
            std::get<hng::exec_semantic_data>(src.data);
        if (!payload.image().empty()) {
            return payload.image();
        }
    }
    if (process_lookup_ == nullptr) {
        return {};
    }
    // 2. 事件主体已落库的镜像
    const std::optional<hng::ProcessMessage> own = process_lookup_->lookup(self);
    if (own.has_value() && !own->exe.empty()) {
        return own->exe;
    }
    // 3. fork 的子进程与父同镜像，覆盖新进程尚未落库的窗口
    if (parent.pid == 0 || parent.pid_start_time == 0 || parent == self) {
        return {};
    }
    const std::optional<hng::ProcessMessage> up = process_lookup_->lookup(parent);
    if (up.has_value() && !up->exe.empty()) {
        return up->exe;
    }
    // 4. 都未知：DETAIL 不呈现
    return {};
}

RuntimePipeline::RoleSnapshot RuntimePipeline::role_of(
    const hng::Process& p) const
{
    const std::optional<uint32_t> role_id = role_lookup_->lookup(p);
    if (!role_id.has_value()) {
        return {};
    }

    RoleSnapshot snapshot;
    snapshot.id = *role_id;
    if (const std::optional<hng::Role> role = role_lookup_->role(*role_id)) {
        snapshot.label = role->roleLabel;
    }
    return snapshot;
}

RuntimePipeline::RoleSnapshot RuntimePipeline::role_of(
    const hng::Process& p, const hng::Process& parent) const
{
    const RoleSnapshot own = role_of(p);
    if (own.id != 0) {
        return own;
    }
    if (parent.pid == 0 || parent.pid_start_time == 0 || parent == p) {
        return {};
    }
    return role_of(parent);
}

uint32_t RuntimePipeline::context_id_of(const hng::Process& p) const
{
    return ctx_maintainer_->lookup_contextID(p).value_or(0);
}
