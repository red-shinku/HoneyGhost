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
    hng::SPSC_Queue<hng::syscall_semantic_data>* syscall_queue,
    hng::SPSC_Queue<hng::file_semantic_data>* file_queue,
    ContextMaintainer* ctx_maintainer, ProcessJoinService* process_join,
    ProcessUpdateService* process_update, RoleJoinService* role_join,
    RoleLookupService* role_lookup)
    : syscall_queue_(syscall_queue),
      file_queue_(file_queue),
      ctx_maintainer_(ctx_maintainer),
      process_join_(process_join),
      process_update_(process_update),
      role_join_(role_join),
      role_lookup_(role_lookup)
{
}

std::size_t RuntimePipeline::take_round(RuntimeDraft* out, std::size_t capacity)
{
    // 固定优先级 syscall → file：每条各取至多一条，高优先级队列再满也不占
    // 低优先级队列的名额
    std::size_t taken = 0;

    if (syscall_queue_ != nullptr && taken < capacity) {
        hng::syscall_semantic_data src;
        if (syscall_queue_->pop(src)) {
            handle_syscall(std::move(src), out[taken]);
            ++taken;
        }
    }

    if (file_queue_ != nullptr && taken < capacity) {
        hng::file_semantic_data src;
        if (file_queue_->pop(src)) {
            handle_file(std::move(src), out[taken]);
            ++taken;
        }
    }

    return taken;
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
            process_update_->update_exe_image(self, payload.semantic_filename());
            decision = ctx_maintainer_
                           ->should_derive_context(self, parent,
                                                   payload.semantic_filename())
                           .value_or(ContextDeriveDecision{});
            break;
        }
        default: {
            decision =
                ctx_maintainer_->on_event(self).value_or(ContextDeriveDecision{});
            break;
        }
    }

    RoleSnapshot role = role_of(self);
    out.event         = RuntimePackaging::pack(
        std::move(src), role.id, std::move(role.label), context_id_of(self));
    out.decision = decision;
}

void RuntimePipeline::handle_file(hng::file_semantic_data src, RuntimeDraft& out)
{
    const hng::Process self{src.head.pid, src.head.pid_start_time};

    const ContextDeriveDecision decision =
        ctx_maintainer_->on_event(self).value_or(ContextDeriveDecision{});

    RoleSnapshot role = role_of(self);
    out.event         = RuntimePackaging::pack(
        std::move(src), role.id, std::move(role.label), context_id_of(self));
    out.decision = decision;
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

uint32_t RuntimePipeline::context_id_of(const hng::Process& p) const
{
    return ctx_maintainer_->lookup_contextID(p).value_or(0);
}
