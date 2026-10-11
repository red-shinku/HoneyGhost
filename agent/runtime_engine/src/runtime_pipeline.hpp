/**
 * @file runtime_pipeline.hpp
 * @brief 语义事件 → 控制平面分派 → 事件草稿
 * @author red-shinku
 * @date 2026.10.11
 */
#ifndef HNG_RUNTIME_PIPELINE_HPP_
#define HNG_RUNTIME_PIPELINE_HPP_

#include <cstddef>
#include <cstdint>

#include "agent/context_maintainer/include/context_maintainer.hpp"
#include "agent/context_maintainer/include/context_maintainer_decision.hpp"
#include "agent/control_plane/include/process_service.hpp"
#include "agent/control_plane/include/role_service.hpp"
#include "agent/event_data/include/runtime_event.hpp"
#include "agent/util/include/spsc_queue.hpp"

/// @brief 一条待分发的事件，及本条事件引发的 context 派生决策
struct RuntimeDraft {
    hng::RuntimeEvent event;         ///< 已填齐运行时信息快照的事件
    ContextDeriveDecision decision;  ///< 本条事件的派生决策；无派生时为缺省值
};

/**
 * @brief 取出语义事件消费的流水线
 * @details 由引擎线程独占使用，自身不加锁。每轮按固定优先级轮询队列
 */
class RuntimePipeline {
   public:
    /// @param syscall_queue 系统调用语义队列，未接线传 nullptr
    /// @param file_queue 文件语义队列，未接线传 nullptr
    /// @param ctx_maintainer 上下文维护模块，非拥有
    /// @param process_join 控制平面进程注册接口，非拥有
    /// @param role_join 控制平面角色归属接口，非拥有
    /// @param role_lookup 控制平面角色查询接口，非拥有
    RuntimePipeline(hng::SPSC_Queue<hng::syscall_semantic_data>* syscall_queue,
                    hng::SPSC_Queue<hng::file_semantic_data>* file_queue,
                    ContextMaintainer* ctx_maintainer,
                    ProcessJoinService* process_join, RoleJoinService* role_join,
                    RoleLookupService* role_lookup);

    /// @brief 取一轮事件并组装草稿
    /// @param[out] out 本轮产物，槽位数不得少于已接线队列数；可跨轮复用
    /// @param[in] capacity out 的槽位数
    /// @return 本次写入的草稿条数
    std::size_t take_round(RuntimeDraft* out, std::size_t capacity);

   private:
    /// syscall 语义载荷的 variant 索引，与 hng::syscall_event_type 一一对应
    static constexpr std::size_t kProcessPayload = 0;
    static constexpr std::size_t kExecPayload    = 1;

    /// @brief 分派一条 syscall 语义事件并组装草稿
    void handle_syscall(hng::syscall_semantic_data src, RuntimeDraft& out);

    /// @brief 分派一条文件语义事件并组装草稿
    void handle_file(hng::file_semantic_data src, RuntimeDraft& out);

    /// @brief 角色归属快照，未归属时为 0
    uint32_t role_id_of(const hng::Process& p) const;

    /// @brief 上下文归属快照，未落定时为 0
    uint32_t context_id_of(const hng::Process& p) const;

    hng::SPSC_Queue<hng::syscall_semantic_data>* syscall_queue_ = nullptr;
    hng::SPSC_Queue<hng::file_semantic_data>* file_queue_       = nullptr;
    // TODO: 未来 ContextMaintainer 在栈上构造
    ContextMaintainer* ctx_maintainer_                          = nullptr;
    ProcessJoinService* process_join_                           = nullptr;
    RoleJoinService* role_join_                                 = nullptr;
    RoleLookupService* role_lookup_                             = nullptr;
};

#endif  // HNG_RUNTIME_PIPELINE_HPP_
