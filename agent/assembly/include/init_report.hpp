/**
 * @file init_report.hpp
 * @brief 初始化的总状态与落地报告
 * @details 由装配层的初始化协调器填写并返回；控制面组件不感知该类型。
 * @author red_shinku
 * @date 2026.10.25
 */

#ifndef HNG_ASSEMBLY_INIT_REPORT_HPP_
#define HNG_ASSEMBLY_INIT_REPORT_HPP_

#include <cstdint>

#include "agent/control_plane/include/context_seed_service.hpp"
#include "agent/control_plane/include/process_seed_service.hpp"
#include "agent/control_plane/include/role_seed_service.hpp"
#include "agent/event_data/include/process_seed.hpp"
#include "agent/role_filter/include/role_filter_component.hpp"

namespace hng {

/**
 * @brief 一次初始化的总状态
 * @details 状态只描述初始化写入的结果，不描述组件线程是否已启动。
 */
enum class InitState : uint8_t {
    INITIALIZING,  ///< 尚未执行或正在执行
    READY,         ///< 全部初始化写入落地，无异常
    DEGRADED,      ///< 角色源不可用/超时、map 写入失败或初始化期丢事件
    PARTIAL,       ///< 快照只读到一部分
    UNAVAILABLE,   ///< /proc 不可用，以空状态继续
    FAILED         ///< 初始化写入被拒或计划乱序；不得启动引擎
};

/**
 * @brief 一次初始化的全部落地结果
 * @details 各字段取自对应组件的一次写入；未执行的步骤保持默认值。
 */
struct InitReport {
    InitState state = InitState::INITIALIZING;  ///< 聚合后的总状态
    ProcessSnapshotAnomalies snapshot;          ///< 本次快照的异常态计数
    ProcessSeedReport process;                  ///< PM seed 的落地统计
    RoleReconcileReport role;                   ///< RM 对账的落地统计
    ContextSeedReport context;                  ///< CM seed 的落地统计
    RoleFilterStats role_filter;                ///< 名单播种与成员应用后的统计
    uint64_t role_source_timeout = 0;           ///< 1 表示等待角色源时超时
    /// @brief 初始化期丢弃的事件数；计数尚未接入时固定为 0
    uint64_t dropped_events      = 0;
};

/**
 * @brief 按严重度合并两个初始化状态
 * @details 优先级 FAILED > UNAVAILABLE > PARTIAL > DEGRADED > READY >
 *          INITIALIZING；结果与参数顺序无关。
 * @param lhs 已累计的状态
 * @param rhs 本次要并入的状态
 * @return 两者中更严重的一个
 */
InitState merge_init_state(InitState lhs, InitState rhs);

/// @brief 状态的可读名称
/// @return 静态字符串，与枚举值一一对应
const char* to_string(InitState state);

}  // namespace hng

#endif  // HNG_ASSEMBLY_INIT_REPORT_HPP_
