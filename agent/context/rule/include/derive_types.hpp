/**
 * @file derive_types.hpp
 * @brief 基于exec信息的 context 派生决策
 * @details
 * 本文件定义派生决策结果 DeriveVerdict，以及依据 exec 信息做 KEEP/DERIVE
 * 判定的纯函数 decide_exec 与解释器家族判定 is_interpreter_exec。
 * 纯判定不依赖窗口等状态；fork 登记的窗口逻辑见 pending_table。
 * @author red_shinku
 * @date 2026.9.5
 */

#ifndef HNG_RULE_DERIVE_TYPES_HPP_
#define HNG_RULE_DERIVE_TYPES_HPP_

#include <cstdint>
#include <string>

#include "agent/event_data/process.hpp"

namespace hng {
namespace rule {

/// 派生决策的原因。reason 仅当 DeriveVerdict::derive 为 true 时有效，KEEP 时为
/// NONE。
enum class DeriveReason : uint8_t {
    NONE,              ///< 占位：KEEP（derive=false）时的无效值
    EXEC_INTERPRETER,  ///< exec 目标属解释器家族（shell/脚本解释器/语言运行时）
    EXEC_UNMATCHED_DEFAULT,  ///< exec 目标未命中 KEEP，默认派生
    NO_EXEC_WINDOW,          ///< 窗口期内无 exec，事件配额耗尽
};

/**
 * @brief 一次派生决策的结果
 * @details KEEP（不派生）表示该新进程无新执行上下文，事件留在父 context；
 * DERIVE 表示应为其派生新 context。上层据 result 决定是否创建 context，
 * 并以 parent 解析新 context 的父 contextID。
 */
struct DeriveVerdict {
    bool derive         = false;  ///< true=派生新 context；false=KEEP
    DeriveReason reason = DeriveReason::NONE;  ///< derive 为 true 时的原因
    hng::Process child  = {};                  ///< 决策对象（fork 产生的新进程）
    hng::Process parent = {};                  ///< 父进程
};

/**
 * @brief 判断某 exec 目标是否属于解释器家族
 * @details 归一化全路径或 basename 命中家族表即判为解释器。路径表为已知的
 * shell/脚本解释器/语言运行时安装路径；basename 命中覆盖符号链接、busybox 等
 * 以别名执行的解释器。不在表中的（复制改名等）不会命中 → 落入默认派生。
 * @param normalized_filename 语义化归一后的可执行文件路径
 */
bool is_interpreter_exec(const std::string& normalized_filename);

/**
 * @brief 依据 exec 信息做派生判定
 * @details 判定优先级：解释器 exec → DERIVE；普通命令且父 context 为解释器
 * 上下文 → KEEP；其余 → DERIVE（未命中 KEEP 一律派生）。
 * @param child 决策对象
 * @param parent 父进程
 * @param parent_context_is_interpreter 父进程所在 context 是否解释器上下文
 * @param normalized_filename 归一后的 exec 目标路径
 * @return 决策结果（含 reason）
 */
DeriveVerdict decide_exec(hng::Process child, hng::Process parent,
                          bool parent_context_is_interpreter,
                          const std::string& normalized_filename);

}  // namespace rule
}  // namespace hng

#endif  // HNG_RULE_DERIVE_TYPES_HPP_
