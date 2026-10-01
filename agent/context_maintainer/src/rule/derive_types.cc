/**
 * @file derive_types.cc
 * @brief 派生纯判定逻辑实现：解释器家族判定与 decide_exec
 * @author red_shinku
 * @date 2026.9.5
 */

#include "agent/context_maintainer/src/rule/derive_types.hpp"

#include <array>
#include <string_view>

namespace hng {
namespace detail {
namespace {

/// 解释器家族表。全路径与 basename 两层命中。
/// 列为 shell / 脚本解释器 / 语言运行时的典型安装路径。
constexpr std::array<std::string_view, 13> kInterpreterPaths = {
    "/bin/sh",         "/bin/bash",        "/bin/dash",
    "/bin/zsh",        "/bin/ksh",         "/bin/ash",
    "/usr/bin/fish",                                         // Shell
    "/usr/bin/python", "/usr/bin/python3", "/usr/bin/perl",  // 语言运行时
    "/usr/bin/ruby",   "/usr/bin/node",    "/usr/bin/php",
};

/// 对应的 basename 集合：覆盖符号链接、busybox 别名、非常规安装路径。
constexpr std::array<std::string_view, 13> kInterpreterBasenames = {
    "sh",     "bash",    "dash", "zsh",  "ksh",  "ash", "fish",
    "python", "python3", "perl", "ruby", "node", "php",
};

}  // namespace

bool is_interpreter_exec(const std::string& normalized_filename)
{
    for (auto path : kInterpreterPaths) {
        if (path == normalized_filename) {
            return true;
        }
    }
    // basename：最后一个 '/' 之后的子串（无 '/' 时为整串）
    std::string_view base(normalized_filename);
    const auto slash = normalized_filename.find_last_of('/');
    if (slash != std::string::npos) {
        base.remove_prefix(slash + 1);
    }
    for (auto name : kInterpreterBasenames) {
        if (name == base) {
            return true;
        }
    }
    return false;
}

DeriveVerdict decide_exec(hng::Process child, hng::Process parent,
                          bool parent_context_is_interpreter,
                          const std::string& normalized_filename)
{
    DeriveVerdict v;  // derive=false, reason=NONE（KEEP）
    v.child  = child;
    v.parent = parent;

    // 解释器 exec → DERIVE（解释器自身即新执行上下文，不随 argv 细分）
    if (is_interpreter_exec(normalized_filename)) {
        v.derive = true;
        v.reason = DeriveReason::EXEC_INTERPRETER;
        return v;
    }
    // 普通命令且父 context 为解释器 → KEEP（会话内一次性命令）
    if (parent_context_is_interpreter) {
        return v;
    }
    // 其余 → 默认派生
    v.derive = true;
    v.reason = DeriveReason::EXEC_UNMATCHED_DEFAULT;
    return v;
}

}  // namespace detail
}  // namespace hng
