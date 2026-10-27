/**
 * @file semantic_file.cc
 * @brief 文件事件语义化工具实现
 * @details
 * 归一化 → 语义化 → 组装。语义化逻辑位于 agent/semantic/path/ 规则引擎，
 * 本工具只做转换，不持有队列与线程状态。
 * @author red_shinku
 * @date 2026.08.14
 */

#include "agent/semantic/src/semantic.hpp"
#include "agent/semantic/src/path/path_normalizer.hpp"
#include "agent/semantic/src/path/path_rule.hpp"

#include <string>

void Semantic_file::transform_one(const file_access_data& raw,
                                  hng::file_semantic_data& ev) const
{
    // 归一化 → 语义化
    std::string norm;
    hng::path::normalize(raw.filename, norm);
    std::string sem;
    hng::path::semanticize(norm, sem);

    ev.head.pid             = raw.head.pid;
    ev.head.pid_start_time  = raw.head.pid_start_time;
    ev.head.ppid            = raw.head.ppid;
    ev.head.ppid_start_time = raw.head.ppid_start_time;
    ev.head.type            = hng::EventType::FILE_EVENT;

    ev.data.set_semantic_filename(sem);
    ev.data.set_comm(
        raw.comm);  // 发起文件访问的进程名（内核侧采集，files.bpf.c）
    ev.data.set_flags(raw.flags);
    ev.data.set_is_innamespace(raw.is_innamespace !=
                               0);  // 内核侧采集（files.bpf.c）
}
