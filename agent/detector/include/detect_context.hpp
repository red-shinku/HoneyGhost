/**
 * @file detect_context.hpp
 * @brief 异常检测模块维护的上下文数据
 * 包含实时的事件信息。
 * 需要声明的是，异常评分以一个 DetectContext 为单位进行。
 * @author red_shinku
 * @date 2026.9.2
 */

#ifndef DETECT_CONTEXT_HPP_
#define DETECT_CONTEXT_HPP_

#include <unordered_set>

#include "agent/event_data/file_event.hpp"
#include "agent/event_data/syscall_event.hpp"

/**
 * @brief 一个Context的活动数据
 * 一个 DetectContext 大致对应到一个 Context。
 * 相比之下 Context 较狭义，其上下文信息只是系统调用语义链。
 * DetectContext 则是由系统调用语义链、文件访问、
 * 网络连接、IPC 这四个维度组成的上下文，以及其中各维度的
 * 异常分值
 */
struct DetectContext {
    // TODO: 用于 Context 序列学习的 Context 标识，可能是其根进程的启动名？

    // 最近系统调用序列与异常分值
    RecentSyscallSeq syscall_seq_recent;
    float syscall_seq_score = 0.0f;

    // 实时文件访问集合与异常分值
    std::unordered_set<hng::file_semantic_data> file_visiting_list;
    float file_visiting_score = 0.0f;

    // TODO: 网络连接/IPC集合
};

struct RecentSyscallSeq {
    // TODO: 对于 N 阶马尔科夫序列，需要一个容量为 N 的环形缓冲区队列
};

#endif  // DETECT_CONTEXT_HPP_