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

#include "agent/event_data/include/syscall_event.hpp"
#include "agent/detector/include/score.hpp"

/**
 * @brief 一个Context的活动数据
 * 一个 DetectContext 大致对应到一个 Context。这里
 * 的 Context 是设计文档中提到的概念
 * DetectContext 当前由系统调用语义链组成，以及各维度的异常分值，
 * 可以看作 Context 概念的具象。
 * @note 文件事件线已删除，文件访问维度随之移除；网络连接与 IPC 维度尚未定义。
 */
struct DetectContext {
    // TODO: 用于 Context 序列学习的 Context 标识，可能是其根进程的启动名？

    // 最近系统调用序列
    RecentSyscallSeq syscall_seq_recent;

    // TODO: 网络连接/IPC集合

    Score score;  ///< 多维度评分信息
};

struct RecentSyscallSeq {
    // TODO: 对于 N 阶马尔科夫序列，需要一个容量为 N 的环形缓冲区队列
};

#endif  // DETECT_CONTEXT_HPP_