/**
 * @file semantic_file.cc
 * @brief 文件事件语义化处理器 实现
 * @details
 * 从文件原始事件队列取出 file_access_data，经 归一化 → 语义化 → 组装 后推入
 * 下游语义事件队列（RawEventQueue_SS<file_semantic_data>）。语义化逻辑位于
 * agent/semantic/path/ 规则引擎，本类只做编排与数据结构转换。
 *
 * @author red_shinku
 * @date 2026.08.14
 */

#include "./include/semantic.hpp"
#include "agent/semantic/path/include/path_normalizer.hpp"
#include "agent/semantic/path/include/path_rule.hpp"

#include <cstring>
#include <string>

Semantic_file::Semantic_file(hng::RawEventQueue_SS<struct file_access_data>& in_queue,
                             hng::RawEventQueue_SS<struct file_semantic_data>& out_queue)
    : raw_event_queue(in_queue), event_queue(out_queue)
{
}

Semantic_file::~Semantic_file() {}

/**
 * @brief 单条文件事件语义化
 * @details
 * 编排三步：归一化（消除拼写差异）→ 规则引擎语义化（消除实例性）→ 组装输出结构
 * 并推入下游队列。输出仅保留语义化文件名，不保留原始 filename。
 */
void Semantic_file::transform()
{
    file_access_data raw;
    if (!raw_event_queue.pop(raw)) {
        return;  // 输入队列空
    }

    // 归一化 → 语义化
    std::string norm;
    hng::path::normalize(raw.filename, norm);
    std::string sem;
    hng::path::semanticize(norm, sem);

    // 组装输出事件
    file_semantic_data ev;
    ev.head.head = raw.head;
    std::memcpy(ev.head.comm, raw.comm, sizeof(ev.head.comm));
    ev.data.set_semantic_filename(sem);
    ev.data.set_flags(raw.flags);
    ev.data.set_is_innamespace(raw.is_innamespace != 0);  // 内核侧采集（files.bpf.c）

    event_queue.push(ev);  // TODO: 下游队列满时丢事件，背压策略待定
}

/**
 * @brief 工作循环：持续消费文件原始事件
 * @details 忙轮询直到退出。TODO: 队列空时的调度让出与退出机制（决策点 H 暂缓）。
 */
void Semantic_file::work()
{
    while (true) {
        transform();
    }
}
