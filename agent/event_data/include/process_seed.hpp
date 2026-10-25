/**
 * @file process_seed.hpp
 * @brief /proc 快照与进程树初始化 seed 共享的数据类型
 * @details 快照读取器、装配层与 ProcessSeedService 共同使用；不依赖控制平面。
 * @author red_shinku
 * @date 2026.10.25
 */

#ifndef HNG_PROCESS_SEED_HPP_
#define HNG_PROCESS_SEED_HPP_

#include <cstdint>
#include <string>
#include <vector>

#include "agent/event_data/include/process.hpp"

namespace hng {

/// @brief 一个进程的初始化描述
/// @details 身份由 process 的 (pid, pid_start_time) 决定；父进程的 pid 与
///          start_time 未知时为 0。
struct ProcessSeedEntry {
    Process process{};             ///< (pid, pid_start_time)
    uint32_t ppid            = 0;  ///< 父 pid；未知为 0
    uint64_t ppid_start_time = 0;  ///< 父启动时间；未知为 0
    std::string exe;  ///< /proc/<pid>/exe 的 readlink 结果；不可读为空
};

/// @brief 一次快照读到的进程批次
struct ProcessSeedBatch {
    /// @details 约定每个身份至多一条、每个 pid 至多一条；违反约定由 seed 统计
    std::vector<ProcessSeedEntry> entries;
    bool complete = true;  ///< false 表示只读到一部分
};

/// @brief 快照读取的异常态计数
/// @details 字段均为本次读取的计数。
struct ProcessSnapshotAnomalies {
    bool proc_available        = true;  ///< false：/proc 根不可读
    uint64_t proc_seen         = 0;     ///< 数字目录条目数
    uint64_t zombie_skipped    = 0;     ///< state 为 Z/X 而跳过的进程
    uint64_t kthread_skipped   = 0;     ///< 带 PF_KTHREAD 而跳过的内核线程
    uint64_t stat_parse_failed = 0;     ///< stat 打开（除 ENOENT）或解析失败
    uint64_t exe_unreadable    = 0;     ///< exe 链接不可读
    uint64_t parent_missing    = 0;     ///< 父进程不在本次快照中
};

/// @brief 一次 /proc 快照的结果
struct ProcessSnapshot {
    ProcessSeedBatch batch;              ///< 已过滤的进程批次
    ProcessSnapshotAnomalies anomalies;  ///< 本次读取的异常态计数
};

}  // namespace hng

#endif  // HNG_PROCESS_SEED_HPP_
