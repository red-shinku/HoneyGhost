/**
 * @file process_seed_service.hpp
 * @brief 进程树的初始化写入接口
 * @details 初始化期同步批量写入，不经通知队列；process_manager.hpp 中
 *          ProcessManager 实现该接口。
 * @author red_shinku
 * @date 2026.10.25
 */

#ifndef HNG_PROCESS_SEED_SERVICE_HPP_
#define HNG_PROCESS_SEED_SERVICE_HPP_

#include <cstdint>

#include "agent/event_data/include/process_seed.hpp"

/// @brief 一次进程树初始化的落地统计
struct ProcessSeedReport {
    uint64_t inserted       = 0;  ///< 实际插入的进程条数
    uint64_t duplicate      = 0;  ///< 批内重复身份；首条落地
    uint64_t pid_reused     = 0;  ///< 同 pid 不同身份；保留 start_time 较大者
    uint64_t parent_missing = 0;  ///< 父不在批内；不建立父计数
    uint64_t invalid        = 0;  ///< pid 或 start_time 为 0
    uint64_t rejected_state = 0;  ///< 非 CONSTRUCTED 时的 seed 调用
};

/// @brief 进程树初始化写入接口
/// @details 同步、直接写入，不调用其它服务、不发通知；调用方在 run() 之前使用。
class ProcessSeedService {
   protected:
    virtual ~ProcessSeedService() = default;

   public:
    /// @brief 用一次快照批量构造初始进程树
    /// @param batch 初始进程批次
    /// @return 落地统计；正常返回时写入对查询方可见
    /// @pre 组件为 CONSTRUCTED；只调用一次
    virtual ProcessSeedReport seed(const hng::ProcessSeedBatch& batch) = 0;
};

#endif  // HNG_PROCESS_SEED_SERVICE_HPP_
