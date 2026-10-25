/**
 * @file proc_snapshot.hpp
 * @brief /proc 快照读取器
 * @details 只被装配层的启动流程使用，读取结果与异常态计数一起交给进程树的
 *          seed。测试可注入伪造的 /proc 根目录。
 * @author red_shinku
 * @date 2026.10.25
 */

#ifndef HNG_ASSEMBLY_PROC_SNAPSHOT_HPP_
#define HNG_ASSEMBLY_PROC_SNAPSHOT_HPP_

#include <string>

#include "agent/event_data/include/process_seed.hpp"

/**
 * @brief 读取一次 /proc 进程快照
 * @details 跳过僵尸（Z/X）与内核线程（PF_KTHREAD）；comm 以最后一个 ')' 为
 *          界；父 starttime 在已读集合内二次解析。不保证条目顺序。
 */
class ProcessSnapshotReader {
   public:
    /// @param proc_root /proc 的根路径；测试可注入临时目录
    explicit ProcessSnapshotReader(std::string proc_root = "/proc");

    /**
     * @brief 读取一次快照
     * @return 已过滤的批次与本次异常态计数；根目录不可读时 proc_available
     *         为 false 且 batch.complete 为 false
     * @note 目录读取不完整时 batch.complete 为 false，已读条目保留
     */
    hng::ProcessSnapshot read() const;

   private:
    std::string proc_root_;
};

#endif  // HNG_ASSEMBLY_PROC_SNAPSHOT_HPP_
