/**
 * @file detector.hpp
 * @brief 异常检测模块
 * @author red_shinku
 * @date 2026.9.2
 */

#ifndef DETECTOR_HPP_
#define DETECTOR_HPP_

#include <unordered_map>
#include <cstdint>

#include "agent/detector/include/detect_context.hpp"
#include "agent/util/include/spsc_queue.hpp"

/**
 * @brief 异常检测器
 * 接受到来的事件，找到其所属的 DetectContext，并更新异常评分。
 * @details
 * 注意：异常评分的单位是 DetectContext，
 * 虽然评分所依赖的基线以角色为单位存储，但是在这里
 * 角色的文件访问、网络、IPC 等行为需要被归类到具体的 DetectContext 中。
 *
 * 异常检测器维护 ContextID -> DetectContext
 */
class Detector {
   public:
    Detector(/* args */);
    ~Detector();

    // TODO: detect: 1) 决定下一次 pop 的队列 2) 计算该维度异常 3) 异常融合
    void detect();

   private:
    /// @brief ContextID 到 DetectContext 的映射
    std::unordered_map<uint32_t, DetectContext> d_context;

    /// @brief ContextID 父树，Detector 的本地缓存（且第一手）
    std::unordered_map<uint32_t, uint32_t> context_parent;

    // 该队列的上游是语义化模块
    hng::SPSC_Queue<hng::syscall_semantic_data>& syscall_event_queue;
    hng::SPSC_Queue<hng::file_semantic_data>& file_event_queue;
};

#endif  // DETECTOR_HPP_