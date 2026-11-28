/**
 * @file collector_component.hpp
 * @brief 原始事件采集组件的公共句柄与构造选项。
 * @details 装配层经工厂构造并持有该句柄；事件线与采集聚合仍在 src/。
 */

#ifndef HNG_COLLECTOR_COMPONENT_HPP_
#define HNG_COLLECTOR_COMPONENT_HPP_

#include "agent/bpf_loader/include/syscall_probe_maps.hpp"
#include "agent/util/include/component.hpp"
#include "agent/util/include/pipeline_stats.hpp"

#include <memory>
#include <optional>
#include <vector>

struct syscall_event;

namespace hng {

template <class T>
class EventChannelWriter;

/**
 * @brief 采集组件的构造选项。
 * @details 原始事件通道与 syscall map 视图均由装配层提供；空写端或空
 *          map 表示该线未接线。
 */
struct CollectorOptions {
    /// 系统调用原始事件通道写端
    hng::EventChannelWriter<::syscall_event>* syscall_sink = nullptr;
    /// 系统调用 map 视图；与 syscall_sink 同时有值才构造系统调用线
    std::optional<hng::SyscallProbeMaps> syscall_maps;
};

/**
 * @brief 原始事件采集组件。
 * @details 封装事件线的 prepare 与单线程采集聚合；组件不持线程，也不管理
 *          BPF 程序生命周期。
 * @note 生命周期为 CONSTRUCTED → READY → RUNNING → STOPPED。
 * @see hng::Component, CollectorOptions, CollectorFactory
 */
class CollectorComponent final : public hng::Component {
   public:
    ~CollectorComponent() override;

    CollectorComponent(const CollectorComponent&)            = delete;
    CollectorComponent& operator=(const CollectorComponent&) = delete;
    CollectorComponent(CollectorComponent&&)                 = delete;
    CollectorComponent& operator=(CollectorComponent&&)      = delete;

    /// @brief 创建各线 reader 并准备采集聚合
    /// @return 成功为 true；失败为 false
    /// @note 只可在 CONSTRUCTED 调用；map 视图由装配层提供
    bool prepare();

    /// @brief 标记探针已挂载并转入 READY
    /// @return 成功为 true；状态不是 CONSTRUCTED 时为 false
    /// @note 由装配层在 BPF 程序挂载成功后调用
    bool mark_ready();

    /// @brief 各线累计计数快照；可从任意线程调用
    std::vector<hng::CollectorLineStats> stats() const;

    /// @brief 当前生命周期状态
    /// @see hng::Component::state
    hng::ComponentState state() const override;

    /// @brief 组件线程入口
    /// @see hng::Component::run
    void run() override;

    /// @brief 停止组件
    /// @see hng::Component::stop
    void stop() override;

   private:
    struct Impl;

    explicit CollectorComponent(std::unique_ptr<Impl> impl);

    friend class CollectorFactory;

    std::unique_ptr<Impl> impl_;
};

}  // namespace hng

#endif  // HNG_COLLECTOR_COMPONENT_HPP_
