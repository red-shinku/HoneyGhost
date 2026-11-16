/**
 * @file collector_component.hpp
 * @brief 原始事件采集组件的公共句柄与构造选项。
 * @details 装配层经工厂构造并持有该句柄；事件线与采集聚合仍在 src/。
 */

#ifndef HNG_COLLECTOR_COMPONENT_HPP_
#define HNG_COLLECTOR_COMPONENT_HPP_

#include <memory>
#include <vector>

#include "agent/util/include/component.hpp"
#include "agent/util/include/pipeline_stats.hpp"

struct file_access_data;
struct syscall_event;
struct network_data;

namespace hng {

template <class T>
class EventChannelWriter;

/**
 * @brief 采集组件的构造选项。
 * @details 三条原始事件通道由装配层创建并持有；空指针表示该线未接线。
 */
struct CollectorOptions {
    /// 文件原始事件通道写端
    hng::EventChannelWriter<::file_access_data>* file_sink = nullptr;
    /// 系统调用原始事件通道写端
    hng::EventChannelWriter<::syscall_event>* syscall_sink = nullptr;
    /// 网络原始事件通道写端
    hng::EventChannelWriter<::network_data>* network_sink  = nullptr;
};

/**
 * @brief 原始事件采集组件。
 * @details 封装各事件线的 prepare / attach 与单线程采集聚合；组件不持线程。
 * @note 生命周期为 CONSTRUCTED → READY → RUNNING → STOPPED。prepare() 成功
 *       后 role_filter_map_fds() 才可能返回有效 fd。
 * @see hng::Component, CollectorOptions, CollectorFactory
 */
class CollectorComponent final : public hng::Component {
   public:
    ~CollectorComponent() override;

    CollectorComponent(const CollectorComponent&)            = delete;
    CollectorComponent& operator=(const CollectorComponent&) = delete;
    CollectorComponent(CollectorComponent&&)                 = delete;
    CollectorComponent& operator=(CollectorComponent&&)      = delete;

    /// @brief 加载骨架、创建 ringbuf 并校验过滤 map fd，不挂载探针
    /// @return 成功为 true；失败为 false
    /// @note 只可在 CONSTRUCTED 调用；失败时已准备的线保留资源，由析构回收
    bool prepare();

    /// @brief 在 prepare() 成功后挂载探针
    /// @return 成功为 true；未准备、已挂载或挂载失败为 false
    /// @note 成功后状态为 READY；挂载失败保留已准备资源
    bool attach();

    /// @brief 汇总各线的角色过滤 map fd
    /// @return 有效 fd 列表；未 prepare() 或对应线无 map 时为空
    /// @note 调用方不得关闭 fd
    std::vector<int> role_filter_map_fds() const;

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
