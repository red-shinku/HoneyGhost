/**
 * @file semantic_component.hpp
 * @brief 语义聚合组件的公共句柄与构造选项。
 * @details 装配层经工厂构造并持有该句柄；语义工具与聚合仍在 src/。
 */

#ifndef HNG_SEMANTIC_COMPONENT_HPP_
#define HNG_SEMANTIC_COMPONENT_HPP_

#include <memory>

#include "agent/util/include/component.hpp"
#include "agent/util/include/pipeline_stats.hpp"

struct file_access_data;
struct syscall_event;

namespace hng {

template <class T>
class EventChannelReader;
template <class T>
class EventChannelWriter;

struct file_semantic_data;
struct syscall_semantic_data;

/**
 * @brief 语义组件的构造选项。
 * @details 通道由装配层创建并持有；未接线的线传空，成对的原始读端与语义
 *          写端须同时为空或同时非空。
 */
struct SemanticOptions {
    /// 文件原始事件通道读端
    hng::EventChannelReader<::file_access_data>* raw_file            = nullptr;
    /// 系统调用原始事件通道读端
    hng::EventChannelReader<::syscall_event>* raw_syscall            = nullptr;
    /// 文件语义事件通道写端
    hng::EventChannelWriter<hng::file_semantic_data>* out_file       = nullptr;
    /// 系统调用语义事件通道写端
    hng::EventChannelWriter<hng::syscall_semantic_data>* out_syscall = nullptr;
};

/**
 * @brief 语义聚合组件。
 * @details 单线程消费两条原始事件通道并写入对应语义通道；组件不持线程。
 * @note 构造后即为 READY；run() 退出前排空两条原始通道并关闭两条语义通道。
 * @see hng::Component, SemanticOptions, SemanticFactory
 */
class SemanticComponent final : public hng::Component {
   public:
    ~SemanticComponent() override;

    SemanticComponent(const SemanticComponent&)            = delete;
    SemanticComponent& operator=(const SemanticComponent&) = delete;
    SemanticComponent(SemanticComponent&&)                 = delete;
    SemanticComponent& operator=(SemanticComponent&&)      = delete;

    /// @brief 当前生命周期状态
    /// @see hng::Component::state
    hng::ComponentState state() const override;

    /// @brief 累计计数快照；可从任意线程调用
    hng::SemanticStats stats() const;

    /// @brief 组件线程入口
    /// @see hng::Component::run
    void run() override;

    /// @brief 停止组件
    /// @see hng::Component::stop
    void stop() override;

   private:
    struct Impl;

    explicit SemanticComponent(std::unique_ptr<Impl> impl);

    friend class SemanticFactory;

    std::unique_ptr<Impl> impl_;
};

}  // namespace hng

#endif  // HNG_SEMANTIC_COMPONENT_HPP_
