/**
 * @file semantic_component.hpp
 * @brief 语义聚合组件的公共句柄与构造选项。
 * @details 装配层经工厂构造并持有该句柄；语义工具与聚合仍在 src/。
 */

#ifndef HNG_SEMANTIC_COMPONENT_HPP_
#define HNG_SEMANTIC_COMPONENT_HPP_

#include <memory>

#include "agent/util/include/component.hpp"

struct file_access_data;
struct syscall_event;

namespace hng {

template <class T>
class SPSC_Queue;

struct file_semantic_data;
struct syscall_semantic_data;

/**
 * @brief 语义组件的构造选项。
 * @details 队列由装配层创建并持有；未接线的线传空，成对的原始与语义队列
 *          须同时为空或同时非空。
 */
struct SemanticOptions {
    /// 文件原始事件队列
    hng::SPSC_Queue<::file_access_data>* raw_file            = nullptr;
    /// 系统调用原始事件队列
    hng::SPSC_Queue<::syscall_event>* raw_syscall            = nullptr;
    /// 文件语义事件队列
    hng::SPSC_Queue<hng::file_semantic_data>* out_file       = nullptr;
    /// 系统调用语义事件队列
    hng::SPSC_Queue<hng::syscall_semantic_data>* out_syscall = nullptr;
};

/**
 * @brief 语义聚合组件。
 * @details 单线程消费两条原始事件队列并写入对应语义队列；组件不持线程。
 * @note 构造后即为 READY；run() 退出前排空两条原始队列。
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
