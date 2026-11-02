/**
 * @file semantic_factory.hpp
 * @brief 语义组件的唯一构造入口。
 */

#ifndef HNG_SEMANTIC_FACTORY_HPP_
#define HNG_SEMANTIC_FACTORY_HPP_

#include <memory>

#include "agent/semantic/include/semantic_component.hpp"

namespace hng {

/**
 * @brief 语义组件工厂。
 * @details create() 至多允许一个经本方法创建的存活实例；组件析构后名额归还。
 */
class SemanticFactory {
   public:
    /**
     * @brief 构造语义组件。
     * @param options 两条原始通道读端与两条语义通道写端的借用指针；未接线传空
     * @return 状态为 READY 的组件
     * @throws std::logic_error 已有经本方法创建的实例存活
     * @throws std::system_error 事件循环 fd 创建失败
     */
    static std::unique_ptr<SemanticComponent> create(
        SemanticOptions options = {});

    SemanticFactory() = delete;
};

}  // namespace hng

#endif  // HNG_SEMANTIC_FACTORY_HPP_
