/**
 * @file runtime_engine_factory.hpp
 * @brief 运行时引擎组件的唯一构造入口。
 */

#ifndef HNG_RUNTIME_ENGINE_FACTORY_HPP_
#define HNG_RUNTIME_ENGINE_FACTORY_HPP_

#include <memory>

#include "agent/runtime_engine/include/runtime_engine_component.hpp"

namespace hng {

/**
 * @brief 运行时引擎组件工厂。
 * @details create() 至多允许一个经本方法创建的存活实例；组件析构后名额归还。
 */
class RuntimeEngineFactory {
   public:
    /**
     * @brief 构造运行时引擎组件。
     * @param options 语义队列与控制平面服务的借用指针；空表示未接线
     * @return 状态为 READY 的组件
     * @throws std::logic_error 已有经本方法创建的实例存活
     */
    static std::unique_ptr<RuntimeEngineComponent> create(
        RuntimeEngineOptions options = {});

    RuntimeEngineFactory() = delete;
};

}  // namespace hng

#endif  // HNG_RUNTIME_ENGINE_FACTORY_HPP_
