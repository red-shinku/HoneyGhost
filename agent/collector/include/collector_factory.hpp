/**
 * @file collector_factory.hpp
 * @brief 采集组件的唯一构造入口。
 */

#ifndef HNG_COLLECTOR_FACTORY_HPP_
#define HNG_COLLECTOR_FACTORY_HPP_

#include <memory>

#include "agent/collector/include/collector_component.hpp"

namespace hng {

/**
 * @brief 采集组件工厂。
 * @details create() 至多允许一个经本方法创建的存活实例；组件析构后名额归还。
 */
class CollectorFactory {
   public:
    /**
     * @brief 构造采集组件。
     * @param options 三条原始事件队列的借用指针；空表示该线未接线
     * @return 状态为 CONSTRUCTED 的组件
     * @throws std::logic_error 已有经本方法创建的实例存活
     */
    static std::unique_ptr<CollectorComponent> create(
        CollectorOptions options = {});

    CollectorFactory() = delete;
};

}  // namespace hng

#endif  // HNG_COLLECTOR_FACTORY_HPP_
