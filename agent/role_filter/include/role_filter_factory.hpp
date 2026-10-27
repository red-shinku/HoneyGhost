/**
 * @file role_filter_factory.hpp
 * @brief 角色过滤组件的唯一构造入口。
 */

#ifndef HNG_ROLE_FILTER_FACTORY_HPP_
#define HNG_ROLE_FILTER_FACTORY_HPP_

#include <memory>

#include "agent/role_filter/include/role_filter_component.hpp"

namespace hng {

/**
 * @brief 角色过滤组件工厂。
 * @details create() 至多允许一个经本方法创建的存活实例；组件析构后名额归还。
 */
class RoleFilterFactory {
   public:
    /**
     * @brief 构造角色过滤组件。
     * @param options 借用的服务、初始策略、map 后端与刷新选项
     * @return 状态为 CONSTRUCTED 的组件
     * @throws std::invalid_argument lookup 或 map 为空
     * @throws std::logic_error 已有经本方法创建的实例存活
     */
    static std::unique_ptr<RoleFilterComponent> create(
        RoleFilterComponentOptions options);

    RoleFilterFactory() = delete;
};

}  // namespace hng

#endif  // HNG_ROLE_FILTER_FACTORY_HPP_
