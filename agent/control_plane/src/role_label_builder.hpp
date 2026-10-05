/**
 * @file role_label_builder.hpp
 * @brief 由角色身份构造 roleLabel
 * @details RoleManager 的内部件，随关系表的落地被调用；规则按来源分派。
 *          对用户而言，roleLabel 是配置里选中角色的静态凭据，故取来源的本名，
 *          不取任何随实例生死或版本变动而离散的运行时标识。
 * @author red_shinku
 * @date 2026.10.5
 */

#ifndef HNG_ROLE_LABEL_BUILDER_HPP_
#define HNG_ROLE_LABEL_BUILDER_HPP_

#include "agent/event_data/include/role.hpp"
#include "agent/role_discovery/include/role_event.hpp"

/// @brief roleLabel 生成器
/// @details 无状态、不做 IO，可在任意线程调用
class RoleLabelBuilder {
   public:
    /// @brief 由角色身份构造 roleLabel
    /// @param identity 角色身份；来源决定取值字段
    /// @return systemd 取 unit 名（实例键）；容器取镜像引用，缺失时退到类型键；
    ///         来源未声明时取类型键
    static hng::role_label_t build(const hng::role::RoleIdentity& identity);
};

#endif  // HNG_ROLE_LABEL_BUILDER_HPP_
