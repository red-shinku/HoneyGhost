#ifndef _USER_MODE_ROLE_HPP
#define _USER_MODE_ROLE_HPP

#include <cstdint>
#include <string>

namespace hng {

using role_label_t = std::string;

/**
 * @brief 角色的对外视图
 * @details roleID 由 RoleManager 分配，从 1 起单调递增
 */
struct Role {
    uint32_t roleID;
    role_label_t roleLabel;
};

}  // namespace hng

#endif  //_USER_MODE_ROLE_HPP