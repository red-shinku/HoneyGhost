#ifndef _USER_MODE_ROLE_HPP
#define _USER_MODE_ROLE_HPP

#include <cstdint>
#include <string>

namespace hng {

using role_lable_t = std::string;

struct Role {
    uint16_t roleID;
    role_lable_t roleLable;
};

}  // namespace hng

#endif  //_USER_MODE_ROLE_HPP