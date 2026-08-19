#ifndef _CONTROL_PLANE_ROLE_HPP
#define _CONTROL_PLANE_ROLE_HPP

#include <cstdint>

#include "./context_manager.hpp"

class Role {
   public:
    Role();
    ~Role();

   private:
    uint16_t roleID;
    ContextManager ctxmanager;
};

#endif  //_CONTROL_PLANE_ROLE_HPP