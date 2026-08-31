#ifndef _CONTROL_PLANE_CONTEXTSERVICE_HPP
#define _CONTROL_PLANE_CONTEXTSERVICE_HPP

#include <optional>
#include <cstdint>

#include "agent/event_data/context.hpp"

class ContextService {
   protected:
    virtual ~ContextService() = default;

   public:
    virtual std::optional<uint32_t> lookup(uint32_t pid,
                                           uint64_t start_time) const        = 0;

    virtual void register_contextID(uint32_t pid, uint64_t start_time,
                                    uint32_t contextID, uint32_t pcontextID) = 0;

    virtual void unregister_contextID(uint32_t pid, uint64_t start_time)     = 0;

    virtual void set_attr(uint32_t pid, uint64_t start_time, uint32_t contextID,
                          hng::contextattr attr)                             = 0;
};

#endif  //_CONTROL_PLANE_CONTEXTSERVICE_HPP