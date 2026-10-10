#ifndef HNG_ROLE_FILTER_POLICY_HPP_
#define HNG_ROLE_FILTER_POLICY_HPP_

#include <memory>
#include <string>
#include "agent/role_filter/include/role_filter_config.hpp"

namespace hng {
namespace detail { class RoleFilterPolicyData; }

/* 构造时编译正则；查询只读。regex 为 ECMAScript、大小写敏感、整串匹配。 */
class RoleFilterPolicy {
   public:
    explicit RoleFilterPolicy(const RoleFilterConfig& config = {});
    bool should_collect(const std::string& role_label) const;

   private:
    std::shared_ptr<const detail::RoleFilterPolicyData> data_;
};
}  // namespace hng
#endif
