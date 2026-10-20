/**
 * @file
 * @brief 黑名单优先的只读标签策略。
 */
#ifndef HNG_ROLE_FILTER_POLICY_HPP_
#define HNG_ROLE_FILTER_POLICY_HPP_
#include <memory>
#include <string>
#include "agent/role_filter/include/role_filter_config.hpp"

namespace hng {
namespace detail { class RoleFilterPolicyData; }
/**
 * @brief 构造时编译、查询时只读的角色名单策略。
 * @details 精确规则使用哈希集合，正则规则依次执行区分大小写的整串匹配。
 */
class RoleFilterPolicy {
   public:
    /**
     * @brief 校验并构建策略；默认空名单拒绝普通事件。
     * @param[in] config 白名单与黑名单规则。
     * @throws std::runtime_error 规则类型、表达式或正则语法非法。
     */
    explicit RoleFilterPolicy(const RoleFilterConfig& config = {});
    /**
     * @brief 判断完整角色标签是否允许采集普通事件。
     * @param[in] role_label systemd unit name 或完整容器镜像引用。
     * @return 标签非空、未命中黑名单且命中白名单时为 true。
     * @note 生命周期事件由 eBPF 探针绕过过滤，不受本策略限制。
     */
    bool should_collect(const std::string& role_label) const;
   private:
    std::shared_ptr<const detail::RoleFilterPolicyData> data_;
};
}  // namespace hng
#endif
