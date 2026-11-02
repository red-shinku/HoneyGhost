/**
 * @file single_instance_guard.hpp
 * @brief 工厂方法存活实例名额的 RAII 守卫。
 */

#ifndef HNG_SINGLE_INSTANCE_GUARD_HPP_
#define HNG_SINGLE_INSTANCE_GUARD_HPP_

#include <atomic>
#include <stdexcept>
#include <string>

namespace hng::detail {

/**
 * @brief 占用一个工厂方法的存活实例名额，析构时归还。
 * @details 构造以 acq_rel 的 CAS 把标志由 false 置为 true；析构以 release
 *          复位。
 * @note 不可复制、不可移动；标志须比本对象活得更久。
 */
class SingleInstanceGuard {
   public:
    /**
     * @brief 占用名额。
     * @param taken 工厂方法的存活标志，须比本对象活得更久
     * @param component 组件名，写入占用失败的异常消息
     * @throws std::logic_error @p taken 已为 true
     */
    SingleInstanceGuard(std::atomic<bool>& taken, const char* component)
        : taken_(&taken)
    {
        bool expected = false;
        if (!taken_->compare_exchange_strong(expected, true,
                                             std::memory_order_acq_rel)) {
            throw std::logic_error(std::string(component) +
                                   " already has a live instance");
        }
    }

    ~SingleInstanceGuard() { taken_->store(false, std::memory_order_release); }

    SingleInstanceGuard(const SingleInstanceGuard&)            = delete;
    SingleInstanceGuard& operator=(const SingleInstanceGuard&) = delete;
    SingleInstanceGuard(SingleInstanceGuard&&)                 = delete;
    SingleInstanceGuard& operator=(SingleInstanceGuard&&)      = delete;

   private:
    std::atomic<bool>* taken_;
};

}  // namespace hng::detail

#endif  // HNG_SINGLE_INSTANCE_GUARD_HPP_
