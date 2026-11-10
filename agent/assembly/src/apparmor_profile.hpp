/**
 * @file apparmor_profile.hpp
 * @brief 初始化完成后把调用线程切到运行期 AppArmor profile
 * @details 入口 profile `hng-agent` 多放行初始化快照需要的 ptrace；切到
 *          `hng-agent-steady` 后该放行消失。profile 属线程私有，多线程进程
 *          须在每个线程各调用一次。
 * @author red_shinku
 * @date 2026.11.10
 */

#ifndef HNG_ASSEMBLY_APPARMOR_PROFILE_HPP_
#define HNG_ASSEMBLY_APPARMOR_PROFILE_HPP_

namespace hng {
namespace detail {

/**
 * @brief 当前线程处于入口 profile 时切到 `hng-agent-steady`
 * @return 已切换成功，或当前不在入口 profile（含宿主没有 AppArmor）为 true；
 *         尝试切换但失败并已记录日志为 false
 * @note 切换失败时线程留在入口 profile，调用方按降级处理。切换要求已载入的
 *       入口 profile 带 `change_profile -> hng-agent-steady`。
 * @see ComponentThreads::start, Assembly::Impl::start_impl
 */
bool enter_steady_profile();

}  // namespace detail
}  // namespace hng

#endif  // HNG_ASSEMBLY_APPARMOR_PROFILE_HPP_
