/**
 * @file capability_drop.hpp
 * @brief 初始化完成后放弃进程权能
 * @details 权能按线程持有，清空只作用于调用线程：多线程进程须在每个线程
 *          各调用一次。清空后该线程创建的线程不再继承任何权能。
 * @author red_shinku
 * @date 2026.11.10
 */

#ifndef HNG_ASSEMBLY_CAPABILITY_DROP_HPP_
#define HNG_ASSEMBLY_CAPABILITY_DROP_HPP_

namespace hng {
namespace detail {

/**
 * @brief 清空调用线程的权能：bounding set 与 effective/permitted/inheritable
 * @return capset 成功为 true；失败已记录日志，不计入启动失败
 * @note 清空 bounding set 需 CAP_SETPCAP，缺失时只清 effective/permitted/
 *       inheritable 三集，此后该线程仍无法自行取得权能。
 * @see ComponentThreads::start, Assembly::Impl::start_impl
 */
bool drop_capabilities();

}  // namespace detail
}  // namespace hng

#endif  // HNG_ASSEMBLY_CAPABILITY_DROP_HPP_
