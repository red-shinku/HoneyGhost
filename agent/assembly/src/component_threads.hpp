/**
 * @file component_threads.hpp
 * @brief 装配层持有的组件线程表
 * @details 以组件指针为键保存组件线程；线程由装配层创建并 join，组件不持
 *          线程。只被装配层的启动与停机流程使用。
 * @author red_shinku
 * @date 2026.10.28
 */

#ifndef HNG_ASSEMBLY_COMPONENT_THREADS_HPP_
#define HNG_ASSEMBLY_COMPONENT_THREADS_HPP_

#include <map>
#include <thread>

#include "agent/assembly/src/apparmor_profile.hpp"
#include "agent/assembly/src/capability_drop.hpp"
#include "agent/util/include/component.hpp"

namespace hng {

/**
 * @brief 组件线程表
 * @details 每个组件至多一个线程。线程由装配层持有；组件须活到对应的
 *          stop_and_join() 返回。析构前须已对表内每个组件调用
 *          stop_and_join()。线程入口先清空该线程的权能并切到运行期 AppArmor
 *          profile，组件 run() 内不再持有权能、也不带入口 profile 的放行。
 */
class ComponentThreads final {
   public:
    /**
     * @brief 为组件创建并启动 run() 线程
     * @param component 线程入口所属的组件；须活到 stop_and_join() 返回
     * @note 同一组件重复调用不覆盖已有线程；线程创建失败时异常按原样传播
     */
    void start(hng::Component& component);

    /**
     * @brief 停止组件并 join 其线程
     * @param component 要停止的组件；须活到本函数返回
     * @note 先调用 stop()，再 join 可 join 的线程；表中没有该组件时只调用
     *       stop()。不得从该组件线程调用
     */
    void stop_and_join(hng::Component& component);

   private:
    /// @brief 组件到其线程的映射
    std::map<hng::Component*, std::thread> threads_;
};

inline void ComponentThreads::start(hng::Component& component)
{
    auto [entry, inserted] = threads_.try_emplace(&component);
    if (!inserted) {
        return;
    }
    entry->second = std::thread([component = &component] {
        detail::drop_capabilities();
        detail::enter_steady_profile();
        component->run();
    });
}

inline void ComponentThreads::stop_and_join(hng::Component& component)
{
    component.stop();

    const auto entry = threads_.find(&component);
    if (entry == threads_.end()) {
        return;
    }
    if (entry->second.joinable()) {
        entry->second.join();
    }
}

}  // namespace hng

#endif  // HNG_ASSEMBLY_COMPONENT_THREADS_HPP_
