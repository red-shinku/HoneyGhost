/**
 * @file component.hpp
 * @brief 组件的生命周期接口
 * @author red_shinku
 * @date 2026.10.25
 */

#ifndef HNG_COMPONENT_HPP_
#define HNG_COMPONENT_HPP_

#include <cstdint>

namespace hng {

/**
 * @brief 组件的生命周期状态
 * @details 只沿 CONSTRUCTED → READY → RUNNING → STOPPED 前进。未 READY 时
 *          stop() 直接置 STOPPED，此后不可再初始化。
 */
enum class ComponentState : uint8_t {
    CONSTRUCTED,  ///< 已构造，初始化尚未完成
    READY,        ///< 初始化写入已落地，可接受运行期写入与 run()
    RUNNING,      ///< run() 已进入
    STOPPED       ///< stop() 后 run() 已返回
};

/**
 * @brief 组件的生命周期接口
 * @details 只表达状态与启停，不提供服务查找；服务接口由具体组件的类型化
 *          句柄提供。组件不持线程：run() 阻塞，线程由装配层创建并 join。
 */
class Component {
   public:
    virtual ~Component()                 = default;

    /// @brief 当前状态
    /// @note 可从任意线程读取
    virtual ComponentState state() const = 0;

    /// @brief 是否已完成初始化
    /// @return 状态为 READY 或 RUNNING 时为 true
    /// @note 只表示初始化完成，不表示线程已启动；这是“就绪可运行”的判据
    bool ready() const
    {
        const ComponentState s = state();
        return s == ComponentState::READY || s == ComponentState::RUNNING;
    }

    /// @brief 组件线程入口：阻塞直到 stop() 且已入队工作落地
    /// @pre ready() 为 true；违反是装配错误，Debug 断言，Release 立即返回
    /// @note 不创建线程；线程由装配层创建，析构前须已返回
    virtual void run()  = 0;

    /// @brief 停止消费；幂等，可从任意线程调用
    /// @note 已入队工作仍会落地；此后的入队被拒绝
    virtual void stop() = 0;
};

}  // namespace hng

#endif  // HNG_COMPONENT_HPP_
