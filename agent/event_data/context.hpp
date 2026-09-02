#ifndef _USER_MODE_CONTEXT_HPP
#define _USER_MODE_PROCESS_HPP

namespace hng {

/**
 * @brief context 结构的属性
 * @details
 * 新派生的 Context 为 UNKNOWN。
 * 已经确定属性的 context 不会再变更。
 * NORMAL 和 ATTACK 都有自己独立的代表 PID。
 * EXTRA_ATTACK 属性只属于附属 context。
 */
enum contextattr {
    NORMAL,        ///< 正常上下文
    UNKNOWN,       ///< 正在观察中
    ATTACK,        ///< 攻击上下文
    EXTRA_ATTACK,  ///< 无对应实体攻击上下文，用于从正常上下文中出现的异常流量
};

}  // namespace hng

#endif  //_USER_MODE_PROCESS_HPP
