#ifndef _USER_MODE_CONTEXT_HPP
#define _USER_MODE_PROCESS_HPP

namespace hng {

/**
 * @brief context 结构的属性
 * @details
 * 新派生的 Context 为 UNKNOWN。
 * 已经确定属性的 context 不会再变更。
 * NORMAL 和 ATTACK 都有自己独立的代表 PID。
 * EXTRA_ATTACK 依附于某个 NORMAL context，其
 * 代表 PID 与所依附的 context 一致。
 * EXTRA_ATTACK 用于从正常上下文中出现的异常流量，即
 * 攻击没有创建新的执行实体的情况
 */
enum contextattr {
    NORMAL,        ///< 正常上下文
    UNKNOWN,       ///< 正在观察中
    ATTACK,        ///< 攻击上下文
    EXTRA_ATTACK,  ///< 无对应实体攻击上下文
};

}  // namespace hng

#endif  //_USER_MODE_PROCESS_HPP
