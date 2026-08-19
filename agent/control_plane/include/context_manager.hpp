/**
 * @file context_manager.hpp
 * @brief 控制平面的上下文管理器组件
 * @author red_shinku
 * @date 2026.8.18
 */

#ifndef _CONTROL_PLANE_CONTEXTMANAGER_HPP
#define _CONTROL_PLANE_CONTEXTMANAGER_HPP

#include <cstdint>
#include <unordered_map>

/**
 * @brief 上下文管理器
 * @details
 * 每个角色拥有一个，上下文管理器负责 context 结构关系的管理
 * 其中记录的 contextID 由 context maintainer 模块生成并注册
 */
class ContextManager {
   public:
    ContextManager(/* args */);
    ~ContextManager();

   private:
    // 维护 PID 到 contextID 的映射
    // 该 map 中只记录每个 context 的根 PID
    // 通常 Process 结构（对应一个PID）中会有其所属 contextID 的缓存
    // 通过其他控制面组件中维护的 PID 树向上查询可以获得该缓存
    std::unordered_map<uint32_t, uint32_t> contextID;  ///< PID -> contextID

    // 维护 context 树状关系，
    // 一个 comtextID 映射到它的上一个父级 ID
    std::unordered_map<uint32_t, uint32_t> parent;  ///< contextID -> parent contextID
};

#endif  //_CONTROL_PLANE_CONTEXTMANAGER_HPP