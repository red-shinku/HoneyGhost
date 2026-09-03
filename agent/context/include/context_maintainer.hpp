/**
 * @file context_maintainer.hpp
 * @brief context 结构的派生、决策、查询 等逻辑维护模块
 * @details
 * 这个模块相当于一个工具箱，是一组处理逻辑（函数），
 * 不存储任何信息和状态。
 * @author red_shinku
 * @date 2026.9.3
 */

#ifndef CONTEXT_MAINTAINER_HPP_
#define CONTEXT_MAINTAINER_HPP_

#include <string>

#include "agent/control_plane/include/context_service.hpp"
#include "agent/detector/include/score.hpp"
#include "agent/event_data/process.hpp"
#include "agent/event_data/event_type.hpp"
#include "./context_maintainer_decision.hpp"

class ContextMaintainer {
   public:
    ContextMaintainer(/* args */);
    ~ContextMaintainer();

    /// @brief 根据 exec 类别事件提供的信息，判断是否需要派生 Context
    /// @return 派生决策，包含是否派生、派生的 contextID、派生的属性
    /// @param file_name 运行可执行程序的文件名
    /// @param argv0 可执行程序的 argv[0]
    /// TODO: 需要规则
    ContextDeriveDecision should_derive_context(std::string file_name,
                                                std::string argv0);

    /// @brief 是否要进入附属 Context
    /// 接受各维度的异常分值，判断本次事件是否应该归类到附属 Context 中
    /// 不包含任何检测逻辑，只做分值判断
    /// @param type 事件所属维度
    /// @param score 多维度评分信息
    ContextExtraDecision should_extra_context(hng::EventType type, Score score);

    /// @brief 尝试更新 Context 的属性
    /// @details
    /// 为 UNKNOWN 属性的 Context 服务
    /// 向 NORMAL 更新的标准是：在一定窗口内保持较高的正常分值
    /// 向 ATTACK 更新的标准是：强攻击证据直接判定，结合多维度异常评分
    /// @param score 多维度评分信息
    void try_update_context_attributes(Score score);

    /// @brief contextID 查询
    /// @param p context代表进程的唯一性表示
    /// @return contextID 查询结果
    std::optional<uint32_t> lookup_contextID(hng::Process p) const;

   private:
    ContextService* context_service;

    /// @brief 需要查询附属 contextID 时使用，是本模块内部逻辑
    /// @param p context代表进程的唯一性表示
    /// @return extraContextID 查询结果
    std::optional<uint32_t> lookup_extra_contextID(hng::Process p) const;

    // 通知控制平面执行更新

    void derive_context();
    void extra_context();
};

#endif  // CONTEXT_MAINTAINER_HPP_
