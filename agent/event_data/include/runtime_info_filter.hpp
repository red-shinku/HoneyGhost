/**
 * @file runtime_info_filter.hpp
 * @brief 运行时信息过滤器
 * @author red-shinku
 * @date 2026.10.10
 */
#ifndef HNG_RUNTIME_INFO_FILTER_HPP_
#define HNG_RUNTIME_INFO_FILTER_HPP_

#include <cstdint>
#include <vector>

#include "agent/event_data/include/filter_expr.hpp"
#include "agent/event_data/include/runtime_event.hpp"

/**
 * @brief 订阅流关心的运行时信息组合
 * @details 值对象，可拷贝。共四个维度：进程、角色、上下文、事件类型。角色维度
 * 含 roleID 与 roleLabel 两组取值。取值集合为空表示该维度不限，故默认构造即全选。
 * 表达式集合与各维度取交集。
 * @note 匹配语义：维度之间取交集，维度之内取并集——已设置的维度要求事件至少
 * 命中该维度中某个集合的某个成员。
 * @note 各 set_* 与 add_expression 只在构造期调用，构造完成后成员不变。
 */
class RuntimeInfoFilter {
   public:
    /// @brief 全选：各维度都不限，且不含表达式
    RuntimeInfoFilter() = default;

    /// @brief 设置进程维度
    /// @note 只比 pid，不比 pid_start_time：进程身份本是二者的组合，此处为
    /// 单键是订阅方只给得出 pid 所致，故 pid 复用后可能误命中
    /// @note 取值在构造期排序去重
    RuntimeInfoFilter& set_process(std::vector<uint32_t> pids);

    /// @brief 设置角色维度
    /// @param roleIDs 按角色 ID 匹配的取值集合
    /// @param roleLabels 按角色标签匹配的取值集合，与 roleIDs 同属角色维度
    /// @note 两组取并集：事件命中任一组的任一成员即视为该维度命中
    /// @note 0 是「未落定」哨兵，按键值比较而非当作不限
    /// @note 归属未落定的事件不带标签，故不会被非空的标签集合命中
    /// @note 两组取值均在构造期排序去重
    RuntimeInfoFilter& set_role(std::vector<uint32_t> roleIDs,
                                std::vector<hng::role_label_t> roleLabels);

    /// @brief 设置上下文维度
    /// @note 0 是「未落定」哨兵，按键值比较而非当作不限
    /// @note 取值在构造期排序去重
    RuntimeInfoFilter& set_context(std::vector<uint32_t> contextIDs);

    /// @brief 设置事件类型维度
    /// @note 取值在构造期排序去重
    RuntimeInfoFilter& set_etype(std::vector<hng::EventType> etypes);

    /// @brief 追加一条布尔表达式，与既有条件取交集
    /// @param expr 表达式；默认构造的表达式恒真，不改变结果
    /// @note 可多次调用，各表达式之间取交集
    RuntimeInfoFilter& add_expression(hng::FilterExpr expr);

    /// @brief 判定一条运行时信息是否命中本过滤器
    /// @return 所有已设置维度与表达式均命中为 true；无已设置条件时为 true
    /// @note 判定顺序：etype → process.pid → contextID → 角色维度 → 各表达式
    bool should_take(const hng::RuntimeInformation& info) const;

   private:
    std::vector<uint32_t> pids_;
    std::vector<uint32_t> roleIDs_;
    std::vector<hng::role_label_t> roleLabels_;
    std::vector<uint32_t> contextIDs_;
    std::vector<hng::EventType> etypes_;
    std::vector<hng::FilterExpr> expressions_;
};

#endif  // HNG_RUNTIME_INFO_FILTER_HPP_
