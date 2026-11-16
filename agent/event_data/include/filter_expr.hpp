/**
 * @file filter_expr.hpp
 * @brief 订阅过滤的布尔表达式
 * @author red-shinku
 * @date 2026.11.13
 */
#ifndef HNG_FILTER_EXPR_HPP_
#define HNG_FILTER_EXPR_HPP_

#include <cstdint>
#include <memory>
#include <vector>

#include "agent/event_data/include/runtime_event.hpp"

namespace hng {

/**
 * @brief 原子谓词作用的字段
 * @details 取值与 cli_service.proto 的 FilterField 一致：能取 uint32_t 的字段
 * 对应 FilterAtom::numbers，role 标签对应 FilterAtom::strings。
 */
enum class FilterField : uint8_t {
    TYPE = 1,    ///< 顶层事件大类 hng::EventType
    KIND,        ///< 语义子类型 hng::EventKind
    PID,         ///< 事件主体进程的 pid
    PPID,        ///< 事件发生时刻的父进程 pid
    ROLE_ID,     ///< 归属角色 ID
    ROLE_LABEL,  ///< 归属角色标签
    CONTEXT_ID   ///< 归属上下文 ID
};

/**
 * @brief 原子谓词的比较方式
 * @details 取值与 cli_service.proto 的 FilterCompare 一致。EQ 命中取值集合中
 * 任一值，NE 不命中集合中任何值，PREFIX 要求任一取值是事件值的前缀。
 * @note PREFIX 只用于 ROLE_LABEL。
 */
enum class FilterCompare : uint8_t { EQ = 1, NE, PREFIX };

/**
 * @brief 单个原子谓词：字段 + 比较方式 + 取值集合
 * @details numbers 用于 TYPE / KIND / PID / PPID / ROLE_ID / CONTEXT_ID，
 * strings 用于 ROLE_LABEL，另一组不参与判定。
 * @note 取值集合为空时 EQ 不命中任何事件，NE 命中所有事件。
 * @see hng::FilterExpr::make_atom
 */
struct FilterAtom {
    FilterField field;
    FilterCompare compare;
    std::vector<uint32_t> numbers;
    std::vector<hng::role_label_t> strings;
};

/**
 * @brief 不可变的布尔过滤表达式
 * @details 由原子谓词经 and / or / not 组合而成。拷贝共享同一份节点，构造完成
 * 后只读，可安全跨线程共享；匹配过程不分配、不抛异常。
 * @note 默认构造的表达式恒真。
 * @see RuntimeInfoFilter::add_expression
 */
class FilterExpr {
   public:
    /// @brief 恒真表达式
    FilterExpr() = default;

    /// @brief 构造原子谓词
    /// @param atom 字段、比较方式与取值；两组取值在此排序去重
    static FilterExpr make_atom(FilterAtom atom);

    /// @brief 构造合取式
    /// @param operands 操作数；为空时结果恒真
    static FilterExpr make_and(std::vector<FilterExpr> operands);

    /// @brief 构造析取式
    /// @param operands 操作数；为空时结果恒假
    static FilterExpr make_or(std::vector<FilterExpr> operands);

    /// @brief 构造取反式
    /// @param operand 被取反的表达式
    static FilterExpr make_not(FilterExpr operand);

    /// @brief 判定一条运行时信息是否命中本表达式
    /// @return 表达式为真为 true；默认构造的表达式恒为 true
    bool matches(const hng::RuntimeInformation& info) const;

   private:
    struct Node;
    std::shared_ptr<const Node> root_;
};

}  // namespace hng

#endif  // HNG_FILTER_EXPR_HPP_
