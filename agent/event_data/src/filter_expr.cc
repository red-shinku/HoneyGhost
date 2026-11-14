/**
 * @file filter_expr.cc
 * @brief 订阅过滤的布尔表达式 实现
 * @author red-shinku
 * @date 2026.11.13
 */

#include "agent/event_data/include/filter_expr.hpp"

#include <algorithm>
#include <cstddef>
#include <string_view>
#include <utility>

namespace hng {

struct FilterExpr::Node {
    enum class Op : uint8_t { ATOM, AND, OR, NOT };

    /// @brief 递归求值
    bool match(const hng::RuntimeInformation& info) const;

    Op op = Op::ATOM;
    hng::FilterAtom atom;                   ///< op 为 ATOM 时有效
    std::vector<hng::FilterExpr> operands;  ///< op 非 ATOM 时有效
};

namespace {

/// @brief 排序并去除重复取值
template <class T>
void sort_unique(std::vector<T>& values)
{
    std::sort(values.begin(), values.end());
    values.erase(std::unique(values.begin(), values.end()), values.end());
}

bool contains(const std::vector<uint32_t>& sorted_numbers, uint32_t value)
{
    return std::binary_search(sorted_numbers.begin(), sorted_numbers.end(),
                              value);
}

bool contains(const std::vector<hng::role_label_t>& sorted_labels,
              const hng::role_label_t& label)
{
    return std::binary_search(sorted_labels.begin(), sorted_labels.end(), label);
}

/// @brief 取字段的数值形态；ROLE_LABEL 不是数值字段，返回 0 且不被使用
uint32_t field_value(hng::FilterField field, const hng::RuntimeInformation& info)
{
    switch (field) {
        case hng::FilterField::TYPE:
            return static_cast<uint32_t>(info.etype);
        case hng::FilterField::KIND:
            return static_cast<uint32_t>(info.kind);
        case hng::FilterField::PID:
            return info.process.pid;
        case hng::FilterField::PPID:
            return info.parent.pid;
        case hng::FilterField::ROLE_ID:
            return info.roleID;
        case hng::FilterField::CONTEXT_ID:
            return info.contextID;
        case hng::FilterField::ROLE_LABEL:
            break;
    }
    return 0;
}

/// @brief 有序标签集合与 string_view 探针之间的字典序比较
/// @note 两种参数顺序都可用，以适配标准算法对比较器的调用方向；不构造临时串
struct PrefixLess {
    bool operator()(const hng::role_label_t& value, std::string_view probe) const
    {
        return value.compare(probe) < 0;
    }

    bool operator()(std::string_view probe, const hng::role_label_t& value) const
    {
        return probe.compare(value) < 0;
    }
};

/// @brief 标签是否以有序前缀集合中的任一取值为前缀
/// @note 有序集合只能按精确值二分，故对标签的每个前缀长度各二分一次，命中
/// 任一长度即为前缀命中；过程不分配内存
bool label_has_prefix(const std::vector<hng::role_label_t>& sorted_prefixes,
                      const hng::role_label_t& label)
{
    for (std::size_t length = 1; length <= label.size(); ++length) {
        if (std::binary_search(sorted_prefixes.begin(), sorted_prefixes.end(),
                               std::string_view(label.data(), length),
                               PrefixLess{})) {
            return true;
        }
    }
    return false;
}

/// @brief 标签是否命中有序标签集合；PREFIX 按前缀命中
bool label_matches(hng::FilterCompare compare,
                   const std::vector<hng::role_label_t>& sorted_labels,
                   const hng::role_label_t& label)
{
    if (compare == hng::FilterCompare::PREFIX) {
        return label_has_prefix(sorted_labels, label);
    }
    const bool hit = contains(sorted_labels, label);
    return compare == hng::FilterCompare::NE ? !hit : hit;
}

bool atom_matches(const hng::FilterAtom& atom,
                  const hng::RuntimeInformation& info)
{
    if (atom.field == hng::FilterField::ROLE_LABEL) {
        return label_matches(atom.compare, atom.strings, info.roleLabel);
    }
    // PREFIX 仅对 ROLE_LABEL 有效，非法组合由订阅入口拒绝，这里不求值
    if (atom.compare == hng::FilterCompare::PREFIX) {
        return false;
    }
    const bool hit = contains(atom.numbers, field_value(atom.field, info));
    return atom.compare == hng::FilterCompare::NE ? !hit : hit;
}

}  // namespace

bool FilterExpr::Node::match(const hng::RuntimeInformation& info) const
{
    switch (op) {
        case Op::ATOM:
            return atom_matches(atom, info);
        case Op::AND:
            for (const hng::FilterExpr& operand : operands) {
                if (!operand.matches(info)) {
                    return false;
                }
            }
            return true;
        case Op::OR:
            for (const hng::FilterExpr& operand : operands) {
                if (operand.matches(info)) {
                    return true;
                }
            }
            return false;
        case Op::NOT:
            return operands.size() == 1 && !operands.front().matches(info);
    }
    return true;
}

FilterExpr FilterExpr::make_atom(FilterAtom atom)
{
    sort_unique(atom.numbers);
    sort_unique(atom.strings);

    auto node  = std::make_shared<Node>();
    node->op   = Node::Op::ATOM;
    node->atom = std::move(atom);

    FilterExpr expr;
    expr.root_ = std::move(node);
    return expr;
}

FilterExpr FilterExpr::make_and(std::vector<FilterExpr> operands)
{
    if (operands.empty()) {
        return FilterExpr{};
    }
    auto node      = std::make_shared<Node>();
    node->op       = Node::Op::AND;
    node->operands = std::move(operands);

    FilterExpr expr;
    expr.root_ = std::move(node);
    return expr;
}

FilterExpr FilterExpr::make_or(std::vector<FilterExpr> operands)
{
    auto node      = std::make_shared<Node>();
    node->op       = Node::Op::OR;
    node->operands = std::move(operands);

    FilterExpr expr;
    expr.root_ = std::move(node);
    return expr;
}

FilterExpr FilterExpr::make_not(FilterExpr operand)
{
    auto node = std::make_shared<Node>();
    node->op  = Node::Op::NOT;
    node->operands.push_back(std::move(operand));

    FilterExpr expr;
    expr.root_ = std::move(node);
    return expr;
}

bool FilterExpr::matches(const hng::RuntimeInformation& info) const
{
    return root_ != nullptr ? root_->match(info) : true;
}

}  // namespace hng
