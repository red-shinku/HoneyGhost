/**
 * @file deferred_relation_table.hpp
 * @brief 按锚点暂存、按等待方去重的pending关系表
 * @details
 * 此处锚点意思是：本落地任务(task to land)依赖的键，该键还未落地，需等待。
 * 关系先于其锚点到达时暂存于此；锚点落地或过期后由调用方按锚点取出并应用，
 * 表本身不解释关系语义。
 * @author red_shinku
 * @date 2026.10.23
 */

#ifndef HNG_DEFERRED_RELATION_TABLE_HPP_
#define HNG_DEFERRED_RELATION_TABLE_HPP_

#include <chrono>
#include <cstddef>
#include <iterator>
#include <list>
#include <optional>
#include <unordered_map>
#include <utility>
#include <vector>

namespace hng {

/// @brief 通用件的显式时间点类型
using RelationTimePoint = std::chrono::steady_clock::time_point;

/**
 * @brief 延迟关系表的容量与寿命参数
 */
struct DeferredRelationOptions {
    std::size_t capacity = 4096;            ///< 最多暂存的关系条数；0 表示不接收
    std::chrono::milliseconds ttl{60'000};  ///< 入表后的寿命；0 表示不按时间过期
};

/**
 * @brief 按锚点暂存、按等待方去重的关系表
 * @tparam Anchor 锚点类型，需支持 std::hash 与 operator==
 * @tparam Waiter 等待方类型，需支持 std::hash 与 operator==
 * @tparam Action 取出后由调用方应用的动作类型，需可移动
 * @details
 * 表内以链表保存入表顺序，并维护锚点、等待方到链表位置的索引，各接口不做整表
 * 扫描：defer 期望 O(1)，take 为 O(该锚点的条目数)，cancel 期望 O(1)，expire
 * 为 O(过期条目数)。 TODO: 超时、容量满被淘汰的条目打印 DEBUG 日志
 * @note 非线程安全：由调用方（消费线程）串行化访问。
 * @note 时间由调用方显式传入；now 在连续调用间不得回退。
 * @see DeferredRelationOptions
 */
template <class Anchor, class Waiter, class Action>
class DeferredRelationTable {
   public:
    enum class Result {
        DEFERRED,   ///< 已入表
        DUPLICATE,  ///< 同一等待方已在表中，保留首条
        FULL        ///< 已达容量上限，未入表
    };

    /// @brief 一条暂存的关系
    struct Entry {
        Anchor anchor;  ///< 等待的锚点
        Waiter waiter;  ///< 等待方
        Action action;  ///< 锚点处理时应用的动作
    };

    /// @brief 构造空表
    /// @param options 容量与寿命参数
    explicit DeferredRelationTable(DeferredRelationOptions options = {});

    /// @brief 暂存一条等待锚点的关系；同一等待方全表至多一条
    /// @param anchor 等待的锚点
    /// @param waiter 等待方
    /// @param action 锚点处理时应用的动作
    /// @param now 入表时间，用于过期判断
    /// @return 入表为 DEFERRED；等待方已在表中为 DUPLICATE；容量已满为 FULL
    /// @note DUPLICATE 与 FULL 均不改变表的内容。
    Result defer(const Anchor& anchor, const Waiter& waiter, Action action,
                 RelationTimePoint now);

    /// @brief 取出并删除某锚点的全部等待项
    /// @param anchor 锚点
    /// @return 该锚点的全部条目，按入表顺序；没有条目时为空
    std::vector<Entry> take(const Anchor& anchor);

    /// @brief 删除某等待方的等待项
    /// @param waiter 等待方
    /// @return 被删除的条目；表中没有该等待方时为 std::nullopt
    std::optional<Entry> cancel(const Waiter& waiter);

    /// @brief 取出并删除超过 ttl 的等待项
    /// @param now 当前时间，不得早于此前调用传入的时间
    /// @return 被删除的条目，按入表顺序；ttl 为 0 时恒为空
    std::vector<Entry> expire(RelationTimePoint now);

    /// @brief 表中的关系条数
    std::size_t size() const;

    /// @brief 表是否为空
    bool empty() const;

   private:
    struct Node {
        Anchor anchor;
        Waiter waiter;
        Action action;
        RelationTimePoint inserted;
    };

    using NodeList             = std::list<Node>;
    using NodeIterator         = typename NodeList::iterator;
    /// @brief 同一锚点的条目位置，保持入表顺序
    using AnchorBucket         = std::list<NodeIterator>;
    using AnchorBucketIterator = typename AnchorBucket::iterator;

    struct WaiterPosition {
        NodeIterator node;                 ///< 条目在链表中的位置
        AnchorBucketIterator bucket_slot;  ///< 条目在所属锚点桶中的位置
    };

    /// @brief 移除条目并清理两处索引，返回被移除的条目
    Entry detach(NodeIterator node);

    DeferredRelationOptions options_;
    NodeList entries_;
    std::unordered_map<Anchor, AnchorBucket> by_anchor_;
    std::unordered_map<Waiter, WaiterPosition> by_waiter_;
};

template <class Anchor, class Waiter, class Action>
DeferredRelationTable<Anchor, Waiter, Action>::DeferredRelationTable(
    DeferredRelationOptions options)
    : options_(options)
{
}

template <class Anchor, class Waiter, class Action>
typename DeferredRelationTable<Anchor, Waiter, Action>::Result
DeferredRelationTable<Anchor, Waiter, Action>::defer(const Anchor& anchor,
                                                     const Waiter& waiter,
                                                     Action action,
                                                     RelationTimePoint now)
{
    if (by_waiter_.find(waiter) != by_waiter_.end()) {
        return Result::DUPLICATE;
    }
    if (entries_.size() >= options_.capacity) {
        return Result::FULL;
    }

    entries_.push_back(Node{anchor, waiter, std::move(action), now});
    NodeIterator node    = std::prev(entries_.end());
    AnchorBucket& bucket = by_anchor_[anchor];
    bucket.push_back(node);
    by_waiter_.emplace(waiter, WaiterPosition{node, std::prev(bucket.end())});
    return Result::DEFERRED;
}

template <class Anchor, class Waiter, class Action>
std::vector<typename DeferredRelationTable<Anchor, Waiter, Action>::Entry>
DeferredRelationTable<Anchor, Waiter, Action>::take(const Anchor& anchor)
{
    std::vector<Entry> taken;
    auto anchor_it = by_anchor_.find(anchor);
    if (anchor_it == by_anchor_.end()) {
        return taken;
    }

    const AnchorBucket bucket = std::move(anchor_it->second);
    by_anchor_.erase(anchor_it);
    taken.reserve(bucket.size());
    for (NodeIterator node : bucket) {
        taken.push_back(detach(node));
    }
    return taken;
}

template <class Anchor, class Waiter, class Action>
std::optional<typename DeferredRelationTable<Anchor, Waiter, Action>::Entry>
DeferredRelationTable<Anchor, Waiter, Action>::cancel(const Waiter& waiter)
{
    auto waiter_it = by_waiter_.find(waiter);
    if (waiter_it == by_waiter_.end()) {
        return std::nullopt;
    }
    return detach(waiter_it->second.node);
}

template <class Anchor, class Waiter, class Action>
std::vector<typename DeferredRelationTable<Anchor, Waiter, Action>::Entry>
DeferredRelationTable<Anchor, Waiter, Action>::expire(RelationTimePoint now)
{
    std::vector<Entry> expired;
    if (options_.ttl.count() == 0) {
        return expired;
    }

    while (!entries_.empty() && now - entries_.front().inserted > options_.ttl) {
        expired.push_back(detach(entries_.begin()));
    }
    return expired;
}

template <class Anchor, class Waiter, class Action>
std::size_t DeferredRelationTable<Anchor, Waiter, Action>::size() const
{
    return entries_.size();
}

template <class Anchor, class Waiter, class Action>
bool DeferredRelationTable<Anchor, Waiter, Action>::empty() const
{
    return entries_.empty();
}

template <class Anchor, class Waiter, class Action>
typename DeferredRelationTable<Anchor, Waiter, Action>::Entry
DeferredRelationTable<Anchor, Waiter, Action>::detach(NodeIterator node)
{
    auto waiter_it = by_waiter_.find(node->waiter);
    if (waiter_it != by_waiter_.end()) {
        auto anchor_it = by_anchor_.find(node->anchor);
        if (anchor_it != by_anchor_.end()) {
            anchor_it->second.erase(waiter_it->second.bucket_slot);
            if (anchor_it->second.empty()) {
                by_anchor_.erase(anchor_it);
            }
        }
        by_waiter_.erase(waiter_it);
    }

    Entry entry{std::move(node->anchor), std::move(node->waiter),
                std::move(node->action)};
    entries_.erase(node);
    return entry;
}

}  // namespace hng

#endif  // HNG_DEFERRED_RELATION_TABLE_HPP_
