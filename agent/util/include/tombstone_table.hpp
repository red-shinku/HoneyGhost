/**
 * @file tombstone_table.hpp
 * @brief 已退出身份的墓碑表
 * @details
 * 记录近期已退出的身份，供迟到写入的关系拒绝或降级时查询；条目按 ttl 过期，
 * 容量满时淘汰最旧条目。
 * @author red_shinku
 * @date 2026.10.23
 */

#ifndef HNG_TOMBSTONE_TABLE_HPP_
#define HNG_TOMBSTONE_TABLE_HPP_

#include "agent/util/include/deferred_relation_table.hpp"

#include <chrono>
#include <cstddef>
#include <iterator>
#include <list>
#include <optional>
#include <unordered_map>
#include <utility>

namespace hng {

/**
 * @brief 墓碑表的容量与寿命参数
 */
struct TombstoneOptions {
    std::size_t capacity = 8192;            ///< 最多保留的墓碑数；0 表示不保留
    std::chrono::milliseconds ttl{60'000};  ///< 墓碑寿命；0 表示不按时间过期
};

/**
 * @brief 已退出身份的墓碑表
 * @tparam Identity 身份类型，需支持 std::hash 与 operator==
 * @tparam Info 首次退出时保留的信息，需可拷贝
 * @details
 * 以链表保存入表顺序，身份到链表位置的索引使查询与删除不做整表扫描：add、find
 * 期望 O(1)，expire 为 O(清除的条目数)。
 * @note 非线程安全：由调用方在外层加锁或只在单线程访问。
 * @note 时间由调用方显式传入；now 在连续调用间不得回退。
 * @note 同一身份以首次记录为准，重复记录不覆盖已有的 Info。
 * @see TombstoneOptions
 * @see RelationTimePoint
 */
template <class Identity, class Info>
class TombstoneTable {
   public:
    /// @brief 构造空表
    /// @param options 容量与寿命参数
    explicit TombstoneTable(TombstoneOptions options = {});

    /// @brief 记录一个已退出身份
    /// @param identity 身份
    /// @param info 首次退出时保留的信息
    /// @param now 入表时间，用于过期判断与淘汰顺序
    /// @return 已记录为 true；同身份未过期已存在为 false，内容不变
    /// @note 容量已满时先按入表顺序淘汰最旧条目再记录。
    /// @note 容量为 0 时不记录，返回 false。
    bool add(const Identity& identity, Info info, RelationTimePoint now);

    /// @brief 查找墓碑
    /// @param identity 身份
    /// @param now 当前时间，不得早于此前调用传入的时间
    /// @return 命中且未过期时为对应的 Info；未命中或已过期时为 std::nullopt
    /// @note 命中但已过期时就地清除该条目。
    std::optional<Info> find(const Identity& identity, RelationTimePoint now);

    /// @brief 清除过期条目
    /// @param now 当前时间，不得早于此前调用传入的时间
    /// @return 清除的条目数；ttl 为 0 时恒为 0
    std::size_t expire(RelationTimePoint now);

    /// @brief 表中的墓碑数
    std::size_t size() const;

   private:
    struct Node {
        Identity identity;
        Info info;
        RelationTimePoint inserted;
    };

    using NodeList     = std::list<Node>;
    using NodeIterator = typename NodeList::iterator;

    /// @brief 移除条目并清理索引
    void erase_node(NodeIterator node);

    TombstoneOptions options_;
    NodeList entries_;
    std::unordered_map<Identity, NodeIterator> index_;
};

template <class Identity, class Info>
TombstoneTable<Identity, Info>::TombstoneTable(TombstoneOptions options)
    : options_(options)
{
}

template <class Identity, class Info>
bool TombstoneTable<Identity, Info>::add(const Identity& identity, Info info,
                                         RelationTimePoint now)
{
    auto index_it = index_.find(identity);
    if (index_it != index_.end()) {
        const bool expired = options_.ttl.count() != 0 &&
                             now - index_it->second->inserted > options_.ttl;
        if (!expired) {
            return false;
        }
        erase_node(index_it->second);
    }

    if (options_.capacity == 0) {
        return false;
    }
    while (entries_.size() >= options_.capacity) {
        index_.erase(entries_.front().identity);
        entries_.pop_front();
    }

    entries_.push_back(Node{identity, std::move(info), now});
    index_.emplace(identity, std::prev(entries_.end()));
    return true;
}

template <class Identity, class Info>
std::optional<Info> TombstoneTable<Identity, Info>::find(
    const Identity& identity, RelationTimePoint now)
{
    auto index_it = index_.find(identity);
    if (index_it == index_.end()) {
        return std::nullopt;
    }
    if (options_.ttl.count() != 0 &&
        now - index_it->second->inserted > options_.ttl) {
        erase_node(index_it->second);
        return std::nullopt;
    }
    return index_it->second->info;
}

template <class Identity, class Info>
std::size_t TombstoneTable<Identity, Info>::expire(RelationTimePoint now)
{
    std::size_t removed = 0;
    if (options_.ttl.count() == 0) {
        return removed;
    }
    while (!entries_.empty() &&
           now - entries_.front().inserted > options_.ttl) {
        index_.erase(entries_.front().identity);
        entries_.pop_front();
        ++removed;
    }
    return removed;
}

template <class Identity, class Info>
std::size_t TombstoneTable<Identity, Info>::size() const
{
    return entries_.size();
}

template <class Identity, class Info>
void TombstoneTable<Identity, Info>::erase_node(NodeIterator node)
{
    index_.erase(node->identity);
    entries_.erase(node);
}

}  // namespace hng

#endif  // HNG_TOMBSTONE_TABLE_HPP_
