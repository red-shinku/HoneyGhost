/**
 * @file chain_feeder.hpp
 * @brief chain 段的回放生产者：语料 → 原始事件通道
 * @details
 * chain 段没有真实采集器，生产侧由本文件的回放生产者承担。
 */

#ifndef HNG_TEST_BENCH_CHAIN_FEEDER_HPP_
#define HNG_TEST_BENCH_CHAIN_FEEDER_HPP_

#include "agent/collector/src/collector.hpp"
#include "agent/util/include/event_channel.hpp"
#include "kernel/include/syscall_event_type.h"
#include "test/bench/bench_trace.hpp"
#include "test/bench/support.hpp"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace bench::chain {

/// @brief 回放的事件类别；PROCESS 与 EXEC 归为 lifecycle
enum class EventClass : std::uint8_t { ALL, SYSCALL, LIFECYCLE };

/// @brief 类别在命令行与结果配置里的名字
inline const char* event_class_name(EventClass value)
{
    switch (value) {
        case EventClass::SYSCALL:
            return "syscall";
        case EventClass::LIFECYCLE:
            return "lifecycle";
        case EventClass::ALL:
            break;
    }
    return "all";
}

/// @brief 该子类型是否属于 lifecycle（进程与 exec）
inline bool is_lifecycle_class(enum syscall_event_type subtype)
{
    return subtype == PROCESS_EVENT || subtype == EXEC_EVENT;
}

/// @brief 该子类型是否落在所选类别里
inline bool class_selected(EventClass mode, enum syscall_event_type subtype)
{
    switch (mode) {
        case EventClass::SYSCALL:
            return !is_lifecycle_class(subtype);
        case EventClass::LIFECYCLE:
            return is_lifecycle_class(subtype);
        case EventClass::ALL:
            break;
    }
    return true;
}

/**
 * @brief 按 head + payload 两段把语料记录拷进事件
 * @param[in] record 已通过定长校验的记录（事件头 + 该子类型的定长载荷）
 * @param[out] event 调用方提供的栈上事件，载荷之外的字节保持原值
 * @note 重建方式与采集器一致：先拷头，再拷「记录长度 - 头长度」字节的载荷。
 *       记录未按 SyscallRecordSize 校验时不得调用本函数。
 */
inline void rebuild_event(const std::vector<char>& record,
                          struct syscall_event& event)
{
    std::memcpy(&event.hdr, record.data(), sizeof(event.hdr));
    std::memcpy(reinterpret_cast<char*>(&event) + sizeof(event.hdr),
                record.data() + sizeof(event.hdr),
                record.size() - sizeof(event.hdr));
}

/// @brief 回放生产的累计计数快照
struct FeederCounters {
    std::uint64_t consumed = 0;  ///< 已回放记录数，含随后被通道拒收的记录
    /// 已回放记录中 lifecycle 类的记录数；syscall 类可由 consumed 相减得到
    std::uint64_t consumed_lifecycle = 0;
    std::uint64_t malformed          = 0;  ///< 加载期定长校验失败的记录数
    std::uint64_t push_ok            = 0;  ///< 成功入队的记录数
    std::uint64_t push_fail          = 0;  ///< 被通道拒收的记录数
};

/**
 * @brief 语料回放生产者
 * @details 加载期完成定长校验与类别筛选；回放期按节拍循环所选记录，在栈上
 *          重建事件后推入原始通道。不持有 BPF 资源，也不重试被拒收的入队。
 * @note load() 只由主线程调用；run() 只由一条回放线程调用；counters() 可从
 *       任意线程调用。
 * @see FeederCounters, bench::chain::rebuild_event
 */
class ChainFeeder final {
   public:
    /**
     * @brief 读入语料并完成定长校验与类别筛选
     * @param[in] path 语料路径
     * @param[in] events 参与回放的类别；records() 始终保留全量记录
     * @param[out] error 失败原因
     * @return 成功时为 true
     * @note 定长校验失败（不足一个事件头、未知子类型或长度与
     *       SyscallRecordSize 不符）的记录计入 malformed() 并跳过；全部记录
     *       都不合法或所选类别为空时返回 false。
     */
    bool load(const std::string& path, EventClass events, std::string& error);

    /// @brief 通过定长校验的全部记录，按语料顺序；供种子使用
    const std::vector<std::vector<char>>& records() const;

    /// @brief 参与回放的记录下标，按语料顺序
    const std::vector<std::size_t>& playback() const;

    /// @brief 加载期定长校验失败的记录数
    std::uint64_t malformed() const;

    /**
     * @brief 回放线程入口
     * @param[in,out] raw 原始事件通道写端
     * @param[in] stop 置位后停止回放
     * @param[in] rate 目标速率，记录/s；0 表示全速
     * @note 只应由一条线程调用。通道拒收只计数、不重试，与采集器「记录被
     *       通道丢弃」的语义一致。
     */
    void run(hng::EventChannelWriter<struct syscall_event>& raw,
             const std::atomic<bool>& stop, double rate);

    /// @brief 累计计数快照
    FeederCounters counters() const;

   private:
    std::vector<std::vector<char>> records_;  ///< 定长校验通过的记录原文
    std::vector<std::size_t> playback_;       ///< 参与回放的 records_ 下标
    std::uint64_t malformed_ = 0;             ///< 校验失败的记录数
    std::atomic<std::uint64_t> consumed_{0};  ///< 已回放记录数
    /// 已回放记录中的 lifecycle 类计数
    std::atomic<std::uint64_t> consumed_lifecycle_{0};
    std::atomic<std::uint64_t> push_ok_{0};    ///< 成功入队次数
    std::atomic<std::uint64_t> push_fail_{0};  ///< 被拒收次数
};

inline bool ChainFeeder::load(const std::string& path, EventClass events,
                              std::string& error)
{
    records_.clear();
    playback_.clear();
    malformed_ = 0;

    bench::TraceReader reader;
    std::string reader_error;
    if (!reader.open(path, reader_error)) {
        error = "failed to open trace " + path + ": " + reader_error;
        return false;
    }

    std::vector<char> record;
    while (reader.next(record, reader_error)) {
        if (record.size() < sizeof(struct syscall_event_head)) {
            ++malformed_;
            continue;
        }
        struct syscall_event_head head;
        std::memcpy(&head, record.data(), sizeof(head));
        const std::size_t expected = hng::detail::SyscallRecordSize(head.subtype);
        if (expected == 0 || record.size() != expected) {
            ++malformed_;
            continue;
        }
        records_.push_back(record);
        if (!class_selected(events, head.subtype)) {
            continue;
        }
        playback_.push_back(records_.size() - 1);
    }
    if (!reader_error.empty()) {
        error = "failed to read trace " + path + ": " + reader_error;
        return false;
    }
    if (records_.empty()) {
        error = "trace " + path + " has no usable records (malformed " +
                std::to_string(malformed_) + " records)";
        return false;
    }
    if (playback_.empty()) {
        error = "trace under --events " + std::string(event_class_name(events)) +
                " has no replayable records";
        return false;
    }
    return true;
}

inline const std::vector<std::vector<char>>& ChainFeeder::records() const
{
    return records_;
}

inline const std::vector<std::size_t>& ChainFeeder::playback() const
{
    return playback_;
}

inline std::uint64_t ChainFeeder::malformed() const { return malformed_; }

inline void ChainFeeder::run(hng::EventChannelWriter<struct syscall_event>& raw,
                             const std::atomic<bool>& stop, double rate)
{
    std::unique_ptr<bench::Pacer> pacer;
    if (rate > 0.0) {
        pacer = std::make_unique<bench::Pacer>(rate);
    }

    std::uint64_t index = 0;
    while (!stop.load(std::memory_order_acquire)) {
        for (const std::size_t offset : playback_) {
            if (stop.load(std::memory_order_relaxed)) {
                break;
            }
            if (pacer) {
                (void)pacer->wait(index);
            }
            ++index;

            struct syscall_event event{};
            rebuild_event(records_[offset], event);
            consumed_.fetch_add(1, std::memory_order_relaxed);
            if (is_lifecycle_class(event.hdr.subtype)) {
                consumed_lifecycle_.fetch_add(1, std::memory_order_relaxed);
            }
            if (raw.push(std::move(event))) {
                push_ok_.fetch_add(1, std::memory_order_relaxed);
            }
            else {
                push_fail_.fetch_add(1, std::memory_order_relaxed);
            }
        }
    }
}

inline FeederCounters ChainFeeder::counters() const
{
    FeederCounters snapshot;
    snapshot.consumed = consumed_.load(std::memory_order_relaxed);
    snapshot.consumed_lifecycle =
        consumed_lifecycle_.load(std::memory_order_relaxed);
    snapshot.malformed = malformed_;
    snapshot.push_ok   = push_ok_.load(std::memory_order_relaxed);
    snapshot.push_fail = push_fail_.load(std::memory_order_relaxed);
    return snapshot;
}

}  // namespace bench::chain

#endif  // HNG_TEST_BENCH_CHAIN_FEEDER_HPP_
