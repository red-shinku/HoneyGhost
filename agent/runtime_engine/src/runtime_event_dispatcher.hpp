/**
 * @file runtime_event_dispatcher.hpp
 * @brief 事件到订阅者的分发
 * @author red-shinku
 * @date 2026.10.11
 */
#ifndef HNG_RUNTIME_EVENT_DISPATCHER_HPP_
#define HNG_RUNTIME_EVENT_DISPATCHER_HPP_

#include <cstddef>
#include <vector>

#include "agent/context_maintainer/include/context_maintainer_decision.hpp"
#include "agent/event_data/include/runtime_event.hpp"
#include "agent/event_data/include/runtime_info_filter.hpp"
#include "agent/runtime_engine/include/runtime_decision_sink.hpp"
#include "agent/runtime_engine/include/runtime_event_sink.hpp"
#include "agent/runtime_engine/include/subscriber_reg_service.hpp"

/**
 * @brief 事件分发器
 * @details 维护系统订阅和CLI订阅两张表。
 * 表由引擎线程独占使用，不加锁
 */
class RuntimeEventDispatcher {
   public:
    /// @brief 一条 CLI 订阅流
    struct CliSink {
        RuntimeEventSink* sink = nullptr;  ///< 订阅流对象，不拥有
        RuntimeInfoFilter filter;          ///< 该流关心的运行时信息
        UnsubscribeAck* ack = nullptr;     ///< 销号回执，不拥有；可为空
    };

    /// @brief 登记系统订阅者
    /// @param sink 订阅者对象，不拥有；须存活到引擎停机
    /// @note 仅在 run() 之前调用；同一 sink 重复登记会重复投递
    void add_system_sink(RuntimeDecisionSink* sink);

    /// @brief 登记一条 CLI 订阅流
    /// @param sink 订阅流对象，不拥有；须存活到销号回执返回
    /// @param filter 该流关心的运行时信息
    /// @param ack 该流的销号回执，不拥有；可为空
    /// @note 同一 sink 不占两个表项，重复登记以本次的过滤器与回执为准
    void add_cli_sink(RuntimeEventSink* sink, RuntimeInfoFilter filter,
                      UnsubscribeAck* ack);

    /// @brief 摘除一条 CLI 订阅流，并回调其销号回执
    /// @return 表中有该 sink 并被摘除为 true；否则为空操作，返回 false
    /// @note 只有实际摘表才回调，故回执至多一次
    bool remove_cli_sink(RuntimeEventSink* sink);

    /// @brief 分发一个事件
    /// @param event 已填齐运行时信息的事件
    /// @param decision 本条事件引发的派生决策
    /// @note 先系统订阅表、后 CLI 订阅表
    void dispatch(const hng::RuntimeEvent& event,
                  const ContextDeriveDecision& decision);

    /// @brief 清空两张订阅表；不触碰订阅者对象本身
    /// @note CLI 表内每条流都会收到销号回执，故停机路径不依赖注销命令
    void clear();

    /// @brief 当前 CLI 订阅流数量
    std::size_t cli_sink_count() const { return cli_sinks_.size(); }

   private:
    std::vector<RuntimeDecisionSink*> system_sinks_;
    std::vector<CliSink> cli_sinks_;
};

#endif  // HNG_RUNTIME_EVENT_DISPATCHER_HPP_
