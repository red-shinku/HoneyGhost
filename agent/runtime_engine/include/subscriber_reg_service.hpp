/**
 * @file subscriber_reg_service.hpp
 * @brief 按需订阅流的注册与注销接口
 * @author red-shinku
 * @date 2026.10.10
 */
#ifndef HNG_SUBSCRIBER_REG_SERVICE_HPP_
#define HNG_SUBSCRIBER_REG_SERVICE_HPP_

#include "agent/event_data/include/runtime_info_filter.hpp"
#include "agent/runtime_engine/include/runtime_event_sink.hpp"

/**
 * @brief 注销完成的回执
 * @details 由发起注销的一方（订阅流）实现，引擎线程摘除订阅表项后回调。
 * 回调之后不会再有流的 on_event 回调，实现方收到即可安全析构。
 */
class UnsubscribeAck {
   protected:
    virtual ~UnsubscribeAck() = default;

   public:
    /// @brief 引擎线程已注销该订阅流
    virtual void on_unsubscribed() = 0;
};

/**
 * @brief 订阅登记的入口，由引擎实现，供订阅流的持有方调用
 * @details 两个方法都是通知写：入队即返回，落地在引擎线程上；引擎停机后入队
 * 被拒绝。注册生效之前产生的事件不补发。
 */
class SubscriberRegService {
   protected:
    virtual ~SubscriberRegService() = default;

   public:
    /// @brief 注册订阅流
    /// @param sink 订阅流对象，本服务不拥有；其存活期须覆盖到注销回执返回
    /// @param filter 该流关心的运行时信息
    /// @return 已入队为 true；引擎已停机、命令被拒绝时为 false
    virtual bool subscribe(RuntimeEventSink* sink, RuntimeInfoFilter filter) = 0;

    /// @brief 注销一路订阅流
    /// @param sink 之前注册的订阅流对象
    /// @param ack 引擎注销完成后的回调
    /// @return 通知已入队为 true；通知被拒绝时为 false
    /// @note 入队成功不代表已注销，以 ack 为准。对未注册的 sink 注销是空操作，
    /// 仍会收到 ack
    virtual bool unsubscribe(RuntimeEventSink* sink, UnsubscribeAck* ack)    = 0;
};

#endif  // HNG_SUBSCRIBER_REG_SERVICE_HPP_
