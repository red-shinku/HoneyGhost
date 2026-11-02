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
 * @brief 回执，实现方收到ack后引擎不会再调用 sink，可安全析构相关流
 * @details
 * 触发点有两处：订阅者被移除、引擎停机清表，不依赖注销命令是否入队成功。
 * @warning 回调在引擎线程（普通线程）上执行，实现方不得阻塞、不得抛异常，也不得
 * 据此认为引擎已停止工作——回调返回前引擎线程仍在运行
 */
class UnsubscribeAck {
   protected:
    virtual ~UnsubscribeAck() = default;

   public:
    /// @brief 本 sink 已离开订阅表
    virtual void on_unsubscribed() = 0;
};

/**
 * @brief 订阅登记的入口，由引擎实现，供订阅流的持有方调用
 * @details 两个方法都是通知写：入队即返回，落地在引擎线程上。注册生效之前产生的
 * 事件不补发。
 */
class SubscriberRegService {
   protected:
    virtual ~SubscriberRegService() = default;

   public:
    /// @brief 注册订阅流
    /// @param sink 订阅流对象，本服务不拥有；其存活期须覆盖到销号回执返回
    /// @param filter 该流关心的运行时信息
    /// @param ack 该流的销号回执，本服务不拥有；空指针表示不需要回执
    /// @return 已入队为 true；引擎已停机、命令被拒绝时为 false
    /// @note 返回 false 时订阅不成立，也不会有回执
    virtual bool subscribe(RuntimeEventSink* sink, RuntimeInfoFilter filter,
                           UnsubscribeAck* ack)      = 0;

    /// @brief 注销一条订阅流
    /// @param sink 之前注册的订阅流对象
    /// @note 入队成功不代表已注销，以 subscribe 时给出的 ack 为准
    /// @note 对已不在订阅表内的 sink 是空操作，不会重复回调 ack
    /// @note 入队被拒（引擎已停机）不改变回执保证：停机清表时仍会回调
    virtual void unsubscribe(RuntimeEventSink* sink) = 0;
};

#endif  // HNG_SUBSCRIBER_REG_SERVICE_HPP_
