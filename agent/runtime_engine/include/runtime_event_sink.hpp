/**
 * @file runtime_event_sink.hpp
 * @brief 按需订阅流的接收接口
 * @author red-shinku
 * @date 2026.10.10
 */
#ifndef HNG_RUNTIME_EVENT_SINK_HPP_
#define HNG_RUNTIME_EVENT_SINK_HPP_

#include "agent/event_data/include/runtime_event.hpp"

/**
 * @brief 需要按需接受运行时事件的订阅流，
 * 继承该接口并实现接受逻辑
 */
class RuntimeEventSink {
   protected:
    virtual ~RuntimeEventSink() = default;

   public:
    virtual void on_event(const hng::RuntimeEvent) = 0;
};

#endif  // HNG_RUNTIME_EVENT_SINK_HPP_