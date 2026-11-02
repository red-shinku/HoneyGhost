/**
 * @file cli_stream.cc
 * @brief CLIStream 的实现
 * @author red-shinku
 * @date 2026.10.16
 */

#include "agent/cli_server/src/cli_stream.hpp"

#include <utility>

#include <userver/engine/task/cancel.hpp>
#include <userver/utils/assert.hpp>

#include "agent/cli_server/src/cli_stream_manager.hpp"

CLIStream::CLIStream(CLIStreamManager& owner, SubscriberRegService& engine,
                     RuntimeInfoFilter filter, std::size_t queue_capacity)
    : owner_(owner),
      engine_(engine),
      filter_(std::move(filter)),
      queue_(queue_capacity)
{
    owner_.attach(this);
}

CLIStream::~CLIStream()
{
    UASSERT_MSG(torn_down_, "CLIStream must be torn down before destruction");
}

void CLIStream::on_event(const hng::RuntimeEvent event)
{
    // TODO: 性能优化点：形参带 const，移动不出来，此处只能拷贝
    queue_.push(event);
}

void CLIStream::on_unsubscribed()
{
    unsubscribed_.store(true, std::memory_order_release);
    queue_.wake();
}

bool CLIStream::subscribe()
{
    subscribed_ = engine_.subscribe(this, filter_, this);
    return subscribed_;
}

void CLIStream::teardown()
{
    if (torn_down_) {
        return;
    }
    torn_down_ = true;

    if (subscribed_) {
        // 等待期间不得被取消打断：半途退出会带着未回执的流析构，而引擎仍可能回调
        const userver::engine::TaskCancellationBlocker blocker;
        engine_.unsubscribe(this);
        while (!unsubscribed_.load(std::memory_order_acquire)) {
            queue_.wait();
        }
    }
    owner_.detach(this);
}

bool CLIStream::try_pop(hng::RuntimeEvent& out, std::size_t& cursor)
{
    return queue_.try_pop(out, cursor);
}

uint64_t CLIStream::dropped() const { return queue_.dropped(); }

bool CLIStream::finished() const
{
    return queue_.closed() || unsubscribed_.load(std::memory_order_acquire);
}

bool CLIStream::wait() { return queue_.wait(); }

void CLIStream::close() { queue_.close(); }
