/**
 * @file runtime_engine_component.cc
 * @brief 运行时引擎组件：生命周期状态、存活名额与引擎转发。
 */
#include "agent/runtime_engine/include/runtime_engine_component.hpp"

#include "agent/runtime_engine/include/runtime_engine_factory.hpp"
#include "agent/runtime_engine/src/runtime_engine.hpp"
#include "agent/util/include/single_instance_guard.hpp"

#include <atomic>
#include <memory>
#include <utility>

namespace hng {

struct RuntimeEngineComponent::Impl {
    /**
     * @brief 先占用存活名额，再按选项接线引擎。
     * @param taken 本创建方法的存活标志
     * @param options 语义队列与控制平面服务的借用指针
     * @throws std::logic_error 名额已被占用
     */
    Impl(std::atomic<bool>& taken, const RuntimeEngineOptions& options)
        : guard(taken, "RuntimeEngineComponent"),
          engine(options.syscall_queue, options.file_queue,
                 options.ctx_maintainer, options.process_join,
                 options.process_update, options.role_join, options.role_lookup)
    {
    }

    hng::detail::SingleInstanceGuard guard;
    std::atomic<hng::ComponentState> state{hng::ComponentState::READY};
    ::RuntimeEngine engine;
};

RuntimeEngineComponent::RuntimeEngineComponent(std::unique_ptr<Impl> impl)
    : impl_(std::move(impl))
{
}

RuntimeEngineComponent::~RuntimeEngineComponent() = default;

SubscriberRegService& RuntimeEngineComponent::subscriber_service() noexcept
{
    return static_cast<::SubscriberRegService&>(impl_->engine);
}

void RuntimeEngineComponent::add_system_sink(RuntimeDecisionSink* sink)
{
    impl_->engine.add_system_sink(sink);
}

RuntimeEngineStats RuntimeEngineComponent::stats() const
{
    return impl_->engine.stats();
}

hng::ComponentState RuntimeEngineComponent::state() const
{
    return impl_->state.load();
}

void RuntimeEngineComponent::run()
{
    hng::ComponentState expected = hng::ComponentState::READY;
    if (impl_->state.compare_exchange_strong(expected,
                                             hng::ComponentState::RUNNING)) {
        impl_->engine.run();
        impl_->state.store(hng::ComponentState::STOPPED);
        return;
    }
    if (expected == hng::ComponentState::RUNNING) return;
    impl_->engine.run();
}

void RuntimeEngineComponent::stop()
{
    impl_->engine.stop();
    impl_->state.store(hng::ComponentState::STOPPED);
}

std::unique_ptr<RuntimeEngineComponent> RuntimeEngineFactory::create(
    RuntimeEngineOptions options)
{
    static std::atomic<bool> taken{false};
    auto impl = std::make_unique<RuntimeEngineComponent::Impl>(taken, options);
    return std::unique_ptr<RuntimeEngineComponent>(
        new RuntimeEngineComponent(std::move(impl)));
}

}  // namespace hng
