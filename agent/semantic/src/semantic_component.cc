/**
 * @file semantic_component.cc
 * @brief 语义组件：存活名额与聚合转发。
 */
#include "agent/semantic/include/semantic_component.hpp"

#include "agent/semantic/include/semantic_factory.hpp"
#include "agent/semantic/src/semantic.hpp"
#include "agent/util/include/single_instance_guard.hpp"

#include <atomic>
#include <memory>
#include <utility>

namespace hng {

struct SemanticComponent::Impl {
    /**
     * @brief 先占用存活名额，再按选项绑定四条队列。
     * @param taken 本创建方法的存活标志
     * @param options 两条原始队列与两条语义队列
     * @throws std::logic_error 名额已被占用
     */
    Impl(std::atomic<bool>& taken, const SemanticOptions& options)
        : guard(taken, "SemanticComponent"),
          aggregate(options.raw_file, options.raw_syscall, options.out_file,
                    options.out_syscall)
    {
    }

    hng::detail::SingleInstanceGuard guard;
    ::Semantic aggregate;
};

SemanticComponent::SemanticComponent(std::unique_ptr<Impl> impl)
    : impl_(std::move(impl))
{
}

SemanticComponent::~SemanticComponent() = default;

hng::ComponentState SemanticComponent::state() const
{
    return impl_->aggregate.state();
}

void SemanticComponent::run() { impl_->aggregate.run(); }

void SemanticComponent::stop() { impl_->aggregate.stop(); }

std::unique_ptr<SemanticComponent> SemanticFactory::create(
    SemanticOptions options)
{
    static std::atomic<bool> taken{false};
    auto impl = std::make_unique<SemanticComponent::Impl>(taken, options);
    return std::unique_ptr<SemanticComponent>(
        new SemanticComponent(std::move(impl)));
}

}  // namespace hng
