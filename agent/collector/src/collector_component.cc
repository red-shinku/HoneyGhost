/**
 * @file collector_component.cc
 * @brief 采集组件：存活名额、三条标准事件线与聚合转发。
 */
#include "agent/collector/include/collector_component.hpp"

#include "agent/collector/include/collector_factory.hpp"
#include "agent/collector/src/collector.hpp"
#include "agent/util/include/single_instance_guard.hpp"

#include <atomic>
#include <memory>
#include <utility>
#include <vector>

namespace hng {

namespace {

/**
 * @brief 按选项构造标准事件线。
 * @param options 各线借用的通道写端；空项对应的线不构造
 * @return 构造出的事件线；全部为空时为空
 */
std::vector<std::unique_ptr<::CollectorType>> build_lines(
    const CollectorOptions& options)
{
    std::vector<std::unique_ptr<::CollectorType>> lines;
    if (options.file_sink) {
        lines.push_back(
            std::make_unique<::FileEventCollector>(*options.file_sink));
    }
    if (options.syscall_sink) {
        lines.push_back(
            std::make_unique<::SyscallEventCollector>(*options.syscall_sink));
    }
    if (options.network_sink) {
        lines.push_back(
            std::make_unique<::NetworkEventCollector>(*options.network_sink));
    }
    return lines;
}

}  // namespace

struct CollectorComponent::Impl {
    /**
     * @brief 先占用存活名额，再按选项构造事件线并交给聚合。
     * @param taken 本创建方法的存活标志
     * @param options 各线借用的通道写端
     * @throws std::logic_error 名额已被占用
     */
    Impl(std::atomic<bool>& taken, const CollectorOptions& options)
        : guard(taken, "CollectorComponent"), aggregate(build_lines(options))
    {
    }

    hng::detail::SingleInstanceGuard guard;
    ::Collector aggregate;
};

CollectorComponent::CollectorComponent(std::unique_ptr<Impl> impl)
    : impl_(std::move(impl))
{
}

CollectorComponent::~CollectorComponent() = default;

bool CollectorComponent::prepare() { return impl_->aggregate.prepare(); }

bool CollectorComponent::attach() { return impl_->aggregate.attach(); }

std::vector<int> CollectorComponent::role_filter_map_fds() const
{
    return impl_->aggregate.role_filter_map_fds();
}

hng::ComponentState CollectorComponent::state() const
{
    return impl_->aggregate.state();
}

void CollectorComponent::run() { impl_->aggregate.run(); }

void CollectorComponent::stop() { impl_->aggregate.stop(); }

std::unique_ptr<CollectorComponent> CollectorFactory::create(
    CollectorOptions options)
{
    static std::atomic<bool> taken{false};
    auto impl = std::make_unique<CollectorComponent::Impl>(taken, options);
    return std::unique_ptr<CollectorComponent>(
        new CollectorComponent(std::move(impl)));
}

}  // namespace hng
