/**
 * @file role_discovery_component.cc
 * @brief 角色发现组件：存活名额、生命周期状态与发现源转发。
 */
#include "agent/role_discovery/include/role_discovery_component.hpp"

#include "agent/role_discovery/include/role_discovery_factory.hpp"
#include "agent/role_discovery/include/role_event_sink.hpp"
#include "agent/role_discovery/include/role_source_barrier.hpp"
#include "agent/util/include/single_instance_guard.hpp"

#include <atomic>
#include <memory>
#include <utility>

#ifdef HNG_HAVE_ROLE_SYSTEMD
#include "agent/role_discovery/src/role_systemd_discoverer.hpp"
#endif

#ifdef HNG_HAVE_ROLE_CONTAINERD
#include "agent/role_discovery/src/role_containerd_discoverer.hpp"
#endif

namespace hng {

namespace {

/**
 * @brief 组件包装的发现源。
 * @details 只表达阻塞运行与停止；具体源由工厂方法决定。
 */
class Source {
   public:
    Source()                         = default;
    virtual ~Source()                = default;

    Source(const Source&)            = delete;
    Source& operator=(const Source&) = delete;
    Source(Source&&)                 = delete;
    Source& operator=(Source&&)      = delete;

    /// @brief 阻塞运行，直到 stop() 被调用
    virtual void run()               = 0;

    /// @brief 请求 run() 返回；幂等
    virtual void stop()              = 0;
};

#ifdef HNG_HAVE_ROLE_SYSTEMD
/// @brief 把公共选项映射成 systemd 发现器配置，其余字段取默认值
hng::role::SystemdRoleDiscoverer::Config make_systemd_config(
    ::RoleSourceBarrier& barrier, const SystemdSourceOptions& options)
{
    hng::role::SystemdRoleDiscoverer::Config config;
    config.snapshot_interval = options.snapshot_interval;
    config.barrier           = &barrier;
    return config;
}

/// @brief systemd 发现源的适配器
class SystemdSource final : public Source {
   public:
    /**
     * @brief 按选项构造 systemd 发现器。
     * @param sink 事件出口，须比本对象活得久
     * @param barrier 初始快照结论的上报点
     * @param options 周期快照间隔
     */
    SystemdSource(role::RoleEventSink& sink, ::RoleSourceBarrier& barrier,
                  const SystemdSourceOptions& options)
        : discoverer_(sink, make_systemd_config(barrier, options))
    {
    }

    void run() override { discoverer_.run(); }

    void stop() override { discoverer_.stop(); }

   private:
    hng::role::SystemdRoleDiscoverer discoverer_;
};
#endif

#ifdef HNG_HAVE_ROLE_CONTAINERD
/// @brief 把公共选项映射成 containerd 发现器配置，其余字段取默认值
hng::role::ContainerdRoleDiscoverer::Config make_containerd_config(
    ::RoleSourceBarrier& barrier, const ContainerdSourceOptions& options)
{
    hng::role::ContainerdRoleDiscoverer::Config config;
    config.socket_path = options.socket_path;
    config.barrier     = &barrier;
    return config;
}

/// @brief containerd 发现源的适配器
class ContainerdSource final : public Source {
   public:
    /**
     * @brief 按选项构造 containerd 发现器。
     * @param sink 事件出口，须比本对象活得久
     * @param barrier 初始快照结论的上报点
     * @param options 翻译进程的 socket 路径
     */
    ContainerdSource(role::RoleEventSink& sink, ::RoleSourceBarrier& barrier,
                     const ContainerdSourceOptions& options)
        : discoverer_(sink, make_containerd_config(barrier, options))
    {
    }

    void run() override { discoverer_.run(); }

    void stop() override { discoverer_.stop(); }

   private:
    hng::role::ContainerdRoleDiscoverer discoverer_;
};
#endif

}  // namespace

struct RoleDiscoveryComponent::Impl {
    /**
     * @brief 先占用存活名额，再接管发现源。
     * @param taken 本创建方法的存活标志
     * @param component 组件名，写入占用失败的异常消息
     * @param discoverer 已构造的发现源
     * @throws std::logic_error 名额已被占用
     */
    Impl(std::atomic<bool>& taken, const char* component,
         std::unique_ptr<Source> discoverer)
        : guard(taken, component), source(std::move(discoverer))
    {
    }

    hng::detail::SingleInstanceGuard guard;
    std::atomic<hng::ComponentState> state{hng::ComponentState::READY};
    std::unique_ptr<Source> source;
};

RoleDiscoveryComponent::RoleDiscoveryComponent(std::unique_ptr<Impl> impl)
    : impl_(std::move(impl))
{
}

RoleDiscoveryComponent::~RoleDiscoveryComponent() = default;

hng::ComponentState RoleDiscoveryComponent::state() const
{
    return impl_->state.load();
}

void RoleDiscoveryComponent::run()
{
    hng::ComponentState expected = hng::ComponentState::READY;
    if (!impl_->state.compare_exchange_strong(expected,
                                              hng::ComponentState::RUNNING)) {
        return;
    }
    impl_->source->run();
    impl_->state.store(hng::ComponentState::STOPPED);
}

void RoleDiscoveryComponent::stop()
{
    impl_->source->stop();
    impl_->state.store(hng::ComponentState::STOPPED);
}

std::unique_ptr<RoleDiscoveryComponent> RoleDiscoveryFactory::create_systemd(
    role::RoleEventSink& sink, ::RoleSourceBarrier& barrier,
    SystemdSourceOptions options)
{
#ifdef HNG_HAVE_ROLE_SYSTEMD
    static std::atomic<bool> taken{false};
    auto source = std::make_unique<SystemdSource>(sink, barrier, options);
    auto impl   = std::make_unique<RoleDiscoveryComponent::Impl>(
        taken, "SystemdRoleDiscoveryComponent", std::move(source));
    return std::unique_ptr<RoleDiscoveryComponent>(
        new RoleDiscoveryComponent(std::move(impl)));
#else
    (void)sink;
    (void)barrier;
    (void)options;
    return nullptr;
#endif
}

std::unique_ptr<RoleDiscoveryComponent> RoleDiscoveryFactory::create_containerd(
    role::RoleEventSink& sink, ::RoleSourceBarrier& barrier,
    ContainerdSourceOptions options)
{
#ifdef HNG_HAVE_ROLE_CONTAINERD
    static std::atomic<bool> taken{false};
    auto source = std::make_unique<ContainerdSource>(sink, barrier, options);
    auto impl   = std::make_unique<RoleDiscoveryComponent::Impl>(
        taken, "ContainerdRoleDiscoveryComponent", std::move(source));
    return std::unique_ptr<RoleDiscoveryComponent>(
        new RoleDiscoveryComponent(std::move(impl)));
#else
    (void)sink;
    (void)barrier;
    (void)options;
    return nullptr;
#endif
}

}  // namespace hng
