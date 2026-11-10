/**
 * @file assembly.cc
 * @brief 装配层的构造、启动与停机实现
 * @details 启动顺序：内核能力预检（启用采集时）→ 构造与接线 → 名单 → 角色源
 *          → 初始化（含探针挂载与读快照）→ 消费线程；停机按“先停生产者、再停
 *          消费者”执行。启动按 require_kernel_support()、build_control_plane()、
 *          build_pipeline()、build_filter()、start_role_sources()、initialize()、
 *          start_consumers() 分段；停机按 stop_stages() 与 release_components()
 *          分段。
 * @author red_shinku
 * @date 2026.10.27
 */

#include "agent/assembly/include/assembly.hpp"

#include "agent/assembly/src/capability_drop.hpp"
#include "agent/assembly/src/component_threads.hpp"
#include "agent/assembly/src/kernel_preflight.hpp"
#include "agent/assembly/src/proc_snapshot.hpp"
#include "agent/collector/include/collector_component.hpp"
#include "agent/collector/include/collector_factory.hpp"
#include "agent/context_maintainer/include/context_maintainer.hpp"
#include "agent/control_plane/include/context_component.hpp"
#include "agent/control_plane/include/control_plane.hpp"
#include "agent/control_plane/include/control_plane_factory.hpp"
#include "agent/control_plane/include/process_component.hpp"
#include "agent/control_plane/include/role_component.hpp"
#include "agent/event_data/include/file_event.hpp"
#include "agent/event_data/include/syscall_event.hpp"
#include "agent/role_discovery/include/role_discovery_component.hpp"
#include "agent/role_discovery/include/role_discovery_factory.hpp"
#include "agent/role_discovery/include/role_source_barrier.hpp"
#include "agent/role_filter/include/process_filter_map.hpp"
#include "agent/role_filter/include/role_filter_component.hpp"
#include "agent/role_filter/include/role_filter_factory.hpp"
#include "agent/runtime_engine/include/runtime_engine_component.hpp"
#include "agent/runtime_engine/include/runtime_engine_factory.hpp"
#include "agent/semantic/include/semantic_component.hpp"
#include "agent/semantic/include/semantic_factory.hpp"
#include "agent/util/include/event_channel.hpp"
#include "agent/util/include/log.hpp"
#include "kernel/include/files_type.h"
#include "kernel/include/networks_type.h"
#include "kernel/include/syscalls_type.h"

#include <atomic>
#include <exception>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <utility>

namespace hng {

struct Assembly::Impl {
    /**
     * @brief 保存选项并按容量创建五条事件通道
     * @param opts 通道容量与启动参数
     * @throws std::system_error 通道唤醒 fd 创建失败
     */
    explicit Impl(AssemblyOptions opts)
        : options(std::move(opts)),
          raw_file_ch(options.raw_queue_capacity),
          raw_syscall_ch(options.raw_queue_capacity),
          raw_network_ch(options.raw_queue_capacity),
          semantic_file_ch(options.semantic_queue_capacity),
          semantic_syscall_ch(options.semantic_queue_capacity)
    {
    }

    /// @brief 执行一次性启动；失败时由调用方 shutdown()
    InitReport start_impl();

#ifdef HNG_HAVE_COLLECTOR
    /// @brief 检查目标内核是否满足探针加载要求
    /// @throws std::runtime_error 内核版本、BTF 或 tracefs 不满足
    void require_kernel_support();
#endif

    /// @brief 至多执行一次 do_shutdown()
    void shutdown();

    /// @brief 按停机顺序停止并 join，再逆序释放组件
    void do_shutdown();

    /// @brief S0 构造控制面聚合，并向维护器注入 context 服务
    void build_control_plane();

    /// @brief 构造采集、语义与引擎组件
    void build_pipeline();

#ifdef HNG_HAVE_COLLECTOR
    /// @brief S1–S2 准备采集器名单 map，构造名单组件并注册生命周期出口
    void build_filter();
#endif

    /// @brief S3 构造角色发现源、登记屏障并启动其线程
    void start_role_sources();

    /// @brief S4 挂探针、读快照并执行初始化
    /// @return 初始化报告；state 为 FAILED 时调用方须停机
    InitReport initialize();

    /// @brief S5–S7 启动控制面、引擎与消费线程
    void start_consumers();

    /// @brief T1–T8 按停机顺序停止并 join 各组件
    void stop_stages();

    /// @brief 逆序释放组件，归还工厂名额
    void release_components();

    AssemblyOptions options;
    hng::EventChannel<::file_access_data> raw_file_ch;
    hng::EventChannel<::syscall_event> raw_syscall_ch;
    hng::EventChannel<::network_data> raw_network_ch;
    hng::EventChannel<hng::file_semantic_data> semantic_file_ch;
    hng::EventChannel<hng::syscall_semantic_data> semantic_syscall_ch;
    ::ContextMaintainer maintainer;
    /// @brief 控制面三个组件的聚合句柄
    std::unique_ptr<hng::ControlPlane> control_plane;
#ifdef HNG_HAVE_COLLECTOR
    /// @brief 采集组件；collect 为 false 时为空
    std::unique_ptr<hng::CollectorComponent> collector;
#endif
    std::unique_ptr<hng::SemanticComponent> semantic;
    std::unique_ptr<hng::RuntimeEngineComponent> engine;
    std::unique_ptr<hng::RoleFilterComponent> role_filter;
    ::RoleSourceBarrier barrier;
    std::unique_ptr<hng::RoleDiscoveryComponent> systemd_source;
    std::unique_ptr<hng::RoleDiscoveryComponent> containerd_source;

    /// @brief 组件线程表；每个已启动组件至多一个线程
    hng::ComponentThreads threads;

    InitReport report;
    std::atomic<bool> running{false};
    std::atomic<bool> start_attempted{false};
    std::atomic<bool> stop_called{false};
    std::once_flag shutdown_once;
};

#ifdef HNG_HAVE_COLLECTOR
void Assembly::Impl::require_kernel_support()
{
    const detail::KernelSupport support = detail::check_kernel_support();
    if (support.ok()) {
        HNG_LOG_INFO("kernel support ok: {}; BTF and tracefs available",
                     support.release);
        return;
    }
    for (const std::string& reason : support.failures()) {
        HNG_LOG_ERROR("unsupported kernel: {}", reason);
    }
    throw std::runtime_error(
        "target kernel does not meet eBPF probe requirements");
}
#endif

void Assembly::Impl::build_control_plane()
{
    // S0 构造控制面聚合句柄；组件间接线由 ControlPlane 完成
    control_plane = ControlPlaneFactory::create();
    maintainer.set_context_service(&control_plane->context().lookup_service(),
                                   &control_plane->context().join_service(),
                                   &control_plane->context().update_service());
}

void Assembly::Impl::build_pipeline()
{
#ifdef HNG_HAVE_COLLECTOR
    if (options.collect) {
        collector = CollectorFactory::create({&raw_file_ch.writer(),
                                              &raw_syscall_ch.writer(),
                                              &raw_network_ch.writer()});
        semantic  = SemanticFactory::create(
            {&raw_file_ch.reader(), &raw_syscall_ch.reader(),
              &semantic_file_ch.writer(), &semantic_syscall_ch.writer()});
    }
#endif

    engine = RuntimeEngineFactory::create(
        {&semantic_syscall_ch.reader(), &semantic_file_ch.reader(), &maintainer,
         &control_plane->process().join_service(),
         &control_plane->process().update_service(),
         &control_plane->role().join_service(),
         &control_plane->role().lookup_service()});
}

#ifdef HNG_HAVE_COLLECTOR
void Assembly::Impl::build_filter()
{
    // S1 名单 map 由采集器 prepare() 创建，成功后才有可用 fd
    if (collector != nullptr && !collector->prepare()) {
        throw std::runtime_error("fail to prepare collector");
    }

    // S2 用过滤 map fd 构造名单组件，并注册为 RM 的生命周期出口
    if (collector != nullptr) {
        RoleFilterComponentOptions ropt;
        ropt.lookup      = &control_plane->role().lookup_service();
        ropt.supervision = &control_plane->role().supervision_service();
        ropt.policy      = RoleFilterPolicy(options.role_filter_config);
        ropt.map = make_bpf_process_filter_map(collector->role_filter_map_fds());
        ropt.filter_options = options.role_filter_options;
        role_filter         = RoleFilterFactory::create(std::move(ropt));
        control_plane->role().add_lifecycle_sink(&role_filter->lifecycle_sink());
    }
}
#endif

void Assembly::Impl::start_role_sources()
{
    // S3 先登记角色源再启动其线程；工厂返回空表示该源未编入构建
    if (options.enable_systemd) {
        systemd_source = RoleDiscoveryFactory::create_systemd(
            control_plane->role().event_sink(), barrier,
            SystemdSourceOptions{options.systemd_snapshot_interval});
        if (systemd_source != nullptr) {
            barrier.expect(role::RoleSource::SYSTEMD);
            threads.start(*systemd_source);
        }
        else {
            HNG_LOG_WARN("systemd role source not built in; skipped");
        }
    }
    if (options.enable_containerd) {
        containerd_source = RoleDiscoveryFactory::create_containerd(
            control_plane->role().event_sink(), barrier,
            ContainerdSourceOptions{options.containerd_socket_path});
        if (containerd_source != nullptr) {
            barrier.expect(role::RoleSource::CONTAINERD);
            threads.start(*containerd_source);
        }
        else {
            HNG_LOG_WARN("containerd role source not built in; skipped");
        }
    }
}

InitReport Assembly::Impl::initialize()
{
    // S4 名单播种后挂探针，再读快照
    ProcessSnapshotReader reader;
    InitializationCoordinator coordinator(
        control_plane->process(), control_plane->context(), control_plane->role(),
        maintainer, role_filter.get(), &barrier, options.initialization);
    InitializationIO io;
    io.read_snapshot = [&reader] { return reader.read(); };
#ifdef HNG_HAVE_COLLECTOR
    if (collector != nullptr) {
        io.attach_probe = [this] { return collector->attach(); };
    }
#endif
    return coordinator.run(io);
}

void Assembly::Impl::start_consumers()
{
    // S5 控制面线程：PM、CM、RM，名单组件存在时一并启动
    threads.start(control_plane->process());
    threads.start(control_plane->context());
    threads.start(control_plane->role());
    if (role_filter != nullptr) {
        threads.start(*role_filter);
    }

    // S6 引擎线程：初始化完成后启动
    threads.start(*engine);

#ifdef HNG_HAVE_COLLECTOR
    // S7 探针已在初始化阶段挂载；这里只启动采集与语义线程
    if (collector != nullptr) {
        threads.start(*collector);
        threads.start(*semantic);
    }
#endif
}

void Assembly::Impl::stop_stages()
{
    // 先停生产者再停消费者；可选组件未构造时跳过
#ifdef HNG_HAVE_COLLECTOR
    if (collector != nullptr) {
        threads.stop_and_join(*collector);  // T1
    }
#endif
    if (semantic != nullptr) {
        threads.stop_and_join(*semantic);  // T2
    }
    if (systemd_source != nullptr) {
        threads.stop_and_join(*systemd_source);  // T3
    }
    if (containerd_source != nullptr) {
        threads.stop_and_join(*containerd_source);
    }
    if (engine != nullptr) {
        threads.stop_and_join(*engine);  // T4
    }
    if (control_plane != nullptr) {
        threads.stop_and_join(control_plane->process());  // T5
        threads.stop_and_join(control_plane->role());     // T6
    }
    if (role_filter != nullptr) {
        threads.stop_and_join(*role_filter);  // T7
    }
    if (control_plane != nullptr) {
        threads.stop_and_join(control_plane->context());  // T8
    }
}

void Assembly::Impl::release_components()
{
    // 逆序释放组件，归还工厂名额；队列与维护器活到 Impl 析构
    systemd_source.reset();
    containerd_source.reset();
    engine.reset();
    role_filter.reset();
    semantic.reset();
#ifdef HNG_HAVE_COLLECTOR
    collector.reset();
#endif
    control_plane.reset();
}

InitReport Assembly::Impl::start_impl()
{
#ifndef HNG_HAVE_COLLECTOR
    if (options.collect) {
        throw std::runtime_error("collector not in build: use --no-collect");
    }
#endif

#ifdef HNG_HAVE_COLLECTOR
    // 探针加载的内核前提先于组件构造检查，避免半启动后才失败
    if (options.collect) {
        require_kernel_support();
    }
#endif

    build_control_plane();
    build_pipeline();
#ifdef HNG_HAVE_COLLECTOR
    build_filter();
#endif
    start_role_sources();
    report = initialize();

    if (report.state == InitState::FAILED) {
        HNG_LOG_ERROR("initialization failed; consumer threads not started");
        shutdown();
        return report;
    }

    start_consumers();
    // S8 探针已挂载、快照已读完：主线程及其后续创建的线程不再需要权能
    detail::drop_capabilities();
    running.store(true);
    HNG_LOG_INFO(
        "agent ready: state {}, collect {}, systemd {}, containerd {}, "
        "process inserted {}, context inserted {}, role filter applied {}",
        to_string(report.state), options.collect, systemd_source != nullptr,
        containerd_source != nullptr, report.process.inserted,
        report.context.inserted, report.role_filter.applied_processes);
    return report;
}

void Assembly::Impl::shutdown()
{
    std::call_once(shutdown_once, [this] { do_shutdown(); });
}

void Assembly::Impl::do_shutdown()
{
    running.store(false);
    stop_stages();
    release_components();

    HNG_LOG_INFO("agent stopped");
}

Assembly::Assembly(AssemblyOptions options)
    : impl_(std::make_unique<Impl>(std::move(options)))
{
}

Assembly::~Assembly() { stop(); }

InitReport Assembly::start()
{
    if (impl_->start_attempted.exchange(true)) {
        throw std::logic_error("Assembly::start 只能调用一次");
    }
    if (impl_->stop_called.load()) {
        throw std::logic_error("Assembly 已停止，不能 start");
    }
    try {
        return impl_->start_impl();
    }
    catch (...) {
        stop();
        throw;
    }
}

void Assembly::stop()
{
    impl_->stop_called.store(true);
    try {
        impl_->shutdown();
    }
    catch (const std::exception& error) {
        HNG_LOG_ERROR("shutdown failed: {}", error.what());
    }
    catch (...) {
        HNG_LOG_ERROR("shutdown failed with an unknown exception");
    }
}

bool Assembly::running() const { return impl_->running.load(); }

AgentServices Assembly::services() const
{
    if (!impl_->running.load()) {
        throw std::logic_error("assembly is not running");
    }

    AgentServices services;
    services.role       = &impl_->control_plane->role().lookup_service();
    services.context    = &impl_->control_plane->context().lookup_service();
    services.process    = &impl_->control_plane->process().lookup_service();
    services.subscriber = &impl_->engine->subscriber_service();
    return services;
}

const InitReport& Assembly::init_report() const { return impl_->report; }

}  // namespace hng
