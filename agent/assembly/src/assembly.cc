/**
 * @file assembly.cc
 * @brief 装配层的构造、启动与停机实现
 * @details 启动顺序：构造与接线 → 名单 map 前置 → 名单组件 → 角色源 →
 *          初始化 → 控制面线程 → 引擎线程 → 探针挂载与采集线程；停机按
 *          “先停生产者、再停消费者”执行。
 * @author red_shinku
 * @date 2026.10.27
 */

#include "agent/assembly/include/assembly.hpp"

#include "agent/assembly/src/proc_snapshot.hpp"
#include "agent/collector/include/collector_component.hpp"
#include "agent/collector/include/collector_factory.hpp"
#include "agent/context_maintainer/include/context_maintainer.hpp"
#include "agent/control_plane/include/context_component.hpp"
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
#include "agent/util/include/log.hpp"
#include "agent/util/include/spsc_queue.hpp"
#include "kernel/include/files_type.h"
#include "kernel/include/networks_type.h"
#include "kernel/include/syscalls_type.h"

#include <atomic>
#include <exception>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <utility>

namespace hng {

struct Assembly::Impl {
    /**
     * @brief 保存选项并按容量创建五条事件队列
     * @param opts 队列容量与启动参数
     */
    explicit Impl(AssemblyOptions opts)
        : options(std::move(opts)),
          raw_file_q(options.raw_queue_capacity),
          raw_syscall_q(options.raw_queue_capacity),
          raw_network_q(options.raw_queue_capacity),
          semantic_file_q(options.semantic_queue_capacity),
          semantic_syscall_q(options.semantic_queue_capacity)
    {
    }

    /// @brief 执行一次性启动；失败时由调用方 shutdown()
    InitReport start_impl();

    /// @brief 至多执行一次 do_shutdown()
    void shutdown();

    /// @brief 按停机顺序停止并 join，再逆序释放组件
    void do_shutdown();

    AssemblyOptions options;
    hng::SPSC_Queue<::file_access_data> raw_file_q;
    hng::SPSC_Queue<::syscall_event> raw_syscall_q;
    hng::SPSC_Queue<::network_data> raw_network_q;
    hng::SPSC_Queue<hng::file_semantic_data> semantic_file_q;
    hng::SPSC_Queue<hng::syscall_semantic_data> semantic_syscall_q;
    ::ContextMaintainer maintainer;
    std::unique_ptr<hng::RoleComponent> role;
    std::unique_ptr<hng::ProcessComponent> process;
    std::unique_ptr<hng::ContextComponent> context;
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

    std::thread process_thread;
    std::thread context_thread;
    std::thread role_thread;
    std::thread role_filter_thread;
    std::thread collector_thread;
    std::thread semantic_thread;
    std::thread engine_thread;
    std::thread systemd_thread;
    std::thread containerd_thread;

    InitReport report;
    std::atomic<bool> running{false};
    std::atomic<bool> start_attempted{false};
    std::atomic<bool> stop_called{false};
    std::once_flag shutdown_once;
};

InitReport Assembly::Impl::start_impl()
{
#ifndef HNG_HAVE_COLLECTOR
    if (options.collect) {
        throw std::runtime_error("collector not in build: use --no-collect");
    }
#endif

    // S0 构造控制面组件并完成跨模块接线
    role    = ControlPlaneFactory::create_role();
    process = ControlPlaneFactory::create_process();
    context = ControlPlaneFactory::create_context();

    process->set_role_join_service(&role->join_service());
    process->add_process_lifecycle_sink(&context->lifecycle_sink());
    process->add_process_lifecycle_sink(&role->lifecycle_sink());
    maintainer.set_context_service(&context->lookup_service(),
                                   &context->join_service(),
                                   &context->update_service());

#ifdef HNG_HAVE_COLLECTOR
    if (options.collect) {
        collector = CollectorFactory::create(
            {&raw_file_q, &raw_syscall_q, &raw_network_q});
        semantic = SemanticFactory::create(
            {&raw_file_q, &raw_syscall_q, &semantic_file_q, &semantic_syscall_q});
    }
#endif

    engine = RuntimeEngineFactory::create(
        {&semantic_syscall_q, &semantic_file_q, &maintainer,
         &process->join_service(), &process->update_service(),
         &role->join_service(), &role->lookup_service()});

#ifdef HNG_HAVE_COLLECTOR
    // S1 名单 map 由采集器 prepare() 创建，成功后才有可用 fd
    if (collector != nullptr && !collector->prepare()) {
        throw std::runtime_error("fail to prepare collector");
    }

    // S2 用过滤 map fd 构造名单组件，并注册为 RM 的生命周期出口
    if (collector != nullptr) {
        RoleFilterComponentOptions ropt;
        ropt.lookup      = &role->lookup_service();
        ropt.supervision = &role->supervision_service();
        ropt.policy      = RoleFilterPolicy(options.role_filter_config);
        ropt.map = make_bpf_process_filter_map(collector->role_filter_map_fds());
        ropt.filter_options = options.role_filter_options;
        role_filter         = RoleFilterFactory::create(std::move(ropt));
        role->add_lifecycle_sink(&role_filter->lifecycle_sink());
    }
#endif

    // S3 先登记角色源再启动其线程；工厂返回空表示该源未编入构建
    if (options.enable_systemd) {
        systemd_source = RoleDiscoveryFactory::create_systemd(
            role->event_sink(), barrier,
            SystemdSourceOptions{options.systemd_snapshot_interval});
        if (systemd_source != nullptr) {
            barrier.expect(role::RoleSource::SYSTEMD);
            systemd_thread =
                std::thread([source = systemd_source.get()] { source->run(); });
        }
        else {
            HNG_LOG_WARN("systemd role source not built in; skipped");
        }
    }
    if (options.enable_containerd) {
        containerd_source = RoleDiscoveryFactory::create_containerd(
            role->event_sink(), barrier,
            ContainerdSourceOptions{options.containerd_socket_path});
        if (containerd_source != nullptr) {
            barrier.expect(role::RoleSource::CONTAINERD);
            containerd_thread = std::thread(
                [source = containerd_source.get()] { source->run(); });
        }
        else {
            HNG_LOG_WARN("containerd role source not built in; skipped");
        }
    }

    // S4 初始化写入落地后再挂探针；FAILED 时不启动任何消费线程
    // TODO: 快照在角色源屏障与名单播种之前读取；屏障等待与播种期间的进程
    //       变化要等下一次事件才可见。需要收窄时把读取移到屏障/播种之后。
    ProcessSnapshotReader reader;
    InitializationCoordinator coordinator(*process, *context, *role, maintainer,
                                          role_filter.get(), &barrier,
                                          options.initialization);
    report = coordinator.run(reader.read());
    if (report.state == InitState::FAILED) {
        HNG_LOG_ERROR("initialization failed; consumer threads not started");
        shutdown();
        return report;
    }

    // S5 控制面线程：PM、CM、RM，名单组件存在时一并启动
    process_thread =
        std::thread([component = process.get()] { component->run(); });
    context_thread =
        std::thread([component = context.get()] { component->run(); });
    role_thread = std::thread([component = role.get()] { component->run(); });
    if (role_filter != nullptr) {
        role_filter_thread =
            std::thread([component = role_filter.get()] { component->run(); });
    }

    // S6 引擎线程：探针挂载前已在运行
    engine_thread = std::thread([component = engine.get()] { component->run(); });

#ifdef HNG_HAVE_COLLECTOR
    // S7 探针挂载后启动采集与语义线程
    if (collector != nullptr) {
        // TODO: 快照读取到探针挂载之间 fork 出的进程要等下一次事件
        //       才可见；需要收窄时在名单播种后加挂载点。
        if (!collector->attach()) {
            throw std::runtime_error("采集器挂载探针失败");
        }
        collector_thread =
            std::thread([component = collector.get()] { component->run(); });
        semantic_thread =
            std::thread([component = semantic.get()] { component->run(); });
    }
#endif

    // S8 全部线程就绪
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

    // 先停生产者再停消费者；join 只在可 join 时调用
    const auto stop_and_join = [](hng::Component* component,
                                  std::thread& thread) {
        if (component != nullptr) {
            component->stop();
        }
        if (thread.joinable()) {
            thread.join();
        }
    };

#ifdef HNG_HAVE_COLLECTOR
    stop_and_join(collector.get(), collector_thread);  // T1
#endif
    stop_and_join(semantic.get(), semantic_thread);       // T2
    stop_and_join(systemd_source.get(), systemd_thread);  // T3
    stop_and_join(containerd_source.get(), containerd_thread);
    stop_and_join(engine.get(), engine_thread);            // T4
    stop_and_join(process.get(), process_thread);          // T5
    stop_and_join(role.get(), role_thread);                // T6
    stop_and_join(role_filter.get(), role_filter_thread);  // T7
    stop_and_join(context.get(), context_thread);          // T8

    // 逆序释放组件，归还工厂名额；队列与维护器活到 Impl 析构
    systemd_source.reset();
    containerd_source.reset();
    engine.reset();
    role_filter.reset();
    semantic.reset();
#ifdef HNG_HAVE_COLLECTOR
    collector.reset();
#endif
    process.reset();
    role.reset();
    context.reset();

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

AssemblyServices Assembly::services() const
{
    if (!impl_->running.load()) {
        throw std::logic_error("assembly is not running");
    }

    AssemblyServices services;
    services.role       = &impl_->role->lookup_service();
    services.context    = &impl_->context->lookup_service();
    services.process    = &impl_->process->lookup_service();
    services.subscriber = &impl_->engine->subscriber_service();
    return services;
}

const InitReport& Assembly::init_report() const { return impl_->report; }

}  // namespace hng
