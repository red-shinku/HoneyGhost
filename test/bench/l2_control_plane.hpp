/**
 * @file l2_control_plane.hpp
 * @brief L2 控制面的装配、语料播种与窗口统计
 * @details
 * 供 engine 与 chain 段共用：按语料出现过的进程给真实的 Process/Context 组件
 * 播种，接线角色替身与 context 维护器，并持有两条组件线程。角色维度始终是
 * test/bench/l1_control_plane.hpp 的替身，不属于本类。
 */

#ifndef HNG_TEST_BENCH_L2_CONTROL_PLANE_HPP_
#define HNG_TEST_BENCH_L2_CONTROL_PLANE_HPP_

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <variant>
#include <vector>

#include "agent/context_maintainer/include/context_maintainer.hpp"
#include "agent/control_plane/include/context_component.hpp"
#include "agent/control_plane/include/context_seed_service.hpp"
#include "agent/control_plane/include/context_stats.hpp"
#include "agent/control_plane/include/control_plane_factory.hpp"
#include "agent/control_plane/include/process_component.hpp"
#include "agent/control_plane/include/process_seed_service.hpp"
#include "agent/control_plane/include/process_stats.hpp"
#include "agent/event_data/include/syscall_event.hpp"
#include "test/bench/l1_control_plane.hpp"

namespace bench::l2 {

/**
 * @brief L2 的一次性 seed 结果
 * @details batch_entries 与 supplemented 描述批次构造；exe_real/synthetic 是
 *          镜像来源；plan_derive/plan_bind 是 context 计划的落地方式；
 *          process/context 是组件 seed 的实际报告。各字段在一次 start() 内确定，
 *          此后不再变化。
 */
struct SeedReport {
    std::size_t batch_entries   = 0;  ///< 批次条目数
    std::uint64_t supplemented  = 0;  ///< 只作为父出现而补成条目的进程数
    std::uint64_t roles         = 0;  ///< 角色替身播种的进程数
    std::uint64_t exe_real      = 0;  ///< 用真实 exec 镜像的条目数
    std::uint64_t exe_synthetic = 0;  ///< 镜像未知而按 pid 合成的条目数
    std::uint64_t plan_derive   = 0;  ///< context 计划中 DERIVE 的条目数
    std::uint64_t plan_bind     = 0;  ///< context 计划中 BIND 的条目数
    ProcessSeedReport process{};      ///< 进程组件 seed 报告
    ContextSeedReport context{};      ///< context 组件 seed 报告
};

/// @brief 控制面的窗口统计快照
/// @details process/context 是累计计数快照，由调用方在两个窗口端点各取一次做差；
///          seed 是启动期的一次性结果，不随窗口变化。
struct ControlPlaneSnapshot {
    ProcessManagerStats process{};  ///< 进程管理器统计
    ContextManagerStats context{};  ///< 上下文管理器统计
    SeedReport seed{};              ///< 启动期 seed 结果
};

/**
 * @brief L2 控制面：真实 Process/Context 组件 + 语料播种 + 组件线程
 * @details start() 经 ControlPlaneFactory 取得两个组件，完成与装配层一致的接线，
 *          按语料全量播种并启动 process/context 两条组件线程。服务访问器供引擎
 *          把进程与 context 维度的注入点指向真实组件；角色维度仍由调用方持有的
 *          bench::l1 替身承担。
 * @note 组件实例由工厂限额保护，同一进程内只能有一个 L2 控制面存活；本对象的
 *       start() 也只能成功一次，失败后组件线程已收尾且不可重试，工厂名额随对象
 *       析构归还。不拥有 ContextMaintainer 与角色替身，二者须存活到 stop() 之后。
 *       stop() 可重复调用；析构时自动调用。
 * @see SeedReport, ControlPlaneSnapshot
 */
class ControlPlane final {
   public:
    ControlPlane() = default;
    ~ControlPlane();

    ControlPlane(const ControlPlane&)            = delete;
    ControlPlane& operator=(const ControlPlane&) = delete;

    /**
     * @brief 装配组件、播种并启动两条组件线程
     * @param[in] events 全量语义事件，种子不受回放类别影响
     * @param[in] settled 角色替身的落定比例；context 为真实 seed，全部语料进程
     *            都会落地
     * @param[in,out] maintainer 已构造的维护器；本方法绑定其 context 三接口
     * @param[in,out] role_join 角色继承替身
     * @param[in,out] role_lookup 角色查询替身
     * @param[out] error 失败原因
     * @return 组件线程已运行时为 true
     * @pre 维护器与角色替身尚未被其它线程使用；进程内没有其它 L2 控制面
     * @note 失败路径已停止并回收组件线程，返回后可直接析构。seed 被组件以
     *       非 CONSTRUCTED 拒绝时按运行期失败处理。
     */
    bool start(const std::vector<hng::syscall_semantic_data>& events,
               double settled, ContextMaintainer& maintainer,
               bench::l1::FakeRoleJoin& role_join,
               bench::l1::FakeRoleLookup& role_lookup, std::string& error);

    /// @brief 进程注册注入点
    /// @pre start() 成功
    ProcessJoinService& process_join();

    /// @brief 进程镜像更新注入点
    /// @pre start() 成功
    ProcessUpdateService& process_update();

    /// @brief 进程查询注入点
    /// @pre start() 成功
    ProcessLookupService& process_lookup();

    /// @brief context 查询注入点
    /// @pre start() 成功
    ContextLookupService& context_lookup();

    /// @brief context 注册注入点
    /// @pre start() 成功
    ContextJoinService& context_join();

    /// @brief context 更新注入点
    /// @pre start() 成功
    ContextUpdateService& context_update();

    /**
     * @brief 停两条组件线程并回收组件
     * @note 先 process 后 context，与装配层的收尾顺序一致；可重复调用。
     */
    void stop();

    /**
     * @brief 取一次控制面统计
     * @return PM/CM 的累计计数与启动期 seed 结果；未启动时为空
     * @note 可在组件线程运行时调用；返回的是当前累计值。
     */
    ControlPlaneSnapshot snapshot() const;

    /// @brief 某条组件线程是否曾抛出异常
    bool failed() const;

   private:
    void build_seed(const std::vector<hng::syscall_semantic_data>& events,
                    double settled, hng::ProcessComponent& process_component,
                    hng::ContextComponent& context_component,
                    ContextMaintainer& maintainer,
                    bench::l1::FakeRoleLookup& role_lookup);

    static void collect_exec_images(
        const std::vector<hng::syscall_semantic_data>& events,
        std::unordered_map<hng::Process, std::string>& images);
    static void fill_seed_exe(
        hng::ProcessSeedEntry& entry,
        const std::unordered_map<hng::Process, std::string>& images,
        SeedReport& report);
    static void build_seed_batch(
        const std::vector<hng::syscall_semantic_data>& events,
        const std::unordered_map<hng::Process, std::string>& images,
        hng::ProcessSeedBatch& batch, SeedReport& report);

    std::unique_ptr<hng::ProcessComponent> process_component_;
    std::unique_ptr<hng::ContextComponent> context_component_;
    std::thread process_thread_;
    std::thread context_thread_;
    std::atomic<bool> failed_{false};

    SeedReport seed_{};
    bool started_ = false;
    bool stopped_ = false;
};

inline ControlPlane::~ControlPlane() { stop(); }

/**
 * @brief 收集全量语料里每个进程最近一次 exec 的真实镜像路径
 * @param[in] events 语义事件
 * @param[out] images 进程身份到镜像绝对路径的映射；空镜像不记录
 * @note 同名进程多次 exec 时以最后一次为准；身份按事件头取 (pid, pid_start_time)
 */
inline void ControlPlane::collect_exec_images(
    const std::vector<hng::syscall_semantic_data>& events,
    std::unordered_map<hng::Process, std::string>& images)
{
    for (const hng::syscall_semantic_data& event : events) {
        const auto* exec = std::get_if<hng::exec_semantic_data>(&event.data);
        if (exec == nullptr || exec->image().empty()) {
            continue;
        }
        images[hng::Process{event.head.pid, event.head.pid_start_time}] =
            exec->image();
    }
}

/// @brief 为一条 seed 条目填入镜像：优先真实 exec 路径，取不到才按 pid 合成
inline void ControlPlane::fill_seed_exe(
    hng::ProcessSeedEntry& entry,
    const std::unordered_map<hng::Process, std::string>& images,
    SeedReport& report)
{
    const auto it = images.find(entry.process);
    if (it != images.end() && !it->second.empty()) {
        entry.exe = it->second;
        ++report.exe_real;
        return;
    }
    entry.exe = "/usr/bin/proc-" + std::to_string(entry.process.pid);
    ++report.exe_synthetic;
}

/**
 * @brief 由语料事件头构造进程初始化批次
 * @param[in] events 语义事件
 * @param[in] images 进程身份到真实 exec 镜像的映射
 * @param[out] batch 初始进程批次，complete 置 true
 * @param[in,out] report 条目数、补父条目数与镜像来源计数
 * @note 主体身份取 (pid, pid_start_time)；ppid 取事件头，为 0 时不补父条目。
 *       父身份同样按 (ppid, ppid_start_time) 去重，补出的条目 ppid 置 0。
 *       ppid_start_time 为 0 的父身份仍补条目，由 seed 计 invalid。
 */
inline void ControlPlane::build_seed_batch(
    const std::vector<hng::syscall_semantic_data>& events,
    const std::unordered_map<hng::Process, std::string>& images,
    hng::ProcessSeedBatch& batch, SeedReport& report)
{
    std::unordered_set<hng::Process> subjects;
    std::unordered_set<hng::Process> parents;
    std::vector<hng::ProcessSeedEntry> entries;
    entries.reserve(events.size());
    for (const hng::syscall_semantic_data& event : events) {
        const hng::Process self{event.head.pid, event.head.pid_start_time};
        const hng::Process parent{event.head.ppid, event.head.ppid_start_time};
        if (self.pid == 0) {
            continue;
        }
        if (subjects.insert(self).second) {
            hng::ProcessSeedEntry entry;
            entry.process         = self;
            entry.ppid            = event.head.ppid;
            entry.ppid_start_time = event.head.ppid_start_time;
            fill_seed_exe(entry, images, report);
            entries.push_back(std::move(entry));
        }
        if (parent.pid != 0) {
            parents.insert(parent);
        }
    }
    for (const hng::Process& parent : parents) {
        if (subjects.count(parent) != 0) {
            continue;
        }
        hng::ProcessSeedEntry entry;
        entry.process = parent;
        fill_seed_exe(entry, images, report);
        entries.push_back(std::move(entry));
        ++report.supplemented;
    }
    report.batch_entries = entries.size();
    batch.entries        = std::move(entries);
    batch.complete       = true;
}

/**
 * @brief 用全量语料给真实组件与角色替身播种
 * @param[in] events 全量语义事件，不受回放类别影响
 * @param[in] settled 角色替身的落定比例
 * @param[in,out] process_component 真实进程管理组件
 * @param[in,out] context_component 真实上下文管理组件
 * @param[in,out] maintainer 已注入真实 context 服务的维护器
 * @param[in,out] role_lookup 角色查询替身
 * @pre 两个组件的 run() 尚未启动；maintainer 已注入真实 context 服务
 * @note 先落地进程批次，再由维护器生成 context 计划并落地；此时所有语料进程
 *       都已有 context 归属，--settled 只影响角色替身。
 */
inline void ControlPlane::build_seed(
    const std::vector<hng::syscall_semantic_data>& events, double settled,
    hng::ProcessComponent& process_component,
    hng::ContextComponent& context_component, ContextMaintainer& maintainer,
    bench::l1::FakeRoleLookup& role_lookup)
{
    std::unordered_map<hng::Process, std::string> images;
    images.reserve(events.size() / 4);
    collect_exec_images(events, images);
    hng::ProcessSeedBatch batch;
    build_seed_batch(events, images, batch, seed_);
    seed_.process = process_component.seed_service().seed(batch);
    seed_.roles = bench::l1::seed_role_substitutes(events, settled, role_lookup);
    const ContextSeedPlan plan = maintainer.build_seed_plan(batch);
    for (const ContextSeedEntry& entry : plan.entries) {
        if (entry.kind == ContextSeedKind::DERIVE) {
            ++seed_.plan_derive;
        }
        else {
            ++seed_.plan_bind;
        }
    }
    seed_.context = context_component.seed_service().seed(plan);
}

inline bool ControlPlane::start(
    const std::vector<hng::syscall_semantic_data>& events, double settled,
    ContextMaintainer& maintainer, bench::l1::FakeRoleJoin& role_join,
    bench::l1::FakeRoleLookup& role_lookup, std::string& error)
{
    if (started_) {
        error = "L2 control plane already started";
        return false;
    }
    if (stopped_) {
        error = "L2 control plane cannot be restarted after stop";
        return false;
    }

    try {
        process_component_ = hng::ControlPlaneFactory::create_process();
        context_component_ = hng::ControlPlaneFactory::create_context();
    }
    catch (const std::exception& failure) {
        error = std::string("failed to construct the control plane component: ") +
                failure.what();
        return false;
    }
    started_ = true;

    // 与装配层一致：进程组件接角色替身与真实 context 的生命周期出口
    process_component_->set_role_join_service(&role_join);
    process_component_->add_process_lifecycle_sink(
        &context_component_->lifecycle_sink());
    maintainer.set_context_service(&context_component_->lookup_service(),
                                   &context_component_->join_service(),
                                   &context_component_->update_service());

    build_seed(events, settled, *process_component_, *context_component_,
               maintainer, role_lookup);
    if (seed_.process.rejected_state != 0 || seed_.context.rejected_state != 0) {
        error = "L2 seed rejected: the component is not CONSTRUCTED (process " +
                std::to_string(seed_.process.rejected_state) + ", context " +
                std::to_string(seed_.context.rejected_state) + ")";
        stop();
        return false;
    }

    try {
        process_thread_ = std::thread([this] {
            try {
                process_component_->run();
            }
            catch (const std::exception& failure) {
                std::fprintf(stderr, "process component thread failed: %s\n",
                             failure.what());
                failed_.store(true, std::memory_order_release);
            }
            catch (...) {
                std::fprintf(
                    stderr,
                    "process component thread failed: unknown exception\n");
                failed_.store(true, std::memory_order_release);
            }
        });
        context_thread_ = std::thread([this] {
            try {
                context_component_->run();
            }
            catch (const std::exception& failure) {
                std::fprintf(stderr, "context component thread failed: %s\n",
                             failure.what());
                failed_.store(true, std::memory_order_release);
            }
            catch (...) {
                std::fprintf(
                    stderr,
                    "context component thread failed: unknown exception\n");
                failed_.store(true, std::memory_order_release);
            }
        });
    }
    catch (const std::exception& failure) {
        error = std::string("failed to start the control plane threads: ") +
                failure.what();
        stop();
        return false;
    }
    error.clear();
    return true;
}

inline ProcessJoinService& ControlPlane::process_join()
{
    return process_component_->join_service();
}

inline ProcessUpdateService& ControlPlane::process_update()
{
    return process_component_->update_service();
}

inline ProcessLookupService& ControlPlane::process_lookup()
{
    return process_component_->lookup_service();
}

inline ContextLookupService& ControlPlane::context_lookup()
{
    return context_component_->lookup_service();
}

inline ContextJoinService& ControlPlane::context_join()
{
    return context_component_->join_service();
}

inline ContextUpdateService& ControlPlane::context_update()
{
    return context_component_->update_service();
}

inline void ControlPlane::stop()
{
    if (stopped_) {
        return;
    }
    stopped_ = true;
    if (process_component_) {
        process_component_->stop();
        if (process_thread_.joinable()) {
            process_thread_.join();
        }
    }
    if (context_component_) {
        context_component_->stop();
        if (context_thread_.joinable()) {
            context_thread_.join();
        }
    }
}

inline ControlPlaneSnapshot ControlPlane::snapshot() const
{
    ControlPlaneSnapshot result;
    result.seed = seed_;
    if (started_) {
        result.process = process_component_->stats();
        result.context = context_component_->stats();
    }
    return result;
}

inline bool ControlPlane::failed() const
{
    return failed_.load(std::memory_order_acquire);
}

}  // namespace bench::l2

#endif  // HNG_TEST_BENCH_L2_CONTROL_PLANE_HPP_
