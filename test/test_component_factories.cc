/**
 * @file test_component_factories.cc
 * @brief 各模块组件工厂的存活名额契约。
 */

#include "agent/control_plane/include/control_plane_factory.hpp"
#include "agent/role_discovery/include/role_discovery_factory.hpp"
#include "agent/runtime_engine/include/runtime_engine_factory.hpp"
#include "agent/semantic/include/semantic_factory.hpp"

#include "agent/control_plane/include/role_service.hpp"
#include "agent/role_discovery/include/role_event_sink.hpp"
#include "agent/role_discovery/include/role_source_barrier.hpp"
#include "agent/role_filter/include/role_filter_factory.hpp"

#ifdef HNG_HAVE_COLLECTOR
#include "agent/collector/include/collector_factory.hpp"
#endif

#include <cstdio>
#include <memory>
#include <optional>
#include <stdexcept>
#include <system_error>
#include <utility>
#include <vector>

namespace {

int g_fail = 0;

#define CHECK(cond, msg)                                                         \
    do {                                                                         \
        if (!(cond)) {                                                           \
            ++g_fail;                                                            \
            std::fprintf(stderr, "[FAIL] %s:%d  %s\n", __FILE__, __LINE__, msg); \
        }                                                                        \
    } while (0)

/**
 * @brief 已存在存活实例时再创建应抛 std::logic_error。
 * @return 抛出为 true
 */
template <class Factory, class Options>
bool second_create_throws(const Options& options)
{
    try {
        auto second = Factory::create(options);
        (void)second;
    }
    catch (const std::logic_error&) {
        return true;
    }
    return false;
}

/**
 * @brief 首次创建、存活期间重复创建、释放后重新创建。
 * @param options 构造选项
 * @param initial_state 新实例的初始状态
 */
template <class Factory, class Options>
void verify_single_instance(const Options& options,
                            hng::ComponentState initial_state)
{
    {
        auto first = Factory::create(options);
        CHECK(first != nullptr, "首次 create 应返回非空句柄");
        if (!first) {
            return;
        }
        CHECK(first->state() == initial_state, "新实例初始状态不符");
        CHECK(second_create_throws<Factory>(options),
              "存活期间再次 create 应抛 std::logic_error");
    }

    auto again = Factory::create(options);
    CHECK(again != nullptr, "释放后再次 create 应返回非空句柄");
    if (again) {
        CHECK(again->state() == initial_state, "重建实例初始状态不符");
    }
}

/**
 * @brief 执行一次创建动作，把名额冲突当作失败而不是终止测试。
 * @tparam Create 无参可调用对象，返回组件句柄
 * @param create 创建动作
 * @return 创建成功返回句柄；抛 std::logic_error 时返回空指针
 */
template <class Create>
auto try_create(Create create) -> decltype(create())
{
    try {
        return create();
    }
    catch (const std::logic_error&) {
        return nullptr;
    }
}

/**
 * @brief 执行一次创建动作并报告是否因名额冲突抛 std::logic_error。
 * @tparam Create 无参可调用对象，返回组件句柄
 * @param create 创建动作
 * @return 抛出 std::logic_error 为 true
 */
template <class Create>
bool create_throws_logic_error(Create create)
{
    try {
        auto component = create();
        (void)component;
    }
    catch (const std::logic_error&) {
        return true;
    }
    return false;
}

/// @brief 角色查询服务的最小替身：全部查询返回空
class FakeRoleLookup final : public RoleLookupService {
   public:
    std::optional<uint32_t> lookup(hng::Process) const override
    {
        return std::nullopt;
    }

    std::optional<hng::Role> role(uint32_t) const override
    {
        return std::nullopt;
    }

    std::optional<hng::Process> main_process(uint32_t) const override
    {
        return std::nullopt;
    }

    std::vector<hng::Role> roles() const override { return {}; }

    std::vector<hng::Role> supervised_roles() const override { return {}; }

    std::optional<hng::role::RoleIdentity> identity(uint32_t) const override
    {
        return std::nullopt;
    }

    std::vector<hng::Process> members(uint32_t) const override { return {}; }

    RoleManagerStats stats() const override { return {}; }
};

/// @brief 名单 map 的最小替身：全部写入成功
class FakeMap final : public hng::ProcessFilterMap {
   public:
    std::error_code allow(hng::Process) noexcept override { return {}; }

    std::error_code erase(hng::Process) noexcept override { return {}; }
};

/// @brief 构造指向 @p lookup 的过滤组件选项
hng::RoleFilterComponentOptions make_filter_options(const FakeRoleLookup& lookup)
{
    hng::RoleFilterComponentOptions options;
    options.lookup = &lookup;
    options.map    = std::make_unique<FakeMap>();
    return options;
}

void verify_semantic_factory()
{
    verify_single_instance<hng::SemanticFactory>(hng::SemanticOptions{},
                                                 hng::ComponentState::READY);
}

void verify_runtime_engine_factory()
{
    verify_single_instance<hng::RuntimeEngineFactory>(hng::RuntimeEngineOptions{},
                                                      hng::ComponentState::READY);
}

/// @brief 只用于销号回执的事件接收替身。
class NoopRuntimeSink final : public RuntimeEventSink {
   public:
    void on_event(const hng::RuntimeEvent) override {}
};

/// @brief 销号回执替身：记录是否被调用。
class AckSink final : public UnsubscribeAck {
   public:
    bool called = false;

    void on_unsubscribed() override { called = true; }
};

/// @brief 停机后 run() 仍落地已入队命令并清表（组件的清理路径）。
void verify_runtime_engine_stop_cleanup()
{
    auto component =
        hng::RuntimeEngineFactory::create(hng::RuntimeEngineOptions{});
    CHECK(component != nullptr, "构造运行时引擎组件");
    if (!component) {
        return;
    }

    NoopRuntimeSink sink;
    AckSink ack;
    CHECK(component->subscriber_service().subscribe(&sink, RuntimeInfoFilter{},
                                                    &ack),
          "停机前订阅应入队");

    component->stop();
    component->run();

    CHECK(ack.called, "停机后 run() 应回调销号回执");
    CHECK(component->state() == hng::ComponentState::STOPPED,
          "清理后状态应保持 STOPPED");
}

void verify_role_filter_factory()
{
    FakeRoleLookup lookup;
    {
        auto first = hng::RoleFilterFactory::create(make_filter_options(lookup));
        CHECK(first != nullptr, "首次 create 应返回非空句柄");
        if (first) {
            CHECK(first->state() == hng::ComponentState::CONSTRUCTED,
                  "新实例初始状态不符");
        }

        bool rejected = false;
        try {
            auto second =
                hng::RoleFilterFactory::create(make_filter_options(lookup));
            (void)second;
        }
        catch (const std::logic_error&) {
            rejected = true;
        }
        CHECK(rejected, "存活期间再次 create 应抛 std::logic_error");
    }

    auto again = hng::RoleFilterFactory::create(make_filter_options(lookup));
    CHECK(again != nullptr, "释放后再次 create 应返回非空句柄");
    if (again) {
        CHECK(again->state() == hng::ComponentState::CONSTRUCTED,
              "重建实例初始状态不符");
    }
    again.reset();

    bool invalid_lookup = false;
    try {
        auto options   = make_filter_options(lookup);
        options.lookup = nullptr;
        auto rejected  = hng::RoleFilterFactory::create(std::move(options));
        (void)rejected;
    }
    catch (const std::invalid_argument&) {
        invalid_lookup = true;
    }
    CHECK(invalid_lookup, "lookup 为空应抛 std::invalid_argument");

    bool invalid_map = false;
    try {
        auto options  = make_filter_options(lookup);
        options.map   = nullptr;
        auto rejected = hng::RoleFilterFactory::create(std::move(options));
        (void)rejected;
    }
    catch (const std::invalid_argument&) {
        invalid_map = true;
    }
    CHECK(invalid_map, "map 为空应抛 std::invalid_argument");
}

/// @brief 控制面三个组件各自单实例，且互不占用对方的存活名额。
void verify_control_plane_factory()
{
    auto process =
        try_create([] { return hng::ControlPlaneFactory::create_process(); });
    auto context =
        try_create([] { return hng::ControlPlaneFactory::create_context(); });
    auto role =
        try_create([] { return hng::ControlPlaneFactory::create_role(); });

    CHECK(process != nullptr, "首次创建进程组件应返回非空句柄");
    CHECK(context != nullptr, "首次创建上下文组件应返回非空句柄");
    CHECK(role != nullptr, "首次创建角色组件应返回非空句柄");

    if (process) {
        CHECK(process->state() == hng::ComponentState::CONSTRUCTED,
              "进程组件初始状态应为 CONSTRUCTED");
    }
    if (context) {
        CHECK(context->state() == hng::ComponentState::CONSTRUCTED,
              "上下文组件初始状态应为 CONSTRUCTED");
    }
    if (role) {
        CHECK(role->state() == hng::ComponentState::CONSTRUCTED,
              "角色组件初始状态应为 CONSTRUCTED");
    }

    CHECK(create_throws_logic_error(
              [] { return hng::ControlPlaneFactory::create_process(); }),
          "进程组件存活期间再次创建应抛 std::logic_error");
    CHECK(create_throws_logic_error(
              [] { return hng::ControlPlaneFactory::create_context(); }),
          "上下文组件存活期间再次创建应抛 std::logic_error");
    CHECK(create_throws_logic_error(
              [] { return hng::ControlPlaneFactory::create_role(); }),
          "角色组件存活期间再次创建应抛 std::logic_error");

    process.reset();
    context.reset();
    role.reset();

    auto rebuilt_process =
        try_create([] { return hng::ControlPlaneFactory::create_process(); });
    auto rebuilt_context =
        try_create([] { return hng::ControlPlaneFactory::create_context(); });
    auto rebuilt_role =
        try_create([] { return hng::ControlPlaneFactory::create_role(); });
    CHECK(rebuilt_process != nullptr, "释放后再次创建进程组件应成功");
    CHECK(rebuilt_context != nullptr, "释放后再次创建上下文组件应成功");
    CHECK(rebuilt_role != nullptr, "释放后再次创建角色组件应成功");
}

/// @brief 角色事件接收替身：丢弃全部事件。
class NullRoleSink final : public hng::role::RoleEventSink {
   public:
    void on_role_event(const hng::role::RoleEvent&) override {}
};

/**
 * @brief 一种发现源的存活名额契约。
 * @tparam Create 无参可调用对象，返回发现组件句柄
 * @param create 创建动作
 * @return 该源已编入构建且首次创建成功时为 true；未编入构建时返回 false
 */
template <class Create>
bool verify_discovery_slot(Create create)
{
    auto first = try_create(create);
    if (first == nullptr) {
        return false;
    }
    CHECK(first->state() == hng::ComponentState::READY,
          "发现组件初始状态应为 READY");
    CHECK(create_throws_logic_error(create),
          "发现组件存活期间再次创建应抛 std::logic_error");
    first.reset();

    auto again = try_create(create);
    CHECK(again != nullptr, "释放后再次创建发现组件应成功");
    return true;
}

/// @brief 两个发现源各自单实例，且可同时存活。
void verify_role_discovery_factory()
{
    NullRoleSink sink;
    RoleSourceBarrier barrier;

    const bool systemd_available    = verify_discovery_slot([&sink, &barrier] {
        return hng::RoleDiscoveryFactory::create_systemd(sink, barrier);
    });
    const bool containerd_available = verify_discovery_slot([&sink, &barrier] {
        return hng::RoleDiscoveryFactory::create_containerd(sink, barrier);
    });

    auto systemd                    = try_create([&sink, &barrier] {
        return hng::RoleDiscoveryFactory::create_systemd(sink, barrier);
    });
    auto containerd                 = try_create([&sink, &barrier] {
        return hng::RoleDiscoveryFactory::create_containerd(sink, barrier);
    });
    CHECK(!systemd_available || systemd != nullptr,
          "两个发现源应各占一个名额，可同时存活");
    CHECK(!containerd_available || containerd != nullptr,
          "两个发现源应各占一个名额，可同时存活");
}

#ifdef HNG_HAVE_COLLECTOR
void verify_collector_factory()
{
    verify_single_instance<hng::CollectorFactory>(
        hng::CollectorOptions{}, hng::ComponentState::CONSTRUCTED);
}
#endif

}  // namespace

int main()
{
    verify_semantic_factory();
    verify_runtime_engine_factory();
    verify_runtime_engine_stop_cleanup();
    verify_role_filter_factory();
    verify_control_plane_factory();
    verify_role_discovery_factory();
#ifdef HNG_HAVE_COLLECTOR
    verify_collector_factory();
#endif

    if (g_fail) {
        std::fprintf(stderr, "TOTAL FAILURES: %d\n", g_fail);
        return 1;
    }
    std::printf("ALL PASS\n");
    return 0;
}
