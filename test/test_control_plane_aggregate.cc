/**
 * @file test_control_plane_aggregate.cc
 * @brief 控制面聚合句柄的构造、服务与名额契约。
 */

#include "agent/control_plane/include/context_component.hpp"
#include "agent/control_plane/include/control_plane.hpp"
#include "agent/control_plane/include/control_plane_factory.hpp"
#include "agent/control_plane/include/process_component.hpp"
#include "agent/control_plane/include/role_component.hpp"

#include <cstdio>
#include <memory>
#include <stdexcept>

namespace {

int g_fail = 0;

#define CHECK(cond, msg)                                                         \
    do {                                                                         \
        if (!(cond)) {                                                           \
            ++g_fail;                                                            \
            std::fprintf(stderr, "[FAIL] %s:%d  %s\n", __FILE__, __LINE__, msg); \
        }                                                                        \
    } while (0)

/// @brief 进程退出接收替身：记录收到的通知次数
class CountingSink final : public ProcessLifecycleSink {
   public:
    void on_process_exited(hng::Process) override { ++count; }

    int count = 0;
};

/**
 * @brief 执行一次创建动作，把名额冲突当作失败而不是终止测试。
 * @tparam Create 无参可调用对象，返回组件或聚合句柄
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
 * @tparam Create 无参可调用对象，返回组件或聚合句柄
 * @param create 创建动作
 * @return 抛出 std::logic_error 为 true
 */
template <class Create>
bool create_throws_logic_error(Create create)
{
    try {
        auto handle = create();
        (void)handle;
    }
    catch (const std::logic_error&) {
        return true;
    }
    return false;
}

/// @brief 聚合句柄存活时三组件可经引用取服务，且服务调用不依赖组件线程。
void verify_aggregate_and_services()
{
    auto plane = try_create([] { return hng::ControlPlaneFactory::create(); });
    CHECK(plane != nullptr, "create 应返回非空聚合句柄");
    if (!plane) {
        return;
    }

    CHECK(plane->role().state() == hng::ComponentState::CONSTRUCTED,
          "聚合中的角色组件初始状态应为 CONSTRUCTED");
    CHECK(plane->process().state() == hng::ComponentState::CONSTRUCTED,
          "聚合中的进程组件初始状态应为 CONSTRUCTED");
    CHECK(plane->context().state() == hng::ComponentState::CONSTRUCTED,
          "聚合中的上下文组件初始状态应为 CONSTRUCTED");

    CHECK(plane->role().lookup_service().roles().empty(),
          "角色查询服务应可调用且初值为空");
    CHECK(!plane->process().lookup_service().resolve(0).has_value(),
          "进程查询服务应可调用且未命中 pid 0");

    const hng::Process process{};
    CHECK(!plane->context().lookup_service().lookup(process).has_value(),
          "上下文查询服务应可调用且未命中空进程");

    plane->role().join_service().bind_to_role(process, process);
    CHECK(plane->role().stats().queue_rejected == 0,
          "角色继承服务的通知应被队列接收");

    CountingSink sink;
    plane->process().add_process_lifecycle_sink(&sink);
    CHECK(sink.count == 0, "注册进程退出接收方不应立即通知");
}

/// @brief 聚合句柄存活时三个单组件创建方法都应因名额占用被拒绝。
void verify_slots_held()
{
    auto plane = try_create([] { return hng::ControlPlaneFactory::create(); });
    CHECK(plane != nullptr, "create 应返回非空聚合句柄");
    if (!plane) {
        return;
    }

    CHECK(create_throws_logic_error(
              [] { return hng::ControlPlaneFactory::create_role(); }),
          "聚合存活期间创建角色组件应抛 std::logic_error");
    CHECK(create_throws_logic_error(
              [] { return hng::ControlPlaneFactory::create_process(); }),
          "聚合存活期间创建进程组件应抛 std::logic_error");
    CHECK(create_throws_logic_error(
              [] { return hng::ControlPlaneFactory::create_context(); }),
          "聚合存活期间创建上下文组件应抛 std::logic_error");
}

/// @brief 聚合句柄析构后三个名额归还，且可再次装配聚合。
void verify_release_and_rebuild()
{
    {
        auto plane =
            try_create([] { return hng::ControlPlaneFactory::create(); });
        CHECK(plane != nullptr, "首次 create 应返回非空聚合句柄");
    }

    auto role =
        try_create([] { return hng::ControlPlaneFactory::create_role(); });
    auto process =
        try_create([] { return hng::ControlPlaneFactory::create_process(); });
    auto context =
        try_create([] { return hng::ControlPlaneFactory::create_context(); });
    CHECK(role != nullptr, "聚合析构后应可再次创建角色组件");
    CHECK(process != nullptr, "聚合析构后应可再次创建进程组件");
    CHECK(context != nullptr, "聚合析构后应可再次创建上下文组件");
    role.reset();
    process.reset();
    context.reset();

    auto first = try_create([] { return hng::ControlPlaneFactory::create(); });
    CHECK(first != nullptr, "释放后再次 create 应返回非空聚合句柄");
    first.reset();

    auto second = try_create([] { return hng::ControlPlaneFactory::create(); });
    CHECK(second != nullptr, "连续两次 create 均应成功");
}

}  // namespace

int main()
{
    verify_aggregate_and_services();
    verify_slots_held();
    verify_release_and_rebuild();

    if (g_fail) {
        std::fprintf(stderr, "TOTAL FAILURES: %d\n", g_fail);
        return 1;
    }
    std::printf("ALL PASS\n");
    return 0;
}
