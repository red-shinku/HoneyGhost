/**
 * @file test_collector_public_header.cc
 * @brief 采集组件公共头可在没有骨架与 libbpf 的环境中独立编译。
 */
#include "agent/collector/include/collector_factory.hpp"

#ifdef HNG_TEST_COLLECTOR_SKELETON_STUB_HPP_
#error "collector_factory.hpp must not include generated skeletons"
#endif

#ifdef COLLECTOR_HPP
#error "collector_factory.hpp must not include the private collector header"
#endif

#include <memory>
#include <type_traits>

static_assert(!std::is_copy_constructible_v<hng::CollectorComponent>);
static_assert(!std::is_copy_assignable_v<hng::CollectorComponent>);
static_assert(!std::is_move_constructible_v<hng::CollectorComponent>);
static_assert(!std::is_move_assignable_v<hng::CollectorComponent>);
static_assert(std::has_virtual_destructor_v<hng::CollectorComponent>);

// 仅编译不链接；OBJECT 库不解析工厂与析构的符号。
void verify_collector_public_header()
{
    std::unique_ptr<hng::CollectorComponent> component =
        hng::CollectorFactory::create();
    (void)component;
}
