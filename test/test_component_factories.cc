/**
 * @file test_component_factories.cc
 * @brief 采集与语义组件工厂的存活名额契约。
 */

#include "agent/semantic/include/semantic_factory.hpp"

#ifdef HNG_HAVE_COLLECTOR
#include "agent/collector/include/collector_factory.hpp"
#endif

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

void verify_semantic_factory()
{
    verify_single_instance<hng::SemanticFactory>(hng::SemanticOptions{},
                                                 hng::ComponentState::READY);
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
