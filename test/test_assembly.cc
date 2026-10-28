/**
 * @file test_assembly.cc
 * @brief 装配层的生命周期契约
 * @details 覆盖：
 *  - collect = false 时启动成功、running() 为真、报告状态非 FAILED；
 *  - init_report() 与 start() 返回的状态一致；
 *  - stop() 后 running() 为假，重复 stop() 不崩；
 *  - services() 只在运行期有效：未启动与停机后抛 std::logic_error，运行期
 *    四个服务指针非空；
 *  - start() 只能调用一次，第二次抛 std::logic_error；
 *  - 已 stop() 的实例再 start() 抛 std::logic_error。
 * @note 不加载探针、不连 systemd 与 containerd，也不断言 /proc 的具体条目；
 *       只断言生命周期与状态。
 */

#include "agent/assembly/include/assembly.hpp"

#include <cstdio>
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
 * @brief 只加载控制面与引擎的构造选项
 * @return collect 与两个角色源均关闭的选项
 */
hng::AssemblyOptions make_options()
{
    hng::AssemblyOptions options;
    options.collect           = false;
    options.enable_systemd    = false;
    options.enable_containerd = false;
    return options;
}

/// @brief 启动、报告、重复 start() 与幂等 stop()
void verify_lifecycle()
{
    hng::Assembly assembly(make_options());
    const hng::InitReport report = assembly.start();

    CHECK(report.state != hng::InitState::FAILED, "初始化不应失败");
    CHECK(assembly.running(), "启动后 running() 应为真");
    CHECK(assembly.init_report().state == report.state,
          "init_report() 应与 start() 返回的状态一致");

    bool second_start_threw = false;
    try {
        assembly.start();
    }
    catch (const std::logic_error&) {
        second_start_threw = true;
    }
    CHECK(second_start_threw, "第二次 start() 应抛 std::logic_error");

    assembly.stop();
    CHECK(!assembly.running(), "stop() 后 running() 应为假");
    assembly.stop();
    CHECK(!assembly.running(), "重复 stop() 后 running() 仍应为假");
}

/// @brief 服务访问器只在运行期有效
void verify_services()
{
    hng::Assembly assembly(make_options());

    bool before_start_threw = false;
    try {
        (void)assembly.services();
    }
    catch (const std::logic_error&) {
        before_start_threw = true;
    }
    CHECK(before_start_threw, "未启动时 services() 应抛 std::logic_error");

    (void)assembly.start();
    CHECK(assembly.running(), "启动后 running() 应为真");

    const hng::AssemblyServices services = assembly.services();
    CHECK(services.role != nullptr, "运行期 role 应非空");
    CHECK(services.context != nullptr, "运行期 context 应非空");
    CHECK(services.process != nullptr, "运行期 process 应非空");
    CHECK(services.subscriber != nullptr, "运行期 subscriber 应非空");

    assembly.stop();

    bool after_stop_threw = false;
    try {
        (void)assembly.services();
    }
    catch (const std::logic_error&) {
        after_stop_threw = true;
    }
    CHECK(after_stop_threw, "停机后 services() 应抛 std::logic_error");
}

/// @brief 先 stop() 后 start() 应被拒绝
void verify_start_after_stop()
{
    hng::Assembly assembly(make_options());
    assembly.stop();

    bool start_threw = false;
    try {
        assembly.start();
    }
    catch (const std::logic_error&) {
        start_threw = true;
    }
    CHECK(start_threw, "已停止的实例 start() 应抛 std::logic_error");
}

}  // namespace

int main()
{
    verify_lifecycle();
    verify_services();
    verify_start_after_stop();

    if (g_fail) {
        std::fprintf(stderr, "TOTAL FAILURES: %d\n", g_fail);
        return 1;
    }
    std::printf("ALL PASS\n");
    return 0;
}
