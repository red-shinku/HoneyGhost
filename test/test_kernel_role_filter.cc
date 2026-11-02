/**
 * @file test_kernel_role_filter.cc
 * @brief 包含真实过滤头，验证进程身份白名单及默认拒绝语义。
 * @note 使用 helpers/CO-RE 替身执行主机测试，不验证 eBPF verifier 或真实加载。
 */
#include <linux/types.h>
#include <linux/bpf.h>
#include <cstdio>
#include <stdexcept>

struct task_struct {
    __u32 tgid;
    __u64 start_boottime;
    task_struct* group_leader;
    task_struct* real_parent;
};
static void* bpf_get_current_task();
static void* bpf_map_lookup_elem(const void*, const void*);
#define __bpf__ 1
#include "kernel/include/role_filter.bpf.h"

namespace {
task_struct leader{100, 1230000000, nullptr, nullptr};
task_struct thread{100, 4560000000, &leader, &leader};
task_struct* current = &thread;
hng_role_filter_key saved{100, 0, 123};
__u32 allowed = 1;
bool found = false;
int checks = 0;
void require(bool c) { ++checks; if (!c) throw std::runtime_error("内核过滤语义检查失败"); }
}

static void* bpf_get_current_task() { return current; }
static void* bpf_map_lookup_elem(const void*, const void* input)
{
    auto key = static_cast<const hng_role_filter_key*>(input);
    require(key->reserved == 0);
    if (found && key->tgid == saved.tgid && key->start_time == saved.start_time) return &allowed;
    return nullptr;
}

int main()
{
    try {
        require(!hng_should_collect());
        found = true; require(hng_should_collect()); /** @note 使用 leader 的时间而非 thread 时间。 */
        allowed = 0; require(!hng_should_collect());
        allowed = 2; require(!hng_should_collect());
        allowed = 1; ++saved.start_time; require(!hng_should_collect());
        --saved.start_time; ++saved.tgid; require(!hng_should_collect());
        current = nullptr; require(!hng_should_collect());
        current = &thread; thread.group_leader = nullptr; require(!hng_should_collect());
        std::printf("PASS: kernel role filter, %d checks (helper mocks)\n", checks);
        return 0;
    } catch (const std::exception& e) { std::fprintf(stderr, "FAIL: %s\n", e.what()); return 1; }
}
