/**
 * @file test_kernel_event_head.cc
 * @brief 包含真实事件头，验证主体与父进程身份都取所属线程组的组长。
 * @note 使用 helpers/CO-RE 替身与伪造 task_struct 在主机上执行，不验证 eBPF
 *       verifier 或真实内核读取。
 */
#include <linux/types.h>
#include <cstdio>
#include <stdexcept>
#include <string>

struct task_struct {
    __u32 tgid;
    __u64 start_boottime;
    task_struct* group_leader;
    task_struct* real_parent;
};

static void* bpf_get_current_task();

#define __bpf__ 1
#include "kernel/include/event_head.h"

namespace {

/// @brief 纳秒换算为 USER_HZ 时钟滴答的除数，与事件头的换算约定一致。
constexpr __u64 kTick = NSEC_PER_USER_HZ;

/// @brief 进程 Q 的组长：启动时间与工作线程不同，用于区分进程身份与线程时间。
task_struct q{200, 200 * kTick, nullptr, nullptr};
/// @brief 进程 Q 的工作线程：曾 fork 出进程 P，与组长共享父进程。
task_struct q_worker{200, 250 * kTick, &q, nullptr};
/// @brief 进程 P 的组长：其 real_parent 是 Q 的工作线程。
task_struct p{100, 100 * kTick, nullptr, &q_worker};
/// @brief 进程 P 的工作线程：与组长共享父进程，启动时间与组长不同。
task_struct p_worker{100, 150 * kTick, &p, &q_worker};
/// @brief 无组长的任务，用于验证字段保持不变。
task_struct orphan{300, 300 * kTick, nullptr, &p};

task_struct* current = &p;
int checks           = 0;

void require(bool condition, const char* what)
{
    ++checks;
    if (!condition) {
        throw std::runtime_error(std::string("事件头身份检查失败：") + what);
    }
}

/// @brief 断言并在失败时给出表达式本身
#define REQUIRE(expr) require(static_cast<bool>(expr), #expr)

/// @brief 把身份字段置为可识别的哨兵，便于验证「不写」的语义
void reset(event_head* head)
{
    *head                 = event_head{};
    head->pid             = 0;
    head->pid_start_time  = 0;
    head->ppid            = 7;
    head->ppid_start_time = 9;
}

}  // namespace

static void* bpf_get_current_task() { return current; }

int main()
{
    try {
        event_head head{};

        // 内核中组长指向自身；夹具须同样自指，否则身份读取链会断
        q.group_leader        = &q;
        q_worker.group_leader = &q;
        p.group_leader        = &p;
        p_worker.group_leader = &p;

        // 父进程是组长
        reset(&head);
        current       = &p;
        p.real_parent = &q;
        init_event_head(&head);
        REQUIRE(head.pid == 100);
        REQUIRE(head.pid_start_time == 100);
        REQUIRE(head.ppid == 200);
        REQUIRE(head.ppid_start_time == 200);

        // 父进程是另一进程的工作线程：取该线程的组长，而不是线程自身的启动时间
        reset(&head);
        p.real_parent = &q_worker;
        init_event_head(&head);
        REQUIRE(head.ppid == 200);
        REQUIRE(head.ppid_start_time == 200);

        // 事件主体是工作线程：主体时间取组长时间，父进程取共享的父进程
        reset(&head);
        current = &p_worker;
        init_event_head(&head);
        REQUIRE(head.pid == 100);
        REQUIRE(head.pid_start_time == 100);
        REQUIRE(head.ppid == 200);
        REQUIRE(head.ppid_start_time == 200);

        // 主体字段的独立入口同样取组长
        reset(&head);
        init_event_head_self(&head, &p_worker);
        REQUIRE(head.pid == 100);
        REQUIRE(head.pid_start_time == 100);

        // 空任务或父任务无组长时字段保持哨兵值
        reset(&head);
        init_event_head_self(&head, nullptr);
        REQUIRE(head.pid == 0 && head.pid_start_time == 0);

        reset(&head);
        current       = &p;
        p.real_parent = nullptr;
        init_event_head(&head);
        REQUIRE(head.ppid == 7 && head.ppid_start_time == 9);

        reset(&head);
        p.real_parent = &orphan;
        init_event_head(&head);
        REQUIRE(head.ppid == 7 && head.ppid_start_time == 9);

        // 探针侧的显式填法同样按组长取
        reset(&head);
        init_event_head_parent(&head, &q_worker);
        REQUIRE(head.ppid == 200);
        REQUIRE(head.ppid_start_time == 200);

        reset(&head);
        init_event_head_parent(&head, nullptr);
        REQUIRE(head.ppid == 7 && head.ppid_start_time == 9);

        std::printf("PASS: event head identity, %d checks (helper mocks)\n",
                    checks);
        return 0;
    }
    catch (const std::exception& e) {
        std::fprintf(stderr, "FAIL: %s\n", e.what());
        return 1;
    }
}
