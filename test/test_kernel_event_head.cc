/**
 * @file test_kernel_event_head.cc
 * @brief 包含真实事件头，验证主体与父进程身份、凭据、进程名与挂载命名空间。
 * @note 使用 helpers/CO-RE 替身与伪造 task_struct 在主机上执行，不验证 eBPF
 *       verifier 或真实内核读取。
 */
#include <linux/types.h>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <string>

struct kuid_t {
    __u32 val;
};

struct cred {
    kuid_t uid;
    kuid_t euid;
};

struct mnt_namespace {
    struct {
        unsigned int inum;
    } ns;
};

struct nsproxy {
    mnt_namespace* mnt_ns;
};

struct task_struct {
    __u32 tgid;
    __u64 start_boottime;
    task_struct* group_leader;
    task_struct* real_parent;
    struct cred* cred;
    char comm[16];
    struct nsproxy* nsproxy;
};

static void* bpf_get_current_task();

#define __bpf__ 1
#include "kernel/include/event_head.h"

namespace {

/// @brief 纳秒换算为 USER_HZ 时钟滴答的除数，与事件头的换算约定一致。
constexpr __u64 kTick         = NSEC_PER_USER_HZ;

/// @brief 非初始挂载命名空间的 inode，用于验证头里报送的是 inum 原值。
constexpr __u32 kNonInitMntNS = 4026532222;

/// @brief 进程 Q 的组长：启动时间与工作线程不同，用于区分进程身份与线程时间。
task_struct q{200, 200 * kTick, nullptr, nullptr, nullptr, {}, nullptr};
/// @brief 进程 Q 的工作线程：曾 fork 出进程 P，与组长共享父进程。
task_struct q_worker{200, 250 * kTick, &q, nullptr, nullptr, {}, nullptr};
/// @brief 进程 P 的组长：其 real_parent 是 Q 的工作线程。
task_struct p{100, 100 * kTick, nullptr, &q_worker, nullptr, {}, nullptr};
/// @brief 进程 P 的工作线程：与组长共享父进程，启动时间与组长不同。
task_struct p_worker{100, 150 * kTick, &p, &q_worker, nullptr, {}, nullptr};
/// @brief 无组长的任务，用于验证字段保持不变。
task_struct orphan{300, 300 * kTick, nullptr, &p, nullptr, {}, nullptr};

/// @brief 进程 P 与 Q 各自的凭据与挂载命名空间，取值不同以验证读取主体。
cred p_cred{{1000}, {0}};
cred q_cred{{2000}, {2000}};
mnt_namespace p_mnt{{kNonInitMntNS}};
mnt_namespace q_mnt{{HNG_INIT_MNT_NS_INUM}};
nsproxy p_ns{&p_mnt};
nsproxy q_ns{&q_mnt};

/// @brief 初始挂载命名空间，用于验证 inum 原样进入事件头。
mnt_namespace init_mnt{{HNG_INIT_MNT_NS_INUM}};
nsproxy init_ns{&init_mnt};

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

/// @brief 设置进程名；测试结构体的 comm 与内核一致，为 16 字节定长缓冲。
void set_comm(task_struct* task, const char* name)
{
    std::memset(task->comm, 0, sizeof(task->comm));
    std::strncpy(task->comm, name, sizeof(task->comm) - 1);
}

/// @brief 把全部字段置为可识别的哨兵，便于验证「不写」的语义
void reset(event_head* head)
{
    *head                 = event_head{};
    head->pid             = 0;
    head->pid_start_time  = 0;
    head->ppid            = 7;
    head->ppid_start_time = 9;
    head->uid             = 7;
    head->euid            = 8;
    head->mnt_ns          = 9;
    head->ret             = 10;
    std::memset(head->comm, 'x', sizeof(head->comm));
}

/// @brief comm 哨兵：全部为 'x'，用于验证父进程初始化不触碰主体字段
constexpr char kCommSentinel[] = "xxxxxxxxxxxxxxxx";

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

        set_comm(&q, "q-leader");
        set_comm(&q_worker, "q-worker");
        set_comm(&p, "p-leader");
        set_comm(&p_worker, "p-worker");

        q.cred           = &q_cred;
        q_worker.cred    = &q_cred;
        p.cred           = &p_cred;
        p_worker.cred    = &p_cred;

        q.nsproxy        = &q_ns;
        q_worker.nsproxy = &q_ns;
        p.nsproxy        = &p_ns;
        p_worker.nsproxy = &p_ns;

        // 父进程是组长
        reset(&head);
        current       = &p;
        p.real_parent = &q;
        init_event_head(&head);
        REQUIRE(head.pid == 100);
        REQUIRE(head.pid_start_time == 100);
        REQUIRE(head.ppid == 200);
        REQUIRE(head.ppid_start_time == 200);
        REQUIRE(head.uid == 1000);
        REQUIRE(head.euid == 0);
        REQUIRE(head.mnt_ns == kNonInitMntNS);
        REQUIRE(head.ret == 0);
        REQUIRE(std::string(head.comm) == "p-leader");

        // 父进程是另一进程的工作线程：取该线程的组长，而不是线程自身的启动时间；
        // 父进程的凭据、命名空间与进程名不参与主体字段
        reset(&head);
        p.real_parent = &q_worker;
        init_event_head(&head);
        REQUIRE(head.ppid == 200);
        REQUIRE(head.ppid_start_time == 200);
        REQUIRE(head.uid == 1000 && head.euid == 0);
        REQUIRE(head.mnt_ns == kNonInitMntNS);
        REQUIRE(std::string(head.comm) == "p-leader");

        // 事件主体是工作线程：主体时间取组长时间，进程名取事件主体自身的线程名
        reset(&head);
        current = &p_worker;
        init_event_head(&head);
        REQUIRE(head.pid == 100);
        REQUIRE(head.pid_start_time == 100);
        REQUIRE(head.ppid == 200);
        REQUIRE(head.ppid_start_time == 200);
        REQUIRE(head.uid == 1000);
        REQUIRE(head.euid == 0);
        REQUIRE(head.mnt_ns == kNonInitMntNS);
        REQUIRE(head.ret == 0);
        REQUIRE(std::string(head.comm) == "p-worker");

        // 主体字段的独立入口同样取组长身份，并填凭据/命名空间/进程名
        reset(&head);
        init_event_head_self(&head, &p_worker);
        REQUIRE(head.pid == 100);
        REQUIRE(head.pid_start_time == 100);
        REQUIRE(head.uid == 1000);
        REQUIRE(head.euid == 0);
        REQUIRE(head.mnt_ns == kNonInitMntNS);
        REQUIRE(head.ret == 0);
        REQUIRE(std::string(head.comm) == "p-worker");

        // 初始挂载命名空间按 inum 原值报送（判据留给用户态）
        p_worker.nsproxy = &init_ns;
        reset(&head);
        current = &p_worker;
        init_event_head(&head);
        REQUIRE(head.mnt_ns == HNG_INIT_MNT_NS_INUM);
        p_worker.nsproxy = &p_ns;

        // 空任务或父任务无组长时身份字段保持哨兵值
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

        // 凭据或命名空间任一级读不到：对应字段保持 0，其余主体字段照常
        task_struct incomplete{400,     400 * kTick, nullptr, nullptr,
                               nullptr, {},          nullptr};
        incomplete.group_leader = &incomplete;
        set_comm(&incomplete, "incomplete");
        reset(&head);
        init_event_head_self(&head, &incomplete);
        REQUIRE(head.pid == 400);
        REQUIRE(head.uid == 0 && head.euid == 0);
        REQUIRE(head.mnt_ns == 0);
        REQUIRE(head.ret == 0);
        REQUIRE(std::string(head.comm) == "incomplete");

        nsproxy empty_ns{nullptr};
        incomplete.nsproxy = &empty_ns;
        reset(&head);
        init_event_head_self(&head, &incomplete);
        REQUIRE(head.mnt_ns == 0);

        // 父进程字段的独立入口不触碰主体字段
        reset(&head);
        init_event_head_parent(&head, &q_worker);
        REQUIRE(head.ppid == 200);
        REQUIRE(head.ppid_start_time == 200);
        REQUIRE(head.uid == 7 && head.euid == 8);
        REQUIRE(head.mnt_ns == 9);
        REQUIRE(head.ret == 10);
        REQUIRE(std::memcmp(head.comm, kCommSentinel, sizeof(head.comm)) == 0);

        reset(&head);
        init_event_head_parent(&head, nullptr);
        REQUIRE(head.ppid == 7 && head.ppid_start_time == 9);

        // 探针侧的显式填法同样按组长取
        reset(&head);
        init_event_head_parent(&head, &q_worker);
        REQUIRE(head.ppid == 200);
        REQUIRE(head.ppid_start_time == 200);

        std::printf(
            "PASS: event head identity/creds/comm/mnt_ns/ret, %d checks "
            "(helper mocks)\n",
            checks);
        return 0;
    }
    catch (const std::exception& e) {
        std::fprintf(stderr, "FAIL: %s\n", e.what());
        return 1;
    }
}
