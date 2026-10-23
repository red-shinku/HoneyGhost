/**
 * @file test_process_manager.cc
 * @brief 进程管理器的单元测试
 * @details
 * 覆盖 ProcessManager：
 *  - 注册 / 注销经队列在消费线程上落地，查询按 (pid, start_time) 判等；
 *  - 角色归属转交：真正插入或替换后转交一次，幂等重放不转交；
 *  - pid 复用：旧实例按退役路径处理——替换时即报退出，
 *    有子进程时转入虚拟根供追溯，且不虚增其父进程的孩子计数；
 *  - 退出通知的两条路径：无子进程直接退出、有子进程转入虚拟根后退出，
 *    两条都在实进程退出时通知全部订阅者，虚拟根驱逐不重复通知；
 *  - 未登记与重复退出：仍按身份转发，由订阅方幂等处理；
 *  - 退出墓碑：迟到 ADD 被拒绝、pid 复用不误伤、存活查询命中/未命中/过期、
 *    墓碑先于退出通知写入、墓碑深度随退出与过期变化；
 *  - 父计数：父身份缺失时只计 parent_missing，不虚增计数；森林根不计；
 *  - stop() 语义：run() 之前 stop() 立即返回、已入队任务仍落地、此后入队被拒；
 *  - 多线程并发注册 / 注销后状态自洽（供 TSAN 构建复验）。
 * @author red_shinku
 * @date 2026.9.18
 */

#include "agent/control_plane/src/process_manager.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <functional>
#include <future>
#include <mutex>
#include <optional>
#include <thread>
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

hng::Process proc(uint32_t pid, uint64_t start)
{
    return hng::Process{pid, start};
}

hng::event_head head(uint32_t pid, uint64_t start, uint32_t ppid,
                     uint64_t ppid_start)
{
    hng::event_head ehead{};
    ehead.pid             = pid;
    ehead.pid_start_time  = start;
    ehead.ppid            = ppid;
    ehead.ppid_start_time = ppid_start;
    ehead.type            = hng::EventType::SYSCALL_EVENT;
    return ehead;
}

/// 轮询等待断言成立：落地在消费线程上，断言点只能等
bool wait_until(const std::function<bool()>& pred, int timeout_ms = 5000)
{
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return pred();
}

/// 可控时钟：只随测试推进，供墓碑寿命用例
struct FakeClock {
    hng::RelationTimePoint now{};
};

/// 三个注入点的记录：计数为原子（消费线程写、用例线程读），明细只在停止后读
struct Recorder {
    std::atomic<std::size_t> binds{0};
    std::atomic<std::size_t> ctx_exited{0};
    std::atomic<std::size_t> role_exited{0};

    std::mutex mutex;
    std::vector<std::pair<hng::Process, hng::Process>> bind_detail;
    std::vector<hng::Process> ctx_detail;
    std::vector<hng::Process> role_detail;
};

/// 两个订阅方各持一个实例，用于验证多播
class FakeLifecycleSink : public ProcessLifecycleSink {
   public:
    FakeLifecycleSink(Recorder& rec, bool context_side)
        : rec_(rec), context_side_(context_side)
    {
    }

    void on_process_exited(hng::Process p) override
    {
        {
            std::lock_guard lock(rec_.mutex);
            (context_side_ ? rec_.ctx_detail : rec_.role_detail).push_back(p);
        }
        (context_side_ ? rec_.ctx_exited : rec_.role_exited)
            .fetch_add(1, std::memory_order_relaxed);
    }

   private:
    Recorder& rec_;
    bool context_side_;
};

class FakeRoleJoin : public RoleJoinService {
   public:
    explicit FakeRoleJoin(Recorder& rec) : rec_(rec) {}

    void bind_to_role(hng::Process child, hng::Process parent) override
    {
        {
            std::lock_guard lock(rec_.mutex);
            rec_.bind_detail.emplace_back(child, parent);
        }
        rec_.binds.fetch_add(1);
    }

   private:
    Recorder& rec_;
};

/// 在退出回调内查询墓碑：回调运行于消费线程，用于验证墓碑先于通知写入，
/// 且通知路径不持有墓碑锁
class TombstoneProbeSink : public ProcessLifecycleSink {
   public:
    void attach(const ProcessManager* manager) { manager_ = manager; }

    void on_process_exited(hng::Process p) override
    {
        const bool hit = manager_ != nullptr && manager_->is_exited(p);
        {
            std::lock_guard lock(mutex_);
            last_ = p;
        }
        if (hit) {
            hits_.fetch_add(1, std::memory_order_relaxed);
        }
        calls_.fetch_add(1, std::memory_order_relaxed);
    }

    std::size_t calls() const { return calls_.load(std::memory_order_relaxed); }
    std::size_t hits() const { return hits_.load(std::memory_order_relaxed); }

    hng::Process last() const
    {
        std::lock_guard lock(mutex_);
        return last_;
    }

   private:
    const ProcessManager* manager_ = nullptr;
    std::atomic<std::size_t> calls_{0};
    std::atomic<std::size_t> hits_{0};
    mutable std::mutex mutex_;
    hng::Process last_{};
};

/// 起 run() 线程，析构时停止并 join
class Runner {
   public:
    explicit Runner(ProcessManager& manager)
        : manager_(manager), thread_([this] { manager_.run(); })
    {
    }

    ~Runner()
    {
        manager_.stop();
        thread_.join();
    }

    Runner(const Runner&)            = delete;
    Runner& operator=(const Runner&) = delete;

   private:
    ProcessManager& manager_;
    std::thread thread_;
};

void run_register_and_lookup()
{
    ProcessManager manager;
    Runner runner(manager);

    manager.register_pid(head(100, 1000, 1, 10));
    CHECK(wait_until([&] { return manager.lookup(proc(100, 1000)).has_value(); }),
          "注册应落地");

    std::optional<hng::ProcessMessage> msg = manager.lookup(proc(100, 1000));
    CHECK(msg.has_value() && msg->pid == 100 && msg->pid_start_time == 1000 &&
              msg->ppid == 1 && msg->ppid_start_time == 10,
          "进程记录应带 ppid 与各自的 start_time");
    CHECK(msg.has_value() && msg->child_count == 0, "新进程的孩子计数应为 0");
    CHECK(msg.has_value() && msg->kind == hng::ProcessKind::REAL,
          "注册的进程应为 REAL");
    CHECK(msg.has_value() && msg->exe.empty(), "注册时镜像为空");
    CHECK(!manager.lookup(proc(100, 9999)).has_value(),
          "同 pid 不同 start_time 应失配");
    CHECK(!manager.lookup(proc(101, 1000)).has_value(), "未注册的 pid 应失配");
}

void run_bind_transfer()
{
    Recorder rec;
    FakeRoleJoin join(rec);
    ProcessManager manager;
    manager.set_role_join_service(&join);
    Runner runner(manager);

    manager.register_pid(head(100, 1000, 1, 10));
    CHECK(wait_until([&] { return rec.binds.load() == 1; }), "插入应转交一次");
    {
        std::lock_guard lock(rec.mutex);
        CHECK(rec.bind_detail.size() == 1 &&
                  rec.bind_detail[0].first == proc(100, 1000) &&
                  rec.bind_detail[0].second == proc(1, 10),
              "转交的应是 (新进程, 事件的 ppid)");
    }

    // 幂等重放：同 pid + start_time 已存在，不插入也不转交
    manager.register_pid(head(100, 1000, 1, 10));
    manager.register_pid(head(200, 2000, 1, 10));  // 屏障
    CHECK(wait_until([&] { return rec.binds.load() == 2; }), "屏障应转交");
    CHECK(rec.binds.load() == 2, "幂等重放不得转交");

    // pid 复用：同 pid 不同 start_time，替换旧实例并转交新实例
    manager.register_pid(head(200, 2001, 1, 10));
    CHECK(wait_until([&] { return rec.binds.load() == 3; }), "覆盖应转交");
    CHECK(!manager.lookup(proc(200, 2000)).has_value(), "旧实例应被顶掉");
    CHECK(manager.lookup(proc(200, 2001)).has_value(), "新实例应在");
    CHECK(manager.stats().pid_reused == 1, "pid 复用应计数");
}

void run_pid_reuse()
{
    Recorder rec;
    FakeLifecycleSink ctx(rec, true);
    FakeLifecycleSink roles(rec, false);
    FakeRoleJoin join(rec);
    ProcessManager manager;
    manager.add_process_lifecycle_sink(&ctx);
    manager.add_process_lifecycle_sink(&roles);
    manager.set_role_join_service(&join);
    Runner runner(manager);

    // 覆盖的旧实例无存活子进程：替换时即报退出
    manager.register_pid(head(200, 2000, 1, 10));
    CHECK(wait_until([&] { return manager.lookup(proc(200, 2000)).has_value(); }),
          "注册应落地");
    manager.register_pid(head(200, 2001, 1, 10));  // pid 复用
    CHECK(wait_until([&] {
              return rec.ctx_exited.load() == 1 && rec.role_exited.load() == 1;
          }),
          "无子进程的旧实例在替换时应报退出");
    CHECK(!manager.lookup(proc(200, 2000)).has_value(), "旧实例应失配");
    CHECK(manager.lookup(proc(200, 2001)).has_value(), "新实例应可查");
    {
        std::lock_guard lock(rec.mutex);
        CHECK(rec.ctx_detail.size() == 1 && rec.ctx_detail[0] == proc(200, 2000),
              "报的应是旧实例");
    }

    // 覆盖的旧实例有存活子进程：替换时即报退出，转入虚拟根保留追溯
    manager.register_pid(head(300, 3000, 1, 10));
    manager.register_pid(head(301, 3001, 300, 3000));  // 子进程
    CHECK(wait_until([&] { return manager.lookup(proc(301, 3001)).has_value(); }),
          "子进程应落地");
    CHECK(manager.lookup(proc(300, 3000))->child_count == 1,
          "旧实例的孩子计数应为 1");

    manager.register_pid(head(300, 3002, 1, 10));  // 覆盖，此时旧实例有子
    manager.register_pid(head(500, 5000, 1, 10));  // 屏障
    CHECK(wait_until([&] { return manager.lookup(proc(500, 5000)).has_value(); }),
          "屏障应落地");
    CHECK(wait_until([&] {
              return rec.ctx_exited.load() == 2 && rec.role_exited.load() == 2;
          }),
          "转入虚拟根的旧实例在退出时即应通知，不等驱逐");
    CHECK(manager.lookup(proc(300, 3000)).has_value(),
          "旧实例应留在虚拟根里，仍可追溯");
    CHECK(manager.lookup(proc(300, 3002)).has_value(), "新实例应可查");

    // 子进程退出：报子进程自身；虚拟根驱逐不再重复通知
    manager.unregister_pid(proc(301, 3001));
    CHECK(wait_until([&] {
              return rec.ctx_exited.load() == 3 && rec.role_exited.load() == 3;
          }),
          "子进程退出应报一次，虚拟根驱逐不得重复通知");
    CHECK(!manager.lookup(proc(300, 3000)).has_value(), "被驱逐的旧实例应失配");
    {
        std::lock_guard lock(rec.mutex);
        CHECK(rec.ctx_detail.size() == 3 &&
                  rec.ctx_detail[1] == proc(300, 3000) &&
                  rec.ctx_detail[2] == proc(301, 3001),
              "旧实例在替换时通知，子进程在其退出时通知");
    }

    // 父进程的孩子计数不得被虚增：爷爷最终仍应能正常退出
    manager.register_pid(head(400, 4000, 1, 10));      // 爷爷
    manager.register_pid(head(401, 4001, 400, 4000));  // 父
    manager.register_pid(head(401, 4002, 400, 4000));  // 覆盖父
    CHECK(wait_until([&] { return rec.ctx_exited.load() == 4; }),
          "被覆盖的父应报退出");
    CHECK(manager.lookup(proc(400, 4000))->child_count == 1,
          "爷爷的孩子计数应仍是 1，不得虚增");

    manager.unregister_pid(proc(401, 4002));
    CHECK(wait_until([&] { return rec.ctx_exited.load() == 5; }),
          "新父退出应报退出");
    manager.unregister_pid(proc(400, 4000));
    CHECK(wait_until([&] { return rec.ctx_exited.load() == 6; }),
          "孩子计数不虚增，爷爷退出时应报退出");
    CHECK(!manager.lookup(proc(400, 4000)).has_value(), "爷爷应已失配");
    {
        std::lock_guard lock(rec.mutex);
        CHECK(rec.ctx_detail.back() == proc(400, 4000), "最后报的应是爷爷");
    }

    CHECK(manager.stats().pid_reused == 3, "三次 pid 复用都应计数");
}

void run_image_update()
{
    ProcessManager manager;
    Runner runner(manager);

    // 存活进程：更新落地后镜像可见，性质仍是 REAL
    manager.register_pid(head(100, 1000, 1, 10));
    CHECK(wait_until([&] { return manager.lookup(proc(100, 1000)).has_value(); }),
          "注册应落地");
    manager.update_exe_image(proc(100, 1000), "/bin/bash");
    CHECK(wait_until([&] {
              const auto msg = manager.lookup(proc(100, 1000));
              return msg && msg->exe == "/bin/bash";
          }),
          "镜像更新应落地");
    CHECK(manager.lookup(proc(100, 1000))->kind == hng::ProcessKind::REAL,
          "存活进程应为 REAL");

    // 已退出并转入虚拟根：保留最后镜像，性质为 VIRTUAL
    manager.register_pid(head(200, 2000, 1, 10));
    manager.register_pid(head(201, 2001, 200, 2000));
    CHECK(wait_until([&] { return manager.lookup(proc(201, 2001)).has_value(); }),
          "子进程应落地");
    manager.update_exe_image(proc(200, 2000), "/usr/bin/python3");
    CHECK(wait_until([&] {
              const auto msg = manager.lookup(proc(200, 2000));
              return msg && msg->exe == "/usr/bin/python3";
          }),
          "退出前镜像应落地");

    manager.unregister_pid(proc(200, 2000));
    CHECK(wait_until([&] {
              const auto msg = manager.lookup(proc(200, 2000));
              return msg && msg->kind == hng::ProcessKind::VIRTUAL;
          }),
          "有子进程的退出进程应转入虚拟根并标记 VIRTUAL");
    CHECK(manager.lookup(proc(200, 2000))->exe == "/usr/bin/python3",
          "转虚拟根应保留最后镜像");

    // 迟到更新命中虚拟根；同 pid 的新实例不受影响
    manager.update_exe_image(proc(200, 2000), "/usr/bin/perl");
    CHECK(wait_until([&] {
              const auto msg = manager.lookup(proc(200, 2000));
              return msg && msg->exe == "/usr/bin/perl";
          }),
          "虚拟根应接受迟到镜像更新");

    manager.register_pid(head(200, 2002, 1, 10));  // pid 复用
    CHECK(wait_until([&] { return manager.lookup(proc(200, 2002)).has_value(); }),
          "新实例应落地");
    manager.update_exe_image(proc(200, 2000), "/late");
    manager.register_pid(head(500, 5000, 1, 10));  // 屏障
    CHECK(wait_until([&] { return manager.lookup(proc(500, 5000)).has_value(); }),
          "屏障应落地");
    CHECK(manager.lookup(proc(200, 2002))->exe.empty(),
          "旧实例的迟到更新不得命中同 pid 的新实例");
    CHECK(manager.lookup(proc(200, 2000))->exe == "/late",
          "迟到更新应落到旧实例的虚拟根");
}

void run_resolve()
{
    ProcessManager manager;
    Runner runner(manager);

    CHECK(!manager.resolve(0).has_value(), "pid 0 应返回空");
    CHECK(!manager.resolve(777).has_value(), "未注册的 pid 应返回空");

    manager.register_pid(head(100, 1000, 1, 10));
    CHECK(wait_until([&] {
              auto p = manager.resolve(100);
              return p.has_value() && *p == proc(100, 1000);
          }),
          "注册后应能按 pid 解析");

    // pid 复用：返回当前实例
    manager.register_pid(head(100, 2000, 1, 10));
    CHECK(wait_until([&] {
              auto p = manager.resolve(100);
              return p.has_value() && *p == proc(100, 2000);
          }),
          "pid 复用后应返回新实例");

    // 虚拟根：父进程退出后仍可追溯
    manager.register_pid(head(300, 3000, 1, 10));
    manager.register_pid(head(301, 3001, 300, 3000));
    CHECK(wait_until([&] { return manager.lookup(proc(301, 3001)).has_value(); }),
          "子进程应落地");
    manager.unregister_pid(proc(300, 3000));
    manager.register_pid(head(500, 5000, 1, 10));  // 屏障
    CHECK(wait_until([&] { return manager.lookup(proc(500, 5000)).has_value(); }),
          "屏障应落地");
    CHECK(manager.lookup(proc(300, 3000)).has_value(), "父进程应在虚拟根中");
    std::optional<hng::Process> p = manager.resolve(300);
    CHECK(p.has_value() && *p == proc(300, 3000),
          "虚拟根应能按 pid 解析出 start_time");

    // 子进程退出后虚拟根被驱逐
    manager.unregister_pid(proc(301, 3001));
    manager.register_pid(head(501, 5001, 1, 10));  // 屏障
    CHECK(wait_until([&] { return manager.lookup(proc(501, 5001)).has_value(); }),
          "第二个屏障应落地");
    CHECK(!manager.resolve(300).has_value(), "虚拟根驱逐后应返回空");
}

void run_exit_paths()
{
    Recorder rec;
    FakeLifecycleSink ctx(rec, true);
    FakeLifecycleSink roles(rec, false);
    FakeRoleJoin join(rec);
    ProcessManager manager;
    manager.add_process_lifecycle_sink(&ctx);
    manager.add_process_lifecycle_sink(&roles);
    manager.set_role_join_service(&join);
    Runner runner(manager);

    // 路径一：无存活子进程 → 退出即通知
    manager.register_pid(head(100, 1000, 1, 10));
    CHECK(wait_until([&] { return manager.lookup(proc(100, 1000)).has_value(); }),
          "注册应落地");
    manager.unregister_pid(proc(100, 1000));
    CHECK(wait_until([&] {
              return rec.ctx_exited.load() == 1 && rec.role_exited.load() == 1;
          }),
          "无子进程的退出应报一次");

    // 路径二：有存活子进程 → 退出即通知，并留作虚拟根供追溯
    manager.register_pid(head(200, 2000, 1, 10));
    manager.register_pid(head(201, 2001, 200, 2000));
    CHECK(wait_until([&] { return manager.lookup(proc(201, 2001)).has_value(); }),
          "子进程应落地");
    CHECK(manager.lookup(proc(200, 2000))->child_count == 1,
          "父进程的孩子计数应为 1");

    manager.unregister_pid(proc(200, 2000));
    // 屏障：注册新进程；此时父进程应已转入虚拟根，仍可追溯
    manager.register_pid(head(300, 3000, 1, 10));
    CHECK(wait_until([&] { return manager.lookup(proc(300, 3000)).has_value(); }),
          "屏障应落地");
    CHECK(manager.lookup(proc(200, 2000)).has_value(),
          "有存活子进程的父进程应留作虚拟根，仍可查");
    CHECK(wait_until([&] {
              return rec.ctx_exited.load() == 2 && rec.role_exited.load() == 2;
          }),
          "留作虚拟根不推迟退出通知");

    manager.unregister_pid(proc(201, 2001));
    // 屏障：注册新进程；子进程退出后父进程的虚拟根计数归零，应被驱逐
    manager.register_pid(head(301, 3001, 1, 10));
    CHECK(wait_until([&] {
              return rec.ctx_exited.load() == 3 && rec.role_exited.load() == 3;
          }),
          "子进程退出应报一次，虚拟根驱逐不得重复通知");
    CHECK(!manager.lookup(proc(200, 2000)).has_value(), "被驱逐后应失配");
    CHECK(!manager.lookup(proc(201, 2001)).has_value(), "子进程应失配");

    // 两路订阅收到的进程集合应一致
    std::vector<hng::Process> ctx_seen;
    std::vector<hng::Process> role_seen;
    {
        std::lock_guard lock(rec.mutex);
        ctx_seen  = rec.ctx_detail;
        role_seen = rec.role_detail;
    }
    CHECK(ctx_seen == role_seen, "context 与角色两路应收到同一批进程");
    CHECK(ctx_seen.size() == 3, "应恰好报三次退出");
}

void run_unknown_and_duplicate()
{
    Recorder rec;
    FakeLifecycleSink ctx(rec, true);
    FakeLifecycleSink roles(rec, false);
    ProcessManager manager;
    manager.add_process_lifecycle_sink(&ctx);
    manager.add_process_lifecycle_sink(&roles);
    Runner runner(manager);

    // 未登记的退出：仍按身份转发，供下游清理陈旧归属
    manager.unregister_pid(proc(777, 7777));
    manager.register_pid(head(100, 1000, 1, 10));
    CHECK(wait_until([&] { return manager.lookup(proc(100, 1000)).has_value(); }),
          "注册应落地");
    CHECK(rec.ctx_exited.load() == 1 && rec.role_exited.load() == 1,
          "未登记的退出应转发一次");

    manager.unregister_pid(proc(100, 1000));
    CHECK(wait_until([&] { return rec.ctx_exited.load() == 2; }),
          "首次注销应报退出");
    manager.unregister_pid(proc(100, 1000));  // 重复注销

    manager.register_pid(head(101, 1001, 1, 10));  // 屏障
    CHECK(wait_until([&] { return manager.lookup(proc(101, 1001)).has_value(); }),
          "屏障应落地");
    CHECK(rec.ctx_exited.load() == 3 && rec.role_exited.load() == 3,
          "重复退出按身份转发，由订阅方幂等处理");
}

void run_exit_before_add()
{
    Recorder rec;
    FakeRoleJoin join(rec);
    ProcessManager manager;
    manager.set_role_join_service(&join);
    Runner runner(manager);

    manager.register_pid(head(50, 5000, 0, 0));  // 父进程，森林根
    CHECK(wait_until([&] { return manager.lookup(proc(50, 5000)).has_value(); }),
          "父进程应落地");
    CHECK(wait_until([&] { return rec.binds.load() == 1; }),
          "父进程应转交一次角色归属");

    // 未登记的退出先写墓碑，随后的 ADD 被整条丢弃
    manager.unregister_pid(proc(100, 1000));
    manager.register_pid(head(100, 1000, 50, 5000));
    CHECK(wait_until([&] { return manager.stats().stale_add == 1; }),
          "迟到 ADD 应被墓碑拒绝并计数");
    CHECK(!manager.lookup(proc(100, 1000)).has_value(), "迟到 ADD 不得插入");
    CHECK(rec.binds.load() == 1, "迟到 ADD 不得转交角色归属");
    CHECK(manager.lookup(proc(50, 5000))->child_count == 0,
          "迟到 ADD 不得更新父进程的孩子计数");
    CHECK(manager.stats().parent_missing == 0, "迟到 ADD 不得计父缺失");
}

void run_pid_reuse_not_misfire()
{
    ProcessManager manager;
    Runner runner(manager);

    manager.register_pid(head(100, 1000, 0, 0));
    CHECK(wait_until([&] { return manager.lookup(proc(100, 1000)).has_value(); }),
          "注册应落地");
    manager.unregister_pid(proc(100, 1000));
    manager.register_pid(head(100, 1001, 0, 0));  // 同 pid 的新实例
    CHECK(wait_until([&] { return manager.lookup(proc(100, 1001)).has_value(); }),
          "同 pid 不同 start_time 的新实例应正常插入");
    CHECK(manager.is_exited(proc(100, 1000)), "旧实例应有墓碑");
    CHECK(!manager.is_exited(proc(100, 1001)), "新实例不得命中旧实例的墓碑");
    CHECK(manager.stats().stale_add == 0, "新实例不得计迟到 ADD");
}

void run_is_exited_expiry()
{
    FakeClock clock;
    ProcessManagerOptions options;
    options.tombstones.ttl = std::chrono::milliseconds(100);
    options.now            = [&clock] { return clock.now; };

    ProcessManager manager(options);
    Runner runner(manager);

    manager.unregister_pid(proc(100, 1000));
    CHECK(wait_until([&] { return manager.stats().tombstone_depth == 1; }),
          "未登记的退出应写墓碑");
    CHECK(manager.is_exited(proc(100, 1000)), "墓碑应命中");
    CHECK(!manager.is_exited(proc(101, 1000)), "未记录的身份不应命中");
    CHECK(!manager.is_exited(proc(100, 1001)), "同 pid 不同 start_time 不应命中");

    clock.now += std::chrono::milliseconds(101);
    CHECK(!manager.is_exited(proc(100, 1000)), "过期墓碑不应命中");
    CHECK(manager.stats().tombstone_depth == 0, "过期墓碑应退出深度");
}

void run_tombstone_depth()
{
    FakeClock clock;
    ProcessManagerOptions options;
    options.tombstones.ttl = std::chrono::milliseconds(100);
    options.now            = [&clock] { return clock.now; };

    ProcessManager manager(options);
    Runner runner(manager);

    manager.unregister_pid(proc(800, 8000));
    manager.unregister_pid(proc(801, 8010));
    CHECK(wait_until([&] { return manager.stats().tombstone_depth == 2; }),
          "两条无记录退出应各写一条墓碑");

    manager.unregister_pid(proc(800, 8000));      // 重复退出
    manager.register_pid(head(900, 9000, 0, 0));  // 屏障
    CHECK(wait_until([&] { return manager.lookup(proc(900, 9000)).has_value(); }),
          "屏障应落地");
    CHECK(manager.stats().tombstone_depth == 2, "重复退出不得新增墓碑");

    clock.now += std::chrono::milliseconds(101);
    manager.register_pid(head(901, 9010, 0, 0));  // 屏障：落地末尾清理过期墓碑
    CHECK(wait_until([&] { return manager.lookup(proc(901, 9010)).has_value(); }),
          "第二个屏障应落地");
    CHECK(wait_until([&] { return manager.stats().tombstone_depth == 0; }),
          "过期墓碑应在落地末尾清除");
}

void run_tombstone_before_notify()
{
    ProcessManager manager;
    TombstoneProbeSink probe;
    probe.attach(&manager);
    manager.add_process_lifecycle_sink(&probe);
    Runner runner(manager);

    // 有记录退出
    manager.register_pid(head(100, 1000, 0, 0));
    CHECK(wait_until([&] { return manager.lookup(proc(100, 1000)).has_value(); }),
          "注册应落地");
    manager.unregister_pid(proc(100, 1000));
    CHECK(wait_until([&] { return probe.hits() == 1; }),
          "有记录退出在通知时墓碑应已写入");
    CHECK(probe.last() == proc(100, 1000), "通知的应是该进程");

    // 无记录退出
    manager.unregister_pid(proc(777, 7777));
    CHECK(wait_until([&] { return probe.hits() == 2; }),
          "无记录退出也应在通知前写墓碑");
    CHECK(probe.last() == proc(777, 7777), "无记录退出应按身份通知");
}

void run_pid_reuse_retire_tombstone()
{
    ProcessManager manager;
    TombstoneProbeSink probe;
    probe.attach(&manager);
    manager.add_process_lifecycle_sink(&probe);
    Runner runner(manager);

    manager.register_pid(head(200, 2000, 0, 0));
    CHECK(wait_until([&] { return manager.lookup(proc(200, 2000)).has_value(); }),
          "注册应落地");
    manager.register_pid(head(200, 2001, 0, 0));  // pid 复用
    CHECK(wait_until([&] { return manager.lookup(proc(200, 2001)).has_value(); }),
          "新实例应落地");
    CHECK(wait_until([&] { return probe.hits() == 1; }),
          "旧实例退役通知时墓碑应已写入");
    CHECK(probe.last() == proc(200, 2000), "通知的应是旧实例");
    CHECK(manager.is_exited(proc(200, 2000)), "旧实例应可查到墓碑");
    CHECK(!manager.is_exited(proc(200, 2001)), "新实例不得命中");
    CHECK(manager.stats().pid_reused == 1, "pid 复用应计数");
}

void run_parent_missing()
{
    ProcessManager manager;
    Runner runner(manager);

    manager.register_pid(head(100, 1000, 50, 5000));  // 父未注册
    CHECK(wait_until([&] { return manager.lookup(proc(100, 1000)).has_value(); }),
          "父缺失的 ADD 仍应插入");
    CHECK(wait_until([&] { return manager.stats().parent_missing == 1; }),
          "父缺失应计数");

    manager.register_pid(head(50, 5000, 0, 0));
    CHECK(wait_until([&] { return manager.lookup(proc(50, 5000)).has_value(); }),
          "父进程应落地");
    CHECK(manager.lookup(proc(50, 5000))->child_count == 0,
          "缺失的 ADD 不得虚增父进程的孩子计数");
    CHECK(manager.stats().parent_missing == 1, "父落地后不应重复计数");
}

void run_root_not_parent_missing()
{
    ProcessManager manager;
    Runner runner(manager);

    manager.register_pid(head(10, 100, 0, 0));
    CHECK(wait_until([&] { return manager.lookup(proc(10, 100)).has_value(); }),
          "森林根应落地");
    CHECK(manager.stats().parent_missing == 0, "森林根不应计父缺失");
}

void run_stop_semantics()
{
    // run() 之前 stop()：run() 立即返回
    {
        ProcessManager manager;
        manager.stop();
        manager.stop();  // 幂等

        std::packaged_task<void()> task([&manager] { manager.run(); });
        std::future<void> done = task.get_future();
        std::thread worker(std::move(task));
        const bool returned =
            done.wait_for(std::chrono::seconds(5)) == std::future_status::ready;
        CHECK(returned, "run() 之前 stop() 时 run() 应立即返回");
        if (returned) {
            worker.join();
        }
        else {
            worker.detach();  // 卡住的线程不能 join，交由进程退出兜底
        }
    }

    // 已入队的任务在 stop() 之后仍被落地
    {
        ProcessManager manager;
        manager.register_pid(head(100, 1000, 1, 10));
        manager.stop();
        manager.run();
        CHECK(manager.lookup(proc(100, 1000)).has_value(),
              "stop() 之后已入队的任务应被落地");
    }

    // stop() 之后的入队被拒（队列契约），不落地
    {
        ProcessManager manager;
        manager.stop();
        manager.register_pid(head(200, 2000, 1, 10));
        manager.run();  // 队列为空，应直接返回
        CHECK(!manager.lookup(proc(200, 2000)).has_value(),
              "停止后的入队不得落地");
    }
}

void run_concurrent_producers()
{
    Recorder rec;
    FakeLifecycleSink ctx(rec, true);
    FakeLifecycleSink roles(rec, false);
    FakeRoleJoin join(rec);
    ProcessManager manager;
    manager.add_process_lifecycle_sink(&ctx);
    manager.add_process_lifecycle_sink(&roles);
    manager.set_role_join_service(&join);
    Runner runner(manager);

    constexpr int kThreads = 4;
    constexpr int kEach    = 100;
    constexpr int kTotal   = kThreads * kEach;

    std::vector<std::thread> producers;
    for (int t = 0; t < kThreads; ++t) {
        producers.emplace_back([&manager, t] {
            for (int i = 0; i < kEach; ++i) {
                const uint32_t pid = 1000 + static_cast<uint32_t>(t) * 100 +
                                     static_cast<uint32_t>(i);
                manager.register_pid(head(pid, pid * 10, 1, 10));
                manager.unregister_pid(proc(pid, pid * 10));
            }
        });
    }
    for (std::thread& producer : producers) {
        producer.join();
    }

    CHECK(wait_until([&] {
              return rec.ctx_exited.load() == static_cast<std::size_t>(kTotal) &&
                     rec.role_exited.load() == static_cast<std::size_t>(kTotal);
          }),
          "每个进程注销后都应报退出");
    CHECK(rec.binds.load() == static_cast<std::size_t>(kTotal),
          "每个进程注册都应转交一次");

    for (int t = 0; t < kThreads; ++t) {
        for (int i = 0; i < kEach; ++i) {
            const uint32_t pid =
                1000 + static_cast<uint32_t>(t) * 100 + static_cast<uint32_t>(i);
            CHECK(!manager.lookup(proc(pid, pid * 10)).has_value(),
                  "并发注册注销后不应有残留");
        }
    }
}

}  // namespace

int main()
{
    run_register_and_lookup();
    run_bind_transfer();
    run_pid_reuse();
    run_image_update();
    run_resolve();
    run_exit_paths();
    run_unknown_and_duplicate();
    run_exit_before_add();
    run_pid_reuse_not_misfire();
    run_is_exited_expiry();
    run_tombstone_depth();
    run_tombstone_before_notify();
    run_pid_reuse_retire_tombstone();
    run_parent_missing();
    run_root_not_parent_missing();
    run_stop_semantics();
    run_concurrent_producers();

    if (g_fail) {
        std::fprintf(stderr, "TOTAL FAILURES: %d\n", g_fail);
        return 1;
    }
    std::printf("ALL PASS\n");
    return 0;
}
