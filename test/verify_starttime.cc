/**
 * @file verify_starttime.cc
 * @brief 阶段 01 校验：事件头 pid_start_time 与 /proc 字段 22 相等
 * @details
 * 加载 syscalls.bpf.o，附着 wake_up_new_task kprobe 与 sys_enter_exit_group
 * tracepoint，从 ringbuf 取事件，与其 /proc 取值比对。覆盖两个入口 × 两条路径
 * 共四处填法：
 *   - fork 事件显式填法：pid 路径（子进程）、ppid 路径（子进程的 real_parent）
 *   - init_event_head 公共填法：pid 路径（事件主体）、ppid 路径（real_parent）
 *
 * 校验方式是 fork 一个已知 pid 的子进程，比对其存活期间（含僵尸态）的 /proc
 * 取值；子进程消失则该处记 SKIP，不计为通过。退出码 0 仅在四处全部比对通过时
 * 给出。
 *
 * 需 root 与 BPF 权限，故不注册为 ctest 用例。从仓库根手动执行：
 *   sudo build-agent/test/verify_starttime [syscalls.bpf.o 路径]
 *
 * @author red_shinku
 * @date 2026.9.10
 */

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <cerrno>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <sys/wait.h>
#include <unistd.h>

#include "kernel/include/syscalls_type.h"

namespace {

/// 待校验的四处填法，按位标记；一次运行各自比对一次
enum Site : int {
    SITE_FORK_PID  = 1 << 0,  ///< fork 事件：新进程自身的启动时间
    SITE_FORK_PPID = 1 << 1,  ///< fork 事件：real_parent 的启动时间
    SITE_INIT_PID  = 1 << 2,  ///< init_event_head：事件主体的启动时间
    SITE_INIT_PPID = 1 << 3,  ///< init_event_head：real_parent 的启动时间
    SITE_ALL       = 0xF,
};

const char *site_name(int bit)
{
    switch (bit) {
        case SITE_FORK_PID:
            return "fork/pid ";
        case SITE_FORK_PPID:
            return "fork/ppid";
        case SITE_INIT_PID:
            return "init/pid ";
        case SITE_INIT_PPID:
            return "init/ppid";
        default:
            return "?";
    }
}

struct Checker {
    pid_t subject;  ///< 被观测的子进程，也是事件的 pid 路径对象
    pid_t parent;   ///< 本进程，即子进程的 real_parent，也是事件的 ppid 路径对象
    int pending;    ///< 尚未比对的填法位（Site 位掩码）
    int ok;
    int skipped;
    int fails;
};

/**
 * @brief 读取 /proc/<pid>/stat 字段 22（USER_HZ 对齐的 boottime tick）
 * @return false 进程已不存在或字段缺失
 */
bool proc_start_time(uint32_t pid, uint64_t *out)
{
    char path[64];
    std::snprintf(path, sizeof(path), "/proc/%u/stat", pid);

    FILE *f = std::fopen(path, "r");
    if (!f) {
        return false;
    }
    char line[4096];
    char *got = std::fgets(line, sizeof(line), f);
    std::fclose(f);
    if (!got) {
        return false;
    }

    // 字段 2（comm）可能含空格与右括号，故取最后一个 ')' 作为字段 3 的起点
    char *p = std::strrchr(line, ')');
    if (!p) {
        return false;
    }
    ++p;

    for (int field = 3; field <= 22; ++field) {
        while (*p == ' ') {
            ++p;
        }
        if (*p == '\0') {
            return false;
        }
        if (field == 22) {
            *out = std::strtoull(p, nullptr, 10);
            return true;
        }
        if (field == 3) {
            ++p;  // state 是单字符
        }
        else {
            std::strtoull(p, &p, 10);
        }
    }
    return false;
}

/**
 * @brief 比对一处填法
 * @param bit         填法标记，比对后从 pending 中清除
 * @param expect_pid  该路径本应指向的进程，用于确认路径取对了对象
 * @param got_pid     事件中该路径给出的 pid
 * @param got_start   事件中该路径给出的 pid_start_time
 */
void check_site(Checker *c, int bit, uint32_t expect_pid, uint32_t got_pid,
                uint64_t got_start)
{
    if (!(c->pending & bit)) {
        return;
    }
    c->pending       &= ~bit;
    const char *name  = site_name(bit);

    if (got_pid != expect_pid) {
        ++c->fails;
        std::printf("[FAIL] %s  事件 pid=%u，应为 %u\n", name, got_pid,
                    expect_pid);
        return;
    }

    uint64_t want = 0;
    if (!proc_start_time(got_pid, &want)) {
        ++c->skipped;
        std::printf("[SKIP] %s  pid=%u 已消失，无法比对\n", name, got_pid);
        return;
    }

    if (want == got_start) {
        ++c->ok;
        std::printf("[ OK ] %s  pid=%-7u eBPF=%-10" PRIu64 " /proc=%" PRIu64 "\n",
                    name, got_pid, got_start, want);
    }
    else {
        ++c->fails;
        std::printf("[FAIL] %s  pid=%-7u eBPF=%-10" PRIu64 " /proc=%-10" PRIu64
                    " 差值 %" PRId64 "\n",
                    name, got_pid, got_start, want,
                    static_cast<int64_t>(got_start) - static_cast<int64_t>(want));
    }
}

int on_event(void *ctx, void *data, size_t size)
{
    auto *c = static_cast<Checker *>(ctx);
    if (size < sizeof(struct syscall_event)) {
        return 0;
    }
    auto *ev                   = static_cast<struct syscall_event *>(data);
    const struct event_head &h = ev->hdr.head;

    // 只关心本进程观测的那一个子进程，其余进程的事件全部忽略
    if (h.pid != static_cast<uint32_t>(c->subject)) {
        return 0;
    }

    switch (ev->hdr.name) {
        case SYSCALL_EVENT_FORK:
            check_site(c, SITE_FORK_PID, static_cast<uint32_t>(c->subject), h.pid,
                       h.pid_start_time);
            check_site(c, SITE_FORK_PPID, static_cast<uint32_t>(c->parent),
                       h.ppid, h.ppid_start_time);
            break;
        case SYSCALL_EVENT_EXIT_GROUP:
            check_site(c, SITE_INIT_PID, static_cast<uint32_t>(c->subject), h.pid,
                       h.pid_start_time);
            check_site(c, SITE_INIT_PPID, static_cast<uint32_t>(c->parent),
                       h.ppid, h.ppid_start_time);
            break;
        default:
            break;
    }
    return 0;
}

int run(const char *obj_path)
{
    bpf_object *obj = bpf_object__open_file(obj_path, nullptr);
    if (long err = libbpf_get_error(obj)) {
        std::fprintf(stderr, "打开 %s 失败：%s（%ld）\n", obj_path,
                     std::strerror(-err), err);
        return 2;
    }
    if (int err = bpf_object__load(obj)) {
        std::fprintf(stderr, "加载 BPF 对象失败：%s（需 root 与 BPF 权限）\n",
                     std::strerror(-err));
        bpf_object__close(obj);
        return 2;
    }

    bpf_program *prog_fork =
        bpf_object__find_program_by_name(obj, "trace_process_birth");
    bpf_program *prog_exit =
        bpf_object__find_program_by_name(obj, "trace_exit_group");
    bpf_map *map = bpf_object__find_map_by_name(obj, "syscall_events");
    if (!prog_fork || !prog_exit || !map) {
        std::fprintf(stderr,
                     "对象内缺少探针或 ringbuf map，可能不是 syscalls.bpf.o\n");
        bpf_object__close(obj);
        return 2;
    }

    Checker ck{};
    ck.pending      = SITE_ALL;
    ck.parent       = ::getpid();

    ring_buffer *rb = ring_buffer__new(bpf_map__fd(map), on_event, &ck, nullptr);
    if (!rb) {
        std::fprintf(stderr, "创建 ringbuf 读取器失败：%s\n",
                     std::strerror(errno));
        bpf_object__close(obj);
        return 2;
    }

    bpf_link *link_fork = bpf_program__attach(prog_fork);
    bpf_link *link_exit = bpf_program__attach(prog_exit);
    if (libbpf_get_error(link_fork) || libbpf_get_error(link_exit)) {
        std::fprintf(stderr, "附着探针失败，需 root 与 CAP_BPF\n");
        ring_buffer__free(rb);
        bpf_object__close(obj);
        return 2;
    }

    // 先建流后造进程：探针就位后再 fork，否则子进程的 fork 事件会永久丢失
    ck.subject = ::fork();
    if (ck.subject < 0) {
        std::fprintf(stderr, "fork 失败：%s\n", std::strerror(errno));
        return 2;
    }
    if (ck.subject == 0) {
        // 子进程：稍候退出以触发 exit_group；父进程不回收，让 /proc 仍可读
        ::usleep(1500 * 1000);
        ::_exit(0);
    }

    std::printf("对象：%s\n主体：pid=%d  父进程：pid=%d\n\n", obj_path,
                ck.subject, ck.parent);

    // 探针一律以 BPF_RB_NO_WAKEUP 提交，不产生唤醒，故不能用 ring_buffer__poll
    // （epoll 永不就绪），必须主动轮询消费
    for (int waited = 0; ck.pending && waited < 5000; waited += 10) {
        if (int n = ring_buffer__consume(rb); n < 0) {
            std::fprintf(stderr, "ringbuf 读取失败：%s\n", std::strerror(-n));
            break;
        }
        ::usleep(10 * 1000);
    }

    for (int bit = 1; bit <= SITE_INIT_PPID; bit <<= 1) {
        if (ck.pending & bit) {
            std::printf("[MISS] %s  未观测到对应事件\n", site_name(bit));
        }
    }

    int status = 0;
    ::waitpid(ck.subject, &status, 0);
    ring_buffer__free(rb);
    bpf_link__destroy(link_fork);
    bpf_link__destroy(link_exit);
    bpf_object__close(obj);

    const int unfinished = __builtin_popcount(static_cast<unsigned>(ck.pending));
    std::printf("\n通过 %d，跳过 %d，失败 %d，未观测到 %d\n", ck.ok, ck.skipped,
                ck.fails, unfinished);
    return (ck.ok == 4) ? 0 : 1;
}

}  // namespace

int main(int argc, char **argv)
{
    const char *obj_path = (argc > 1) ? argv[1] : "kernel/build/syscalls.bpf.o";
    return run(obj_path);
}
