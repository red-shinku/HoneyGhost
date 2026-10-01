/**
 * @file semantic_syscall.cc
 * @brief 系统调用事件语义化处理器 实现
 * @details
 * 从系统调用原始事件队列取出 struct syscall_event，按 hdr.type 将 union 中八种
 * 事件分别转换为对应的 proto 语义载荷，组装为 syscall_semantic_data 推入下游
 * 语义事件队列（RawEventQueue_SS<syscall_semantic_data>）。
 *
 * 语义化原则：去除随机性信息。除 exec 的 filename（复用 agent/semantic/path/
 * 规则引擎语义化）与 credential 的 union→oneof 归位外，其余六种事件为纯字段
 * 搬运——进程身份头部原样拷贝，syscall 名由 hdr.name 枚举映射为字符串。
 *
 * @author red_shinku
 * @date 2026.08.17
 */

#include "agent/semantic/include/semantic.hpp"
#include "agent/semantic/src/path/path_normalizer.hpp"
#include "agent/semantic/src/path/path_rule.hpp"

#include <string>

namespace {

/**
 * @brief syscall_event_name 枚举 → 系统调用名字符串
 * @details 下游按名字符串识别具体系统调用；枚举顺序不保证稳定，故用 switch
 * 显式映射，-Wswitch 可保证新枚举值被覆盖。未知值兜底返回 "unknown"。
 */
const char* syscall_name_str(enum syscall_event_name name)
{
    switch (name) {
        case SYSCALL_EVENT_FORK:
            return "fork";
        case SYSCALL_EVENT_CLONE:
            return "clone";
        case SYSCALL_EVENT_VFORK:
            return "vfork";
        case SYSCALL_EVENT_EXECVE:
            return "execve";
        case SYSCALL_EVENT_EXECVEAT:
            return "execveat";
        case SYSCALL_EVENT_SETUID:
            return "setuid";
        case SYSCALL_EVENT_SETGID:
            return "setgid";
        case SYSCALL_EVENT_CAPSET:
            return "capset";
        case SYSCALL_EVENT_UNSHARE:
            return "unshare";
        case SYSCALL_EVENT_SETNS:
            return "setns";
        case SYSCALL_EVENT_PTRACE:
            return "ptrace";
        case SYSCALL_EVENT_BPF:
            return "bpf";
        case SYSCALL_EVENT_OPEN:
            return "open";
        case SYSCALL_EVENT_OPENAT:
            return "openat";
        case SYSCALL_EVENT_OPENAT2:
            return "openat2";
        case SYSCALL_EVENT_CREAT:
            return "creat";
        case SYSCALL_EVENT_UNLINK:
            return "unlink";
        case SYSCALL_EVENT_LINK:
            return "link";
        case SYSCALL_EVENT_RENAME:
            return "rename";
        case SYSCALL_EVENT_RENAMEAT:
            return "renameat";
        case SYSCALL_EVENT_RENAMEAT2:
            return "renameat2";
        case SYSCALL_EVENT_MMAP:
            return "mmap";
        case SYSCALL_EVENT_MPROTECT:
            return "mprotect";
        case SYSCALL_EVENT_CONNECT:
            return "connect";
        case SYSCALL_EVENT_SOCKET:
            return "socket";
        case SYSCALL_EVENT_BIND:
            return "bind";
        case SYSCALL_EVENT_EXIT_GROUP:
            return "exit_group";
        default:
            return "unknown";
    }
}

// 以下八个 helper 对应 hdr.type 的八种事件，各构造一种 proto 载荷填入 variant。
// 语义化原则：去除随机性；除 exec/credential 外均为纯字段搬运。

/**
 * @brief 进程生命周期事件 → process_semantic_data
 * @details 纯搬运 exit_code（exit_group 有效）。进程诞生事件无载荷字段，新进程
 * 身份由事件头给出（head.pid/pid_start_time=新进程，ppid=父进程）。
 */
void process_to_semantic(const struct syscall_event& raw,
                         hng::syscall_semantic_data& out)
{
    auto& d = out.data.emplace<hng::process_semantic_data>();
    d.set_exit_code(raw.process_event.exit_code);
    d.set_syscall_name(syscall_name_str(raw.hdr.name));
}

/**
 * @brief 执行事件 → exec_semantic_data
 * @details filename 复用路径语义化规则引擎去除随机性，输出 semantic_filename；
 * argv0/argv1（程序名与首参数）为稳定语义，原样保留。
 */
void exec_to_semantic(const struct syscall_event& raw,
                      hng::syscall_semantic_data& out)
{
    auto& d = out.data.emplace<hng::exec_semantic_data>();
    std::string norm, sem;
    hng::path::normalize(raw.exec_event.filename, norm);
    hng::path::semanticize(norm, sem);
    d.set_semantic_filename(sem);
    d.set_argv0(raw.exec_event.argv0);
    d.set_argv1(raw.exec_event.argv1);
    d.set_flags(raw.exec_event.flags);
    d.set_syscall_name(syscall_name_str(raw.hdr.name));
}

/**
 * @brief 权限变更事件 → credential_semantic_data
 * @details 内核侧为 union，此处按 hdr.name 归位到 oneof 的具体分支。
 */
void credential_to_semantic(const struct syscall_event& raw,
                            hng::syscall_semantic_data& out)
{
    auto& d = out.data.emplace<hng::credential_semantic_data>();
    switch (raw.hdr.name) {
        case SYSCALL_EVENT_SETUID:
            d.set_setuid_uid(raw.credential_event.setuid.uid);
            break;
        case SYSCALL_EVENT_SETGID:
            d.set_setgid_gid(raw.credential_event.setgid.gid);
            break;
        case SYSCALL_EVENT_CAPSET: {
            auto* cap = d.mutable_capset();
            cap->set_effective(raw.credential_event.capset.effective);
            cap->set_permitted(raw.credential_event.capset.permitted);
            cap->set_inheritable(raw.credential_event.capset.inheritable);
            break;
        }
        default:
            break;  // 防御：credential 类仅上述三种 name，理论不可达
    }
    d.set_syscall_name(syscall_name_str(raw.hdr.name));
}

/**
 * @brief 命名空间事件 → namespace_semantic_data
 * @details 纯搬运：ns_type 与 CLONE_NEW* 标志。
 */
void namespace_to_semantic(const struct syscall_event& raw,
                           hng::syscall_semantic_data& out)
{
    auto& d = out.data.emplace<hng::namespace_semantic_data>();
    d.set_ns_type(raw.namespace_event.ns_type);
    d.set_flags(raw.namespace_event.flags);
    d.set_syscall_name(syscall_name_str(raw.hdr.name));
}

/**
 * @brief 文件系统调用事件 → file_syscall_semantic_data
 * @details 纯搬运：O_* / RENAME_* 标志与创建权限 mode。文件路径由独立的文件
 * 事件采集模块（files.bpf.c）负责语义化，此处不携带路径。
 */
void file_to_semantic(const struct syscall_event& raw,
                      hng::syscall_semantic_data& out)
{
    auto& d = out.data.emplace<hng::file_syscall_semantic_data>();
    d.set_flags(raw.file_event.flags);
    d.set_mode(raw.file_event.mode);
    d.set_syscall_name(syscall_name_str(raw.hdr.name));
}

/**
 * @brief 内存事件 → memory_semantic_data
 * @details 纯搬运：PROT_* 权限与 MAP_* 标志。
 */
void memory_to_semantic(const struct syscall_event& raw,
                        hng::syscall_semantic_data& out)
{
    auto& d = out.data.emplace<hng::memory_semantic_data>();
    d.set_prot(raw.memory_event.prot);
    d.set_flags(raw.memory_event.flags);
    d.set_syscall_name(syscall_name_str(raw.hdr.name));
}

/**
 * @brief 网络事件 → network_syscall_semantic_data
 * @details 纯搬运：地址族 / 套接字类型 / 协议号。
 */
void network_to_semantic(const struct syscall_event& raw,
                         hng::syscall_semantic_data& out)
{
    auto& d = out.data.emplace<hng::network_syscall_semantic_data>();
    d.set_family(raw.network_event.family);
    d.set_type(raw.network_event.type);
    d.set_protocol(raw.network_event.protocol);
    d.set_syscall_name(syscall_name_str(raw.hdr.name));
}

/**
 * @brief 内核操作事件 → kernel_semantic_data
 * @details 纯搬运：ptrace 请求类型或 bpf 命令及其关联参数。
 */
void kernel_to_semantic(const struct syscall_event& raw,
                        hng::syscall_semantic_data& out)
{
    auto& d = out.data.emplace<hng::kernel_semantic_data>();
    d.set_command(raw.kernel_event.command);
    d.set_arg(raw.kernel_event.arg);
    d.set_syscall_name(syscall_name_str(raw.hdr.name));
}

}  // namespace

Semantic_syscall::Semantic_syscall(
    hng::SPSC_Queue<struct syscall_event>& in_queue,
    hng::SPSC_Queue<hng::syscall_semantic_data>& out_queue)
    : raw_event_queue(in_queue), event_queue(out_queue)
{
}

Semantic_syscall::~Semantic_syscall() {}

/**
 * @brief 单条系统调用事件语义化
 * @details 编排两步：进程身份头部原样拷贝 → 按 hdr.type 分派八种载荷转换，
 * 推入下游队列。
 */
void Semantic_syscall::transform()
{
    struct syscall_event raw;
    if (!raw_event_queue.pop(raw)) {
        return;  // 输入队列空
    }

    hng::syscall_semantic_data ev;
    transform_one(raw, ev);

    event_queue.push(ev);  // TODO: 下游队列满时丢事件，背压策略待定
}

/**
 * @brief 原始事件 → 语义事件纯转换
 * @details 输入事件头（进程身份上下文）原样拷贝为语义事件头部；载荷按
 * hdr.type 分派到对应 helper。hdr.type 由内核侧 init_syscall_event_head 归类，
 * 此处不做重新推断。
 */
void Semantic_syscall::transform_one(const struct syscall_event& raw,
                                     hng::syscall_semantic_data& out)
{
    out.head.pid             = raw.hdr.head.pid;
    out.head.pid_start_time  = raw.hdr.head.pid_start_time;
    out.head.ppid            = raw.hdr.head.ppid;
    out.head.ppid_start_time = raw.hdr.head.ppid_start_time;

    // head.type 为顶层事件流类别（hng::EventType，scoped 枚举），与 raw.hdr.type
    // （syscall_event_type 的八类细分）不同义；本流恒为 syscall 语义流，故固定。
    out.head.type            = hng::EventType::SYSCALL_EVENT;

    switch (raw.hdr.type) {
        case PROCESS_EVENT:
            process_to_semantic(raw, out);
            break;
        case EXEC_EVENT:
            exec_to_semantic(raw, out);
            break;
        case CREDENTIAL_EVENT:
            credential_to_semantic(raw, out);
            break;
        case NAMESPACE_EVENT:
            namespace_to_semantic(raw, out);
            break;
        case FILE_EVENT:
            file_to_semantic(raw, out);
            break;
        case MEMORY_EVENT:
            memory_to_semantic(raw, out);
            break;
        case NETWORK_EVENT:
            network_to_semantic(raw, out);
            break;
        case KERNEL_EVENT:
            kernel_to_semantic(raw, out);
            break;
    }
}

/**
 * @brief 工作循环：持续消费系统调用原始事件
 * @details 忙轮询直到退出。TODO: 队列空时的调度让出与退出机制。
 */
void Semantic_syscall::work()
{
    while (true) {
        transform();
    }
}
