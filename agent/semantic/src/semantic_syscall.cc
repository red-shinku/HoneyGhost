/**
 * @file semantic_syscall.cc
 * @brief 系统调用事件语义化工具实现
 * @details
 * 按 hdr.subtype 将 union 中九种事件分别转换为对应的 proto 语义载荷，组装为
 * syscall_semantic_data。本工具不持有队列与线程状态。
 *
 * 语义化原则：去除随机性信息。除 exec 的 image（先 normalize，再复用
 * agent/semantic/path/ 规则引擎语义化）、file 的 path1/path2 与 memory 的 path
 * （各自 normalize 消除拼写差异）与 credential 按 kind 展开 requested 外，其余
 * 事件为纯字段搬运——进程身份字符串字段收敛为合法 UTF-8 后拷贝，syscall 名由
 * hdr.name 枚举映射为字符串。
 *
 * @author red_shinku
 * @date 2026.08.17
 */

#include "agent/semantic/src/semantic.hpp"
#include "agent/semantic/src/path/path_normalizer.hpp"
#include "agent/semantic/src/path/path_rule.hpp"
#include "agent/util/include/utf8_sanitize.hpp"

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
        case SYSCALL_EVENT_SETREUID:
            return "setreuid";
        case SYSCALL_EVENT_SETRESUID:
            return "setresuid";
        case SYSCALL_EVENT_SETFSUID:
            return "setfsuid";
        case SYSCALL_EVENT_SETRESGID:
            return "setresgid";
        case SYSCALL_EVENT_SETGROUPS:
            return "setgroups";
        case SYSCALL_EVENT_PRCTL:
            return "prctl";
        case SYSCALL_EVENT_UNSHARE:
            return "unshare";
        case SYSCALL_EVENT_SETNS:
            return "setns";
        case SYSCALL_EVENT_MOUNT:
            return "mount";
        case SYSCALL_EVENT_UMOUNT2:
            return "umount2";
        case SYSCALL_EVENT_PIVOT_ROOT:
            return "pivot_root";
        case SYSCALL_EVENT_CHROOT:
            return "chroot";
        case SYSCALL_EVENT_PTRACE:
            return "ptrace";
        case SYSCALL_EVENT_BPF:
            return "bpf";
        case SYSCALL_EVENT_INIT_MODULE:
            return "init_module";
        case SYSCALL_EVENT_FINIT_MODULE:
            return "finit_module";
        case SYSCALL_EVENT_DELETE_MODULE:
            return "delete_module";
        case SYSCALL_EVENT_KEXEC_LOAD:
            return "kexec_load";
        case SYSCALL_EVENT_REBOOT:
            return "reboot";
        case SYSCALL_EVENT_SETHOSTNAME:
            return "sethostname";
        case SYSCALL_EVENT_TASK_RENAME:
            return "task_rename";
        case SYSCALL_EVENT_CGROUP_ATTACH_TASK:
            return "cgroup_attach_task";
        case SYSCALL_EVENT_MODULE_LOAD:
            return "module_load";
        case SYSCALL_EVENT_MODULE_FREE:
            return "module_free";
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
        case SYSCALL_EVENT_UNLINKAT:
            return "unlinkat";
        case SYSCALL_EVENT_LINKAT:
            return "linkat";
        case SYSCALL_EVENT_SYMLINK:
            return "symlink";
        case SYSCALL_EVENT_SYMLINKAT:
            return "symlinkat";
        case SYSCALL_EVENT_CHMOD:
            return "chmod";
        case SYSCALL_EVENT_FCHMOD:
            return "fchmod";
        case SYSCALL_EVENT_FCHMODAT:
            return "fchmodat";
        case SYSCALL_EVENT_TRUNCATE:
            return "truncate";
        case SYSCALL_EVENT_FTRUNCATE:
            return "ftruncate";
        case SYSCALL_EVENT_MKNOD:
            return "mknod";
        case SYSCALL_EVENT_MKNODAT:
            return "mknodat";
        case SYSCALL_EVENT_MEMFD_CREATE:
            return "memfd_create";
        case SYSCALL_EVENT_OPEN_BY_HANDLE_AT:
            return "open_by_handle_at";
        case SYSCALL_EVENT_NAME_TO_HANDLE_AT:
            return "name_to_handle_at";
        case SYSCALL_EVENT_CHDIR:
            return "chdir";
        case SYSCALL_EVENT_FCHDIR:
            return "fchdir";
        case SYSCALL_EVENT_MMAP:
            return "mmap";
        case SYSCALL_EVENT_MPROTECT:
            return "mprotect";
        case SYSCALL_EVENT_MREMAP:
            return "mremap";
        case SYSCALL_EVENT_MUNMAP:
            return "munmap";
        case SYSCALL_EVENT_CONNECT:
            return "connect";
        case SYSCALL_EVENT_SOCKET:
            return "socket";
        case SYSCALL_EVENT_BIND:
            return "bind";
        case SYSCALL_EVENT_SENDTO:
            return "sendto";
        case SYSCALL_EVENT_SENDMSG:
            return "sendmsg";
        case SYSCALL_EVENT_RECVFROM:
            return "recvfrom";
        case SYSCALL_EVENT_ACCEPT4:
            return "accept4";
        case SYSCALL_EVENT_LISTEN:
            return "listen";
        case SYSCALL_EVENT_KILL:
            return "kill";
        case SYSCALL_EVENT_TKILL:
            return "tkill";
        case SYSCALL_EVENT_TGKILL:
            return "tgkill";
        case SYSCALL_EVENT_RT_SIGQUEUEINFO:
            return "rt_sigqueueinfo";
        case SYSCALL_EVENT_EXIT_GROUP:
            return "exit_group";
        default:
            return "unknown";
    }
}

// 以下九个 helper 对应 hdr.subtype 的九种事件，各构造一种 proto 载荷填入
// variant。 语义化原则：去除随机性；除 exec/credential 外均为纯字段搬运。

/**
 * @brief 进程生命周期事件 → process_semantic_data
 * @details exit_code 等数值字段纯搬运（进程退出事件有效），字符串字段收敛为合法
 * UTF-8 后搬运。进程诞生事件无载荷字段，新进程身份由事件头给出
 * （head.pid/pid_start_time=新进程，ppid=父进程）。
 */
void process_to_semantic(const struct syscall_event& raw,
                         hng::syscall_semantic_data& out)
{
    auto& d = out.data.emplace<hng::process_semantic_data>();
    d.set_exit_code(raw.process_event.exit_code);
    d.set_derived_flags(raw.process_event.derived_flags);
    d.set_exit_signal(raw.process_event.exit_signal);
    d.set_old_comm(hng::sanitize_utf8(raw.process_event.old_comm,
                                      sizeof(raw.process_event.old_comm)));
    d.set_new_comm(hng::sanitize_utf8(raw.process_event.new_comm,
                                      sizeof(raw.process_event.new_comm)));
    d.set_cgroup_path(hng::sanitize_utf8(raw.process_event.cgroup_path,
                                         sizeof(raw.process_event.cgroup_path)));
    d.set_target_pid(raw.process_event.target_pid);
    d.set_syscall_name(syscall_name_str(raw.hdr.name));
}

/**
 * @brief 执行事件 → exec_semantic_data
 * @details image 收敛为合法 UTF-8 后再 normalize 消除拼写差异，然后原样输出（供
 * 取证，保留实例信息），再经路径语义化规则引擎去除随机性后输出 semantic_filename
 * （供规则与基线）；invoked 是用户原始输入，收敛为合法 UTF-8 后搬运，不做
 * normalize。image 为空时上述两个路径字段均为空串。argv0..argv3、LD_PRELOAD 与
 * LD_LIBRARY_PATH 是命令行/注入特征，收敛为合法 UTF-8 后保留；image_flags 原样
 * 透传。
 */
void exec_to_semantic(const struct syscall_event& raw,
                      hng::syscall_semantic_data& out)
{
    auto& d = out.data.emplace<hng::exec_semantic_data>();
    const std::string image =
        hng::sanitize_utf8(raw.exec_event.image, sizeof(raw.exec_event.image));
    std::string norm, sem;
    hng::path::normalize(image, norm);
    d.set_image(norm);
    if (!norm.empty()) {
        hng::path::semanticize(norm, sem);
        d.set_semantic_filename(sem);
    }
    d.set_invoked(hng::sanitize_utf8(raw.exec_event.invoked,
                                     sizeof(raw.exec_event.invoked)));
    d.set_image_flags(raw.exec_event.image_flags);
    d.set_argv0(
        hng::sanitize_utf8(raw.exec_event.argv0, sizeof(raw.exec_event.argv0)));
    d.set_argv1(
        hng::sanitize_utf8(raw.exec_event.argv1, sizeof(raw.exec_event.argv1)));
    d.set_argv2(
        hng::sanitize_utf8(raw.exec_event.argv2, sizeof(raw.exec_event.argv2)));
    d.set_argv3(
        hng::sanitize_utf8(raw.exec_event.argv3, sizeof(raw.exec_event.argv3)));
    d.set_ld_preload(hng::sanitize_utf8(raw.exec_event.ld_preload,
                                        sizeof(raw.exec_event.ld_preload)));
    d.set_ld_library_path(hng::sanitize_utf8(
        raw.exec_event.ld_library_path, sizeof(raw.exec_event.ld_library_path)));
    d.set_flags(raw.exec_event.flags);
    d.set_syscall_name(syscall_name_str(raw.hdr.name));
}

/**
 * @brief 权限变更事件 → credential_semantic_data
 * @details 内核侧用 kind 区分请求的是 UID、GID、Capability 集合还是 prctl：按
 * kind 搬运，requested 逐项展开，capset 只在 kind=CAPS 时填充，prctl 的三个
 * 字段只在 kind=PRCTL 时填充。
 */
void credential_to_semantic(const struct syscall_event& raw,
                            hng::syscall_semantic_data& out)
{
    auto& d = out.data.emplace<hng::credential_semantic_data>();
    d.set_kind(raw.credential_event.kind);
    // requested 固定 3 槽，探针保证 count 不越界，此处仍按槽数截断
    for (__u32 i = 0; i < raw.credential_event.requested_count && i < 3; ++i) {
        d.add_requested(raw.credential_event.requested[i]);
    }
    if (raw.credential_event.kind == CREDENTIAL_CAPS) {
        auto* cap = d.mutable_capset();
        cap->set_effective(raw.credential_event.cap_effective);
        cap->set_permitted(raw.credential_event.cap_permitted);
        cap->set_inheritable(raw.credential_event.cap_inheritable);
    }
    else if (raw.credential_event.kind == CREDENTIAL_PRCTL) {
        d.set_prctl_option(raw.credential_event.prctl_option);
        d.set_arg2(raw.credential_event.arg2);
        d.set_securebits(raw.credential_event.securebits);
    }
    d.set_syscall_name(syscall_name_str(raw.hdr.name));
}

/**
 * @brief 命名空间事件 → namespace_semantic_data
 * @details unshare/setns 搬运 CLONE_* 掩码与目标 fd；mount 族搬运两条路径
 * （各自收敛为合法 UTF-8 后再 normalize 输出，未解析的路径保留收敛后的串）、
 * 文件系统类型（收敛为合法 UTF-8）与挂载标志。
 */
void namespace_to_semantic(const struct syscall_event& raw,
                           hng::syscall_semantic_data& out)
{
    auto& d = out.data.emplace<hng::namespace_semantic_data>();
    d.set_flags(raw.namespace_event.flags);
    d.set_ns_mask(raw.namespace_event.ns_mask);
    d.set_fd(raw.namespace_event.fd);
    std::string norm;
    hng::path::normalize(hng::sanitize_utf8(raw.namespace_event.source,
                                            sizeof(raw.namespace_event.source)),
                         norm);
    d.set_source(norm);
    hng::path::normalize(hng::sanitize_utf8(raw.namespace_event.target,
                                            sizeof(raw.namespace_event.target)),
                         norm);
    d.set_target(norm);
    d.set_source_flags(raw.namespace_event.source_flags);
    d.set_target_flags(raw.namespace_event.target_flags);
    d.set_fstype(hng::sanitize_utf8(raw.namespace_event.fstype,
                                    sizeof(raw.namespace_event.fstype)));
    d.set_mount_flags(raw.namespace_event.mount_flags);
    d.set_syscall_name(syscall_name_str(raw.hdr.name));
}

/**
 * @brief 文件系统调用事件 → file_syscall_semantic_data
 * @details 两条路径均由探针解析为绝对路径，各自收敛为合法 UTF-8 后再经 normalize
 * 消除拼写差异后输出；未解析的路径保留收敛后的串，其状态位一并搬运供呈现层
 * 标记。dirfd/dirfd2、at_flags、openat2 的 resolve、truncate 的长度、mknod 的
 * 设备号、文件句柄与以 fd 为参数的系统调用统一原样透传。memfd 的 path1 带
 * "memfd:" 前缀。
 */
void file_to_semantic(const struct syscall_event& raw,
                      hng::syscall_semantic_data& out)
{
    auto& d = out.data.emplace<hng::file_syscall_semantic_data>();
    std::string norm;
    hng::path::normalize(
        hng::sanitize_utf8(raw.file_event.path1, sizeof(raw.file_event.path1)),
        norm);
    d.set_path1(norm);
    hng::path::normalize(
        hng::sanitize_utf8(raw.file_event.path2, sizeof(raw.file_event.path2)),
        norm);
    d.set_path2(norm);
    d.set_flags(raw.file_event.flags);
    d.set_mode(raw.file_event.mode);
    d.set_path1_flags(raw.file_event.path1_flags);
    d.set_path2_flags(raw.file_event.path2_flags);
    d.set_dirfd(raw.file_event.dirfd);
    d.set_dirfd2(raw.file_event.dirfd2);
    d.set_at_flags(raw.file_event.at_flags);
    d.set_resolve(raw.file_event.resolve);
    d.set_length(raw.file_event.length);
    d.set_dev(raw.file_event.dev);
    d.set_handle(raw.file_event.handle, sizeof(raw.file_event.handle));
    d.set_fd(raw.file_event.fd);
    d.set_syscall_name(syscall_name_str(raw.hdr.name));
}

/**
 * @brief 内存事件 → memory_semantic_data
 * @details 纯搬运：请求地址、长度、PROT_*、MAP_*、文件区段起点、源 fd、匿名与
 * W|X 标志。mmap 的源文件路径由 exit 钩子解析，收敛为合法 UTF-8 后再经 normalize
 * 消除拼写差异后输出，path_flags 一并搬运；匿名映射的 path 为空、path_flags
 * 为 0。
 */
void memory_to_semantic(const struct syscall_event& raw,
                        hng::syscall_semantic_data& out)
{
    auto& d = out.data.emplace<hng::memory_semantic_data>();
    d.set_prot(raw.memory_event.prot);
    d.set_flags(raw.memory_event.flags);
    d.set_addr(raw.memory_event.addr);
    d.set_length(raw.memory_event.length);
    d.set_offset(raw.memory_event.offset);
    d.set_fd(raw.memory_event.fd);
    d.set_anonymous(raw.memory_event.anonymous != 0);
    d.set_wx(raw.memory_event.wx != 0);
    std::string norm;
    hng::path::normalize(
        hng::sanitize_utf8(raw.memory_event.path, sizeof(raw.memory_event.path)),
        norm);
    d.set_path(norm);
    d.set_path_flags(raw.memory_event.path_flags);
    d.set_syscall_name(syscall_name_str(raw.hdr.name));
}

/**
 * @brief 网络事件 → network_syscall_semantic_data
 * @details 纯搬运：地址族 / 套接字类型 / 协议号、目标与来源 IP/端口、本地端口、
 * 套接字 fd、收发字节数、listen 的 backlog 与 AF_UNIX 的 sun_path（收敛为合法
 * UTF-8 后搬运）。dst_ip 与 src_ip 固定输出 4 个网络字节序的字，未采集时为 0。
 */
void network_to_semantic(const struct syscall_event& raw,
                         hng::syscall_semantic_data& out)
{
    auto& d = out.data.emplace<hng::network_syscall_semantic_data>();
    d.set_family(raw.network_event.family);
    d.set_type(raw.network_event.type);
    d.set_protocol(raw.network_event.protocol);
    for (int i = 0; i < 4; ++i) {
        d.add_dst_ip(raw.network_event.dst_ip[i]);
        d.add_src_ip(raw.network_event.src_ip[i]);
    }
    d.set_dst_port(raw.network_event.dst_port);
    d.set_src_port(raw.network_event.src_port);
    d.set_sockfd(raw.network_event.sockfd);
    d.set_count(raw.network_event.count);
    d.set_backlog(raw.network_event.backlog);
    d.set_flags(raw.network_event.flags);
    d.set_unix_path(hng::sanitize_utf8(raw.network_event.unix_path,
                                       sizeof(raw.network_event.unix_path)));
    d.set_syscall_name(syscall_name_str(raw.hdr.name));
}

/**
 * @brief 内核操作事件 → kernel_semantic_data
 * @details 纯搬运（字符串字段收敛为合法 UTF-8 后搬运）：ptrace 的请求类型、目标
 * pid 与数据参数；bpf 的命令、前 16 字节属性与按命令解出的类型。bpf_attr 固定
 * 输出 4 个小端 u32，未采集时为 0。
 */
void kernel_to_semantic(const struct syscall_event& raw,
                        hng::syscall_semantic_data& out)
{
    auto& d = out.data.emplace<hng::kernel_semantic_data>();
    d.set_command(raw.kernel_event.command);
    d.set_target_pid(raw.kernel_event.target_pid);
    d.set_arg(raw.kernel_event.arg);
    for (int i = 0; i < 4; ++i) {
        d.add_bpf_attr(raw.kernel_event.bpf_attr[i]);
    }
    d.set_bpf_type(raw.kernel_event.bpf_type);
    d.set_module_name(hng::sanitize_utf8(raw.kernel_event.module_name,
                                         sizeof(raw.kernel_event.module_name)));
    d.set_module_len(raw.kernel_event.module_len);
    d.set_kexec_entry(raw.kernel_event.kexec_entry);
    d.set_kexec_segments(raw.kernel_event.kexec_segments);
    d.set_reboot_cmd(raw.kernel_event.reboot_cmd);
    d.set_hostname(hng::sanitize_utf8(raw.kernel_event.hostname,
                                      sizeof(raw.kernel_event.hostname)));
    d.set_syscall_name(syscall_name_str(raw.hdr.name));
}

/**
 * @brief 信号发送事件 → signal_semantic_data
 * @details 纯搬运：信号号、目标 pid/tid 与 rt_sigqueueinfo 的 si_code。
 */
void signal_to_semantic(const struct syscall_event& raw,
                        hng::syscall_semantic_data& out)
{
    auto& d = out.data.emplace<hng::signal_semantic_data>();
    d.set_sig(raw.signal_event.sig);
    d.set_target_pid(raw.signal_event.target_pid);
    d.set_target_tid(raw.signal_event.target_tid);
    d.set_si_code(raw.signal_event.si_code);
    d.set_syscall_name(syscall_name_str(raw.hdr.name));
}

}  // namespace

/**
 * @brief 原始事件 → 语义事件纯转换
 * @details 输入事件头（进程身份、凭据、挂载命名空间）原样拷贝，进程名 comm 收敛为
 * 合法 UTF-8 后写入语义事件头部；载荷按 hdr.subtype 分派到对应 helper。
 * hdr.subtype 由内核侧 init_syscall_event_head 归类，此处不做重新推断。
 */
void Semantic_syscall::transform_one(const struct syscall_event& raw,
                                     hng::syscall_semantic_data& out) const
{
    out.head.pid             = raw.hdr.head.pid;
    out.head.pid_start_time  = raw.hdr.head.pid_start_time;
    out.head.ppid            = raw.hdr.head.ppid;
    out.head.ppid_start_time = raw.hdr.head.ppid_start_time;

    out.head.uid             = raw.hdr.head.uid;
    out.head.euid            = raw.hdr.head.euid;
    out.head.mnt_ns          = raw.hdr.head.mnt_ns;
    out.head.ret             = raw.hdr.head.ret;
    out.head.comm =
        hng::sanitize_utf8(raw.hdr.head.comm, sizeof(raw.hdr.head.comm));

    // head.type 为顶层事件流类别（hng::EventType，scoped 枚举），与
    // raw.hdr.subtype （syscall_event_type 的九类细分）不同义；本流恒为 syscall
    // 语义流，故固定。
    out.head.type    = hng::EventType::SYSCALL_EVENT;
    // 语义子类型由内核头原样携带，不再由载荷 variant 下标反推
    out.head.subtype = raw.hdr.subtype;

    switch (raw.hdr.subtype) {
        case UNKNOWN_EVENT:
            break;
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
        case SIGNAL_EVENT:
            signal_to_semantic(raw, out);
            break;
    }
}

namespace hng {

bool has_unresolved_path(const struct syscall_event& raw)
{
    return raw.hdr.subtype == FILE_EVENT &&
           ((raw.file_event.path1_flags | raw.file_event.path2_flags) &
            PATH_UNRESOLVED) != 0;
}

}  // namespace hng
