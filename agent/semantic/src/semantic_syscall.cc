/**
 * @file semantic_syscall.cc
 * @brief 系统调用事件语义化工具实现
 * @details
 * 按 hdr.subtype 将 union 中八种事件分别转换为对应的 proto 语义载荷，组装为
 * syscall_semantic_data。本工具不持有队列与线程状态。
 *
 * 语义化原则：去除随机性信息。除 exec 的 filename（复用 agent/semantic/path/
 * 规则引擎语义化）、file 的 path（normalize 消除拼写差异）与 credential 的
 * union→oneof 归位外，其余事件为纯字段搬运——进程身份头部原样拷贝，syscall 名
 * 由 hdr.name 枚举映射为字符串。
 *
 * @author red_shinku
 * @date 2026.08.17
 */

#include "agent/semantic/src/semantic.hpp"
#include "agent/semantic/src/path/path_normalizer.hpp"
#include "agent/semantic/src/path/path_rule.hpp"

#include <string>

namespace {

/**
 * @brief 判断从 pos 起是否为一段合法 UTF-8，返回其长度
 * @param text 待检查的字节串
 * @param pos 起始位置
 * @return 合法序列的字节数（1..4）；非法或越界返回 0
 * @details 排除 overlong 编码、代理区编码与超出 U+10FFFF 的取值，
 *          与 protobuf 对 string 字段的 UTF-8 要求一致。
 */
size_t utf8_sequence_length(std::string_view text, size_t pos)
{
    const unsigned char lead = static_cast<unsigned char>(text[pos]);
    if (lead < 0x80) {
        return 1;
    }
    size_t length      = 0;
    unsigned char low  = 0x80;
    unsigned char high = 0xBF;
    if (lead >= 0xC2 && lead <= 0xDF) {
        length = 2;
    }
    else if (lead >= 0xE0 && lead <= 0xEF) {
        length = 3;
        if (lead == 0xE0) {
            low = 0xA0;  // overlong
        }
        if (lead == 0xED) {
            high = 0x9F;  // 代理区
        }
    }
    else if (lead >= 0xF0 && lead <= 0xF4) {
        length = 4;
        if (lead == 0xF0) {
            low = 0x90;
        }
        if (lead == 0xF4) {
            high = 0x8F;
        }
    }
    else {
        return 0;
    }
    if (pos + length > text.size()) {
        return 0;
    }
    const unsigned char second = static_cast<unsigned char>(text[pos + 1]);
    if (second < low || second > high) {
        return 0;
    }
    for (size_t i = 2; i < length; ++i) {
        const unsigned char next = static_cast<unsigned char>(text[pos + i]);
        if (next < 0x80 || next > 0xBF) {
            return 0;
        }
    }
    return length;
}

/**
 * @brief 把内核的进程名缓冲转成合法 UTF-8
 * @param raw 定长缓冲
 * @param size 缓冲容量
 * @return 截到首个 NUL 的副本；非法 UTF-8 序列的每个字节替换为 '?'
 * @note 内核 comm 允许任意非 NUL 字节，直接放进 proto 的 string 会让
 *       客户端解析失败，故在此收敛为合法 UTF-8。
 */
std::string sanitize_comm(const char* raw, size_t size)
{
    const std::string_view text(raw, size);
    const std::string_view trimmed = text.substr(0, text.find('\0'));
    std::string out;
    out.reserve(trimmed.size());
    size_t pos = 0;
    while (pos < trimmed.size()) {
        const size_t length = utf8_sequence_length(trimmed, pos);
        if (length == 0) {
            out += '?';
            ++pos;
            continue;
        }
        out.append(trimmed.substr(pos, length));
        pos += length;
    }
    return out;
}

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
        case SYSCALL_EVENT_SENDTO:
            return "sendto";
        case SYSCALL_EVENT_SENDMSG:
            return "sendmsg";
        case SYSCALL_EVENT_EXIT_GROUP:
            return "exit_group";
        default:
            return "unknown";
    }
}

// 以下八个 helper 对应 hdr.subtype 的八种事件，各构造一种 proto 载荷填入
// variant。 语义化原则：去除随机性；除 exec/credential 外均为纯字段搬运。

/**
 * @brief 进程生命周期事件 → process_semantic_data
 * @details 纯搬运 exit_code（进程退出事件有效）。进程诞生事件无载荷字段，新进程
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
 * @details 路径经 hng::path::normalize 消除拼写差异后作为原始路径输出，尚不做
 * 绝对化（相对路径保持原样）；flags/mode 原样搬运。
 */
void file_to_semantic(const struct syscall_event& raw,
                      hng::syscall_semantic_data& out)
{
    auto& d = out.data.emplace<hng::file_syscall_semantic_data>();
    std::string norm;
    hng::path::normalize(raw.file_event.path, norm);
    d.set_path(norm);
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
 * @details 纯搬运：地址族 / 套接字类型 / 协议号，以及目标 IP、目标端口与本地
 * 端口。dst_ip 固定输出 4 个网络字节序的字，未采集时为 0。
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
    }
    d.set_dst_port(raw.network_event.dst_port);
    d.set_src_port(raw.network_event.src_port);
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

/**
 * @brief 原始事件 → 语义事件纯转换
 * @details 输入事件头（进程身份、凭据、挂载命名空间与进程名）原样拷贝为语义
 * 事件头部；载荷按 hdr.subtype 分派到对应 helper。hdr.subtype 由内核侧
 * init_syscall_event_head 归类，此处不做重新推断。
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
    out.head.comm = sanitize_comm(raw.hdr.head.comm, sizeof(raw.hdr.head.comm));

    // head.type 为顶层事件流类别（hng::EventType，scoped 枚举），与
    // raw.hdr.subtype （syscall_event_type 的八类细分）不同义；本流恒为 syscall
    // 语义流，故固定。
    out.head.type = hng::EventType::SYSCALL_EVENT;
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
    }
}
