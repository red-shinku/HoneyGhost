/**
 * @file role_cgroup_reader.hpp
 * @brief cgroup v2 的递归枚举与进程成员补齐
 * @details
 * 按 cgroup 遍历补齐成员，这样不依赖父子链（double-fork
 * 后重新挂到 PID 1 的进程仍在同一 cgroup 内）。
 * 且 cgroup.procs 是内核给的一致性快照，角色 cgroup 一定是独立子树。
 * 这是因为 cgroup v2 的 no internal process 规则迫使 systemd
 * 和容器运行时都会为服务分配独立 cgroup。
 * @author red_shinku
 * @date 2026.9.11
 */

#ifndef HNG_ROLE_CGROUP_READER_HPP_
#define HNG_ROLE_CGROUP_READER_HPP_

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "agent/event_data/include/process.hpp"

namespace hng {
namespace role {

/**
 * @brief cgroup 进程枚举器
 * @details 无状态，全部为静态入口。
 */
class RoleCgroupReader {
   public:
    /// cgroup v2 统一层次的挂载点，进程内只探测一次
    /// @details 各源给出的 cgroup 路径相对本挂载点，须先拼接才可直接打开。
    /// 自 /proc/self/mountinfo 探测，探测不到时取 /sys/fs/cgroup。
    /// @return 不以 '/' 结尾的绝对路径
    static const std::string& root();

    /// 把源给出的相对 cgroup 路径解析成可直接打开的绝对路径
    /// @param cgroup_path 相对挂载点的路径，已是绝对路径时原样返回
    static std::string absolute(const std::string& cgroup_path);

    /// 递归枚举 cgroup 内全部进程
    /// @param cgroup_path 角色的 cgroup 路径
    /// @param proc_root procfs 根目录，默认 /proc
    /// @return 该 cgroup 及其全部子孙 cgroup 内的进程，按 pid 升序
    /// @note 路径不存在、不可读或被删除时返回已收集结果；枚举期间退出的进程被跳过
    static std::vector<hng::Process> read(const std::string& cgroup_path,
                                          const std::string& proc_root = "/proc");

    /// 取 /proc/<pid>/stat 的字段 22（starttime，boottime 对齐的 tick，不做换算）
    /// @param stat_content 文件全文
    /// @return 解析失败（无右括号、字段不足、字段非数字或超出 uint64）时为空
    static std::optional<uint64_t> parse_start_time(
        const std::string& stat_content);

    /// 取进程所属的 cgroup 路径
    /// @param pid 进程号
    /// @param proc_root procfs 根目录，默认 /proc
    /// @return cgroup v2 统一层次那一行的路径（以 '/' 开头，可直接交给
    ///         absolute()
    ///         拼接）；进程不存在、文件读不到或没有统一层次那一行时为空
    /// @note 供只有 pid 的源使用（systemd 源另有 ControlGroup 属性，不必读这里）
    static std::optional<std::string> read_process_cgroup(
        uint32_t pid, const std::string& proc_root = "/proc");
};

}  // namespace role
}  // namespace hng

#endif  // HNG_ROLE_CGROUP_READER_HPP_
