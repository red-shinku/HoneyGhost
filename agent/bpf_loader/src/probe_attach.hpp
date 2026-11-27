/**
 * @file probe_attach.hpp
 * @brief BPF 程序的可选探针挂载设施
 * @note 仅供 agent/bpf_loader/src 内部使用。
 */

#ifndef HNG_BPF_LOADER_PROBE_ATTACH_HPP_
#define HNG_BPF_LOADER_PROBE_ATTACH_HPP_

#include <bpf/libbpf.h>

#include <filesystem>
#include <vector>

namespace hng::detail {

/**
 * @brief 关闭 tracepoint 不存在的程序的 autoload
 * @param obj 已打开、尚未加载的 BPF 对象
 * @param tracefs_root tracefs 根；为空表示无法判定，不关闭任何程序
 * @return 被关闭 autoload 的程序数
 * @note 只处理 section 形如 tracepoint/<group>/<event> 的程序；
 *       必须在 bpf_object__load 之前调用。
 */
int skip_missing_tracepoints(bpf_object* obj,
                             const std::filesystem::path& tracefs_root);

/**
 * @brief 逐个挂载已 autoload 的程序
 * @param obj 已加载的 BPF 对象
 * @param links 输出：成功挂载的链接，由调用方用 bpf_link__destroy 释放
 * @return 挂载失败的程序数
 * @note 单个程序失败不中断后续程序；obj 为空时返回 0。
 * @note 挂载完成后校验每个已挂载的 sys_enter_<x> 是否有已挂载的
 *       sys_exit_<x>，不匹配只记 warn，不影响返回值与统计。
 */
int attach_programs(bpf_object* obj, std::vector<bpf_link*>& links);

}  // namespace hng::detail

#endif  // HNG_BPF_LOADER_PROBE_ATTACH_HPP_
