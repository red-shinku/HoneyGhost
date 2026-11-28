/**
 * @file bpf_program_loader.hpp
 * @brief BPF 程序对象的生命周期接口与统计。
 * @details 公共头不暴露 libbpf、骨架或 Linux BPF 类型。
 */

#ifndef HNG_BPF_LOADER_INCLUDE_BPF_PROGRAM_LOADER_HPP_
#define HNG_BPF_LOADER_INCLUDE_BPF_PROGRAM_LOADER_HPP_

#include <cstdint>

namespace hng {

/// @brief BPF 程序对象的生命周期状态
enum class BpfProgramState { UNPREPARED, PREPARED, ATTACHED };

/// @brief BPF 程序对象的累计统计快照
struct BpfProgramStats {
    /// 骨架中的全部程序数，含已关闭 autoload 的程序
    std::uint64_t total_programs    = 0;
    /// 当前已挂载的程序数
    std::uint64_t attached_programs = 0;
    /// 因 tracepoint 缺失而关闭 autoload 的程序数
    std::uint64_t skipped_probes    = 0;
    /// 挂载失败的程序数，跨重试累计
    std::uint64_t attach_failed     = 0;
};

/**
 * @brief 一个 BPF object 的加载、挂载与卸载接口。
 * @details 不持线程、不消费事件；只管理 BPF 对象、程序链接与 map
 *          生命周期。
 */
class BpfProgramLoader {
   public:
    virtual ~BpfProgramLoader()                    = default;

    /**
     * @brief 打开、按 tracefs 跳过缺失探针、加载并校验对象。
     * @return 成功为 true；已准备、加载或校验失败为 false
     * @note 只允许调用一次；失败时不保留已获取资源。
     */
    virtual bool prepare()                         = 0;

    /**
     * @brief 挂载全部 autoload 程序。
     * @return 至少挂载一个程序，或没有需要挂载的程序时为 true；
     *         全部失败为 false
     * @note 单个程序失败只累加统计；失败后可重试。
     */
    virtual bool attach()                          = 0;

    /// @brief 卸载全部程序链接；幂等
    virtual void detach() noexcept                 = 0;

    /// @brief 当前生命周期状态
    virtual BpfProgramState state() const noexcept = 0;

    /// @brief 累计统计快照；可从任意线程读取
    virtual BpfProgramStats stats() const noexcept = 0;
};

}  // namespace hng

#endif  // HNG_BPF_LOADER_INCLUDE_BPF_PROGRAM_LOADER_HPP_
