/**
 * @file syscall_probe_loader.hpp
 * @brief 系统调用采集骨架的 BPF 程序加载器。
 * @details 公共头不暴露骨架或 libbpf 类型；map fd 由 loader
 *          持有。
 */

#ifndef HNG_BPF_LOADER_INCLUDE_SYSCALL_PROBE_LOADER_HPP_
#define HNG_BPF_LOADER_INCLUDE_SYSCALL_PROBE_LOADER_HPP_

#include "agent/bpf_loader/include/bpf_program_loader.hpp"
#include "agent/bpf_loader/include/syscall_probe_maps.hpp"

#include <memory>

namespace hng {

/**
 * @brief syscalls 骨架的加载器。
 * @details 管理骨架、探针链接与采集所需 map；map 视图只在 loader
 *          存活且已 prepare() 后有效。
 */
class SyscallProbeLoader final : public BpfProgramLoader {
   public:
    ~SyscallProbeLoader() override;

    /// @brief 打开、跳过缺失 tracepoint、加载并校验采集 map
    bool prepare() override;
    /// @brief 挂载全部 autoload 程序
    bool attach() override;
    /// @brief 销毁全部程序链接；幂等
    void detach() noexcept override;

    BpfProgramState state() const noexcept override;
    BpfProgramStats stats() const noexcept override;

    /**
     * @brief 采集所需 map 视图的快照
     * @return 值对象；视图只在 loader 存活期间有效
     * @throws std::logic_error prepare() 尚未成功
     */
    SyscallProbeMaps maps() const;

   private:
    struct Impl;
    explicit SyscallProbeLoader(std::unique_ptr<Impl> impl);
    friend class BpfLoaderFactory;

    std::unique_ptr<Impl> impl_;
};

}  // namespace hng

#endif  // HNG_BPF_LOADER_INCLUDE_SYSCALL_PROBE_LOADER_HPP_
