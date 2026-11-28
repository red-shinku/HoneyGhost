/**
 * @file bpf_loader_factory.hpp
 * @brief BPF 程序加载器的唯一构造入口。
 */

#ifndef HNG_BPF_LOADER_INCLUDE_BPF_LOADER_FACTORY_HPP_
#define HNG_BPF_LOADER_INCLUDE_BPF_LOADER_FACTORY_HPP_

#include "agent/bpf_loader/include/syscall_probe_loader.hpp"

#include <filesystem>
#include <memory>

namespace hng {

/// @brief BPF 程序加载器工厂
class BpfLoaderFactory {
   public:
    /**
     * @brief 构造系统调用采集骨架的加载器
     * @param tracefs_root tracefs 根；为空时在 prepare() 中自动解析
     * @return 尚未准备的 loader
     */
    static std::unique_ptr<SyscallProbeLoader> create_syscall_probe(
        std::filesystem::path tracefs_root = {});

    BpfLoaderFactory() = delete;
};

}  // namespace hng

#endif  // HNG_BPF_LOADER_INCLUDE_BPF_LOADER_FACTORY_HPP_
