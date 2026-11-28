/**
 * @file bpf_program_group.hpp
 * @brief 多个 BPF 程序加载器的非拥有聚合与生命周期编排。
 * @details 参数中的 loader 须比本对象活得更久。
 */

#ifndef HNG_BPF_LOADER_INCLUDE_BPF_PROGRAM_GROUP_HPP_
#define HNG_BPF_LOADER_INCLUDE_BPF_PROGRAM_GROUP_HPP_

#include "agent/bpf_loader/include/bpf_program_loader.hpp"

#include <vector>

namespace hng {

/**
 * @brief 按注册顺序编排多个 BPF 程序加载器的准备、挂载与卸载。
 * @details 不拥有 loader；只转发生命周期调用并聚合统计，供装配层统一
 *          驱动。
 */
class BpfProgramGroup {
   public:
    BpfProgramGroup()                                  = default;
    BpfProgramGroup(const BpfProgramGroup&)            = delete;
    BpfProgramGroup& operator=(const BpfProgramGroup&) = delete;

    /**
     * @brief 登记一个加载器
     * @param loader 非拥有的加载器；须比本对象活得更久
     * @note 允许重复登记同一加载器，调用顺序与登记顺序一致。
     */
    void add(BpfProgramLoader& loader);

    /**
     * @brief 按登记顺序 prepare()，首个失败即停止
     * @return 全部成功为 true；首个失败为 false
     */
    bool prepare_all();

    /**
     * @brief 按登记顺序 attach()，任一失败时 detach_all() 并返回 false
     * @return 全部成功为 true；任一失败为 false
     */
    bool attach_all();

    /// @brief 按登记顺序 detach()；可重复调用
    void detach_all() noexcept;

    /// @brief 按登记顺序快照统计
    std::vector<BpfProgramStats> stats() const;

   private:
    std::vector<BpfProgramLoader*> loaders_;
};

}  // namespace hng

#endif  // HNG_BPF_LOADER_INCLUDE_BPF_PROGRAM_GROUP_HPP_
