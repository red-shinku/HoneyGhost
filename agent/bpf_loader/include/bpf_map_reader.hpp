/**
 * @file bpf_map_reader.hpp
 * @brief BPF map 的只读查询与 per-CPU 计数求和接口。
 * @details 公共头不暴露 libbpf 或 Linux BPF 类型；Reader 在创建时复制 fd
 *          并设置 CLOEXEC。
 */

#ifndef HNG_BPF_LOADER_INCLUDE_BPF_MAP_READER_HPP_
#define HNG_BPF_LOADER_INCLUDE_BPF_MAP_READER_HPP_

#include "agent/bpf_loader/include/bpf_map.hpp"

#include <cstdint>
#include <memory>
#include <system_error>

namespace hng {

/**
 * @brief 独占 BPF map fd 副本的只读接口
 * @details lookup 使用 libbpf bpf_map_lookup_elem；per-CPU 求和同时使用
 *          libbpf_num_possible_cpus。只读调用可跨线程并发。
 */
class BpfMapReader {
   public:
    /**
     * @brief 复制 fd 并校验 map ABI
     * @param view 借用的 map 视图
     * @param expected 调用方期望的 map ABI
     * @return 独占 fd 副本的 Reader
     * @throws std::system_error fd 复制失败或 ABI 不符
     */
    static std::unique_ptr<BpfMapReader> create(BpfMapView view,
                                                BpfMapSpec expected);

    ~BpfMapReader();
    BpfMapReader(BpfMapReader&&) noexcept;
    BpfMapReader& operator=(BpfMapReader&&) noexcept;
    BpfMapReader(const BpfMapReader&)            = delete;
    BpfMapReader& operator=(const BpfMapReader&) = delete;

    /**
     * @brief 查询一个键对应的值
     * @param key 键指针
     * @param value 输出缓冲区，大小不小于 map 的 value_size
     * @return 成功时为空错误码；失败时为真实 errno
     */
    std::error_code lookup(const void* key, void* value) const noexcept;

    /**
     * @brief 对一个 per-CPU map 的键求和全部 CPU 上的 uint64_t 值
     * @param key 键指针
     * @param total 输出：全部 CPU 的和；失败时保持不变
     * @return 成功时为空错误码；非 per-CPU map、ABI 不符或内核调用失败时
     *         返回错误码
     * @note 仅支持 value_size 为 sizeof(uint64_t) 的 PERCPU_ARRAY、
     *       PERCPU_HASH 与 LRU_PERCPU_HASH
     */
    std::error_code sum_percpu_u64(const void* key,
                                   std::uint64_t& total) const noexcept;

   private:
    struct Impl;
    explicit BpfMapReader(std::unique_ptr<Impl> impl);

    std::unique_ptr<Impl> impl_;
};

}  // namespace hng

#endif  // HNG_BPF_LOADER_INCLUDE_BPF_MAP_READER_HPP_
