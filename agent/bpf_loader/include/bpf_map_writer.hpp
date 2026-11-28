/**
 * @file bpf_map_writer.hpp
 * @brief 只使用 bpf syscall 的 BPF map 写入接口。
 * @details 公共头不暴露 libbpf 或 Linux BPF 类型；Writer 在创建时复制 fd
 *          并设置 CLOEXEC。
 */

#ifndef HNG_BPF_LOADER_INCLUDE_BPF_MAP_WRITER_HPP_
#define HNG_BPF_LOADER_INCLUDE_BPF_MAP_WRITER_HPP_

#include "agent/bpf_loader/include/bpf_map.hpp"

#include <memory>
#include <system_error>

namespace hng {

/**
 * @brief 独占 BPF map fd 副本的写入接口
 * @details 只使用 bpf syscall；update 与 erase 单条操作返回真实 errno。
 */
class BpfMapWriter {
   public:
    struct Options {
        /// 为 true 时要求 map 为空，否则创建失败
        bool require_empty = false;
    };

    /**
     * @brief 复制 fd、校验 ABI 与可选空表前提
     * @param view 借用的 map 视图
     * @param expected 调用方期望的 map ABI
     * @param options 创建选项
     * @return 独占 fd 副本的 Writer
     * @throws std::system_error fd 复制失败、ABI 不符、表非空或内核调用失败
     */
    static std::unique_ptr<BpfMapWriter> create(BpfMapView view,
                                                BpfMapSpec expected,
                                                Options options = {false});

    ~BpfMapWriter();
    BpfMapWriter(BpfMapWriter&&) noexcept;
    BpfMapWriter& operator=(BpfMapWriter&&) noexcept;
    BpfMapWriter(const BpfMapWriter&)            = delete;
    BpfMapWriter& operator=(const BpfMapWriter&) = delete;

    /**
     * @brief 以 BPF_ANY 写入或覆盖一个条目
     * @return 成功时为空错误码；失败时为真实 errno
     */
    std::error_code update(const void* key, const void* value) noexcept;

    /**
     * @brief 删除一个条目
     * @return 成功时为空错误码；失败时为真实 errno，含 ENOENT
     */
    std::error_code erase(const void* key) noexcept;

   private:
    struct Impl;
    explicit BpfMapWriter(std::unique_ptr<Impl> impl);

    std::unique_ptr<Impl> impl_;
};

}  // namespace hng

#endif  // HNG_BPF_LOADER_INCLUDE_BPF_MAP_WRITER_HPP_
