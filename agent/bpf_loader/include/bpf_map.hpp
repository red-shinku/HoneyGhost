/**
 * @file bpf_map.hpp
 * @brief 借用式 BPF map 视图、类型与容量描述。
 * @details 公共头不暴露 libbpf 或 Linux BPF 类型；map fd 由 loader 持有。
 */

#ifndef HNG_BPF_LOADER_INCLUDE_BPF_MAP_HPP_
#define HNG_BPF_LOADER_INCLUDE_BPF_MAP_HPP_

#include <cstdint>

namespace hng {

/// @brief BPF map 的类型、键值大小与容量
struct BpfMapSpec {
    /// BPF_MAP_TYPE_* 数值
    std::uint32_t type        = 0;
    /// 键字节数
    std::uint32_t key_size    = 0;
    /// 值字节数
    std::uint32_t value_size  = 0;
    /// 最大条目数
    std::uint32_t max_entries = 0;

    bool operator==(const BpfMapSpec& other) const noexcept;
    bool operator!=(const BpfMapSpec& other) const noexcept;
};

/**
 * @brief 已打开 BPF map 的借用视图
 * @details 不拥有 fd；仅在 fd 的持有者存活期间有效。
 */
class BpfMapView {
   public:
    /**
     * @brief 通过 BPF_OBJ_GET_INFO_BY_FD 读取 map 信息
     * @param fd 已打开的 BPF map fd
     * @throws std::system_error fd 无效或内核调用失败
     */
    static BpfMapView from_fd(int fd);

    int fd() const noexcept;

    const BpfMapSpec& spec() const noexcept;

   private:
    BpfMapView(int fd, BpfMapSpec spec) noexcept;

    int fd_;
    BpfMapSpec spec_;
};

}  // namespace hng

#endif  // HNG_BPF_LOADER_INCLUDE_BPF_MAP_HPP_
