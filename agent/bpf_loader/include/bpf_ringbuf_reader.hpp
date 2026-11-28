/**
 * @file bpf_ringbuf_reader.hpp
 * @brief BPF ringbuf 的消费接口与事件回调注入。
 * @details 公共头不暴露 libbpf 或 Linux BPF 类型。
 */

#ifndef HNG_BPF_LOADER_INCLUDE_BPF_RINGBUF_READER_HPP_
#define HNG_BPF_LOADER_INCLUDE_BPF_RINGBUF_READER_HPP_

#include "agent/bpf_loader/include/bpf_map.hpp"

#include <cstddef>
#include <memory>

namespace hng {

/**
 * @brief 独占 ringbuf 资源与 fd 副本的消费接口。
 * @details 回调在消费线程同步执行；一个实例只允许一个消费线程。
 */
class RingBufferReader {
   public:
    /**
     * @brief ringbuf 记录回调
     * @param ctx 构造时注入的上下文
     * @param data 记录数据，仅在本次回调期间有效
     * @param size 记录字节数
     * @return 0 继续消费；非 0 终止本轮并作为 consume() 的返回值
     */
    using Handler = int (*)(void* ctx, const void* data,
                            std::size_t size) noexcept;

    /**
     * @brief 校验 map 类型、复制 fd 并创建 ringbuf reader
     * @param ringbuf 类型必须为 BPF_MAP_TYPE_RINGBUF 的借用视图
     * @param handler 记录回调；须在 Reader 存活期间有效
     * @param ctx 传给回调的上下文
     * @return 独占 fd 副本与 ringbuf 资源的 Reader
     * @throws std::system_error ABI 不符、fd 复制或 ringbuf 创建失败
     */
    static std::unique_ptr<RingBufferReader> create(BpfMapView ringbuf,
                                                    Handler handler, void* ctx);

    /// @brief 释放 ringbuf 资源后关闭复制的 fd
    ~RingBufferReader();
    RingBufferReader(RingBufferReader&&) noexcept;
    RingBufferReader& operator=(RingBufferReader&&) noexcept;
    RingBufferReader(const RingBufferReader&)            = delete;
    RingBufferReader& operator=(const RingBufferReader&) = delete;

    /**
     * @brief 从 ringbuf 消费至多 budget 条记录
     * @return 实际消费条数；负值为 ringbuf 错误或回调错误
     */
    int consume(std::size_t budget) noexcept;

    /**
     * @brief 借用 ringbuf 的 epoll fd
     * @return epoll fd；调用方不得关闭
     */
    int epoll_fd() const noexcept;

   private:
    struct Impl;
    explicit RingBufferReader(std::unique_ptr<Impl> impl);

    std::unique_ptr<Impl> impl_;
};

}  // namespace hng

#endif  // HNG_BPF_LOADER_INCLUDE_BPF_RINGBUF_READER_HPP_
