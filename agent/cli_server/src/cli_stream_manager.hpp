/**
 * @file cli_stream_manager.hpp
 * @brief 定义 CLIStreamManager，订阅流表、并发配额与停机广播
 * @author red-shinku
 * @date 2026.10.16
 */

#ifndef HNG_CLI_STREAM_MANAGER_HPP
#define HNG_CLI_STREAM_MANAGER_HPP

#include <atomic>
#include <cstddef>
#include <mutex>
#include <optional>
#include <vector>

class CLIStream;

/**
 * @brief 订阅流管理器。用于对 CLIStream
 * 本身的管理，包括：并发配额（申请、登记、摘除）、停机时对流的广播。
 * 流向运行时引擎的订阅操作由流自己负责。
 * @note 流的析构必须先 detach（在 teardown() 内），故 shutdown() 持锁期间取到的
 * 指针必然有效——正在析构的流阻塞在 detach 的锁上。
 */
class CLIStreamManager final {
   public:
    /// @brief 并发流配额的 RAII 槽位：持有即占一个名额，析构即释放
    class StreamSlot final {
       public:
        StreamSlot(StreamSlot&& other) noexcept;
        StreamSlot& operator=(StreamSlot&& other) noexcept;
        ~StreamSlot();

        StreamSlot(const StreamSlot&)            = delete;
        StreamSlot& operator=(const StreamSlot&) = delete;

       private:
        friend class CLIStreamManager;

        explicit StreamSlot(CLIStreamManager& owner) : owner_(&owner) {}

        CLIStreamManager* owner_ = nullptr;
    };

    /// @param max_streams 同时活跃的订阅流条数上限
    explicit CLIStreamManager(std::size_t max_streams);
    ~CLIStreamManager();

    /// @brief 申请消费任务，成功后占一个配额
    /// @return 已满时为空，调用方应回 RESOURCE_EXHAUSTED
    std::optional<StreamSlot> acquire();

    /// @brief 登记一条流；流对象由调用方拥有
    /// @note 任意线程调用
    void attach(CLIStream* stream);

    /// @brief 摘除一条流；须在流对象析构之前调用
    void detach(CLIStream* stream);

    /// @brief 停机：置关闭标志，并唤醒表内每一条流
    /// @note 只置标志与唤醒，不等待；各流的收敛由自己的消费循环完成
    void shutdown();

    bool shutting_down() const;

    /// @brief 当前占用的配额槽数
    std::size_t active_streams() const;

   private:
    /// @brief 释放一个配额槽；只由 StreamSlot 的析构调用
    void release_slot();

    /// 流表 streams_ 的锁。表只在建流 / 拆流 / 停机时变更，故用互斥量
    std::mutex mu_;
    std::vector<CLIStream*> streams_;

    const std::size_t max_streams_;
    std::atomic<std::size_t> active_{0};
    std::atomic<bool> shutting_down_{false};
};

#endif  // HNG_CLI_STREAM_MANAGER_HPP
