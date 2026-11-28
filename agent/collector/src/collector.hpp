/**
 * @file collector.hpp
 * @brief 原始事件采集线接口与单线程采集聚合。
 */
#ifndef COLLECTOR_HPP
#define COLLECTOR_HPP

#include "agent/bpf_loader/include/syscall_probe_maps.hpp"
#include "agent/util/include/component.hpp"
#include "agent/util/include/event_channel.hpp"
#include "agent/util/include/pipeline_stats.hpp"
#include "kernel/include/syscall_event_type.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

// BPF 资源与释放方式均为实现细节，定义只存在于 src/。
namespace hng::detail {
struct SyscallCollectorState;

/**
 * @brief 该 subtype 的 ringbuf 记录精确长度：事件头 + 定长载荷。
 * @param subtype 内核事件头里的 syscall 子类型。
 * @return 记录字节数；未知 subtype 返回 0。
 * @note 这是内核预留长度与采集器解析长度的唯一映射，两侧都取内核头的
 *       sizeof，故不会各自漂移。
 */
constexpr std::size_t SyscallRecordSize(enum syscall_event_type subtype) noexcept
{
    switch (subtype) {
        case PROCESS_EVENT:
            return sizeof(struct syscall_event_head) +
                   sizeof(struct process_event);
        case EXEC_EVENT:
            return sizeof(struct syscall_event_head) + sizeof(struct exec_event);
        case CREDENTIAL_EVENT:
            return sizeof(struct syscall_event_head) +
                   sizeof(struct credential_event);
        case NAMESPACE_EVENT:
            return sizeof(struct syscall_event_head) +
                   sizeof(struct namespace_event);
        case FILE_EVENT:
            return sizeof(struct syscall_event_head) + sizeof(struct file_event);
        case MEMORY_EVENT:
            return sizeof(struct syscall_event_head) +
                   sizeof(struct memory_event);
        case NETWORK_EVENT:
            return sizeof(struct syscall_event_head) +
                   sizeof(struct network_event);
        case KERNEL_EVENT:
            return sizeof(struct syscall_event_head) +
                   sizeof(struct kernel_event);
        case SIGNAL_EVENT:
            return sizeof(struct syscall_event_head) +
                   sizeof(struct signal_event);
        case UNKNOWN_EVENT:
            break;
    }
    return 0;
}

// ringbuf 记录格式与通道元素尺寸是跨内核/用户态的 ABI，锁定在编译期。
static_assert(sizeof(struct syscall_event_head) == 80,
              "ringbuf 记录头尺寸变化会破坏按 subtype 解析的载荷偏移");
static_assert(sizeof(struct process_event) == 304,
              "PROCESS 载荷变化会改变 ringbuf 的 PROCESS 记录长度");
static_assert(sizeof(struct exec_event) == 904,
              "EXEC 载荷变化会改变 ringbuf 的 EXEC 记录长度");
static_assert(sizeof(struct credential_event) == 72,
              "CREDENTIAL 载荷变化会改变 ringbuf 的 CREDENTIAL 记录长度");
static_assert(sizeof(struct namespace_event) == 576,
              "NAMESPACE 载荷变化会改变 ringbuf 的 NAMESPACE 记录长度");
static_assert(sizeof(struct file_event) == 584,
              "FILE 载荷变化会改变 ringbuf 的 FILE 记录长度");
static_assert(sizeof(struct memory_event) == 312,
              "MEMORY 载荷变化会改变 ringbuf 的 MEMORY 记录长度");
static_assert(sizeof(struct network_event) == 184,
              "NETWORK 载荷变化会改变 ringbuf 的 NETWORK 记录长度");
static_assert(sizeof(struct kernel_event) == 184,
              "KERNEL 载荷变化会改变 ringbuf 的 KERNEL 记录长度");
static_assert(sizeof(struct signal_event) == 16,
              "SIGNAL 载荷变化会改变 ringbuf 的 SIGNAL 记录长度");
static_assert(sizeof(syscall_event) == 984,
              "用户态通道元素保持为 union 最大者的定长");
static_assert(offsetof(syscall_event, process_event) ==
              sizeof(struct syscall_event_head));
static_assert(offsetof(syscall_event, exec_event) ==
              sizeof(struct syscall_event_head));
static_assert(offsetof(syscall_event, credential_event) ==
              sizeof(struct syscall_event_head));
static_assert(offsetof(syscall_event, namespace_event) ==
              sizeof(struct syscall_event_head));
static_assert(offsetof(syscall_event, file_event) ==
              sizeof(struct syscall_event_head));
static_assert(offsetof(syscall_event, memory_event) ==
              sizeof(struct syscall_event_head));
static_assert(offsetof(syscall_event, network_event) ==
              sizeof(struct syscall_event_head));
static_assert(offsetof(syscall_event, kernel_event) ==
              sizeof(struct syscall_event_head));
static_assert(offsetof(syscall_event, signal_event) ==
              sizeof(struct syscall_event_head));
}  // namespace hng::detail

/**
 * @brief 单条事件线的采集接口。
 * @note 不持线程。prepare、consume 与析构须由同一调用方串行；单个实例仅
 *       允许一个消费线程。回调绑定对象地址，故禁止复制或移动。
 */
class CollectorType {
   public:
    CollectorType()                                = default;
    virtual ~CollectorType()                       = default;

    CollectorType(const CollectorType&)            = delete;
    CollectorType& operator=(const CollectorType&) = delete;
    CollectorType(CollectorType&&)                 = delete;
    CollectorType& operator=(CollectorType&&)      = delete;

    /**
     * @brief 用构造时注入的 map 视图创建 reader。
     * @return 成功为 true；已准备或资源创建失败为 false
     * @note 不管理 BPF 程序生命周期；失败时不保留采集线已获取的资源。
     */
    virtual bool prepare()                         = 0;
    /**
     * @brief 把 ringbuf 中就绪的记录搬到输出通道。
     * @param budget 本次最多消费的记录数；实现可忽略该上限
     * @return 搬到输出通道的记录数；负值为 ringbuf 错误
     * @note 未 prepare() 时返回 0，不访问 ringbuf；通道满时记录被丢弃，
     *       计数在通道内。
     */
    virtual int consume(std::size_t budget)        = 0;
    /**
     * @brief 借用 ringbuf 的 epoll fd；prepare() 前或失败后返回 -1。
     * @note 调用方不得关闭 fd；fd 的生命周期由采集线持有。
     */
    virtual int epoll_fd() const noexcept          = 0;
    /// @brief 线名，用于统计标签；返回静态字符串
    virtual const char* name() const noexcept      = 0;

    /// @brief 本线的累计计数快照；可从任意线程调用
    virtual hng::CollectorLineStats stats() const  = 0;

    /// @brief 标记本线已退回超时轮询
    void mark_polling() noexcept
    {
        polling_.store(true, std::memory_order_relaxed);
    }

    /// @brief 本线是否已退回超时轮询
    bool polling() const noexcept
    {
        return polling_.load(std::memory_order_relaxed);
    }

    /// @brief 记录探针挂载状态，供统计读取
    void mark_attached(bool value) noexcept
    {
        attached_.store(value, std::memory_order_relaxed);
    }

    /// @brief 探针当前是否已挂载
    bool attached() const noexcept
    {
        return attached_.load(std::memory_order_relaxed);
    }

    /// @brief 累计从 ringbuf 搬出的记录数
    void mark_consumed(std::uint64_t count = 1) noexcept
    {
        consumed_.fetch_add(count, std::memory_order_relaxed);
    }

    /// @brief 已搬出的记录数
    std::uint64_t consumed() const noexcept
    {
        return consumed_.load(std::memory_order_relaxed);
    }

    /// @brief 累计 ring_buffer 消费错误
    void mark_consume_error() noexcept
    {
        consume_errors_.fetch_add(1, std::memory_order_relaxed);
    }

    /// @brief 消费错误次数
    std::uint64_t consume_errors() const noexcept
    {
        return consume_errors_.load(std::memory_order_relaxed);
    }

    /// @brief 累计因记录头或长度非法而丢弃的记录数
    void mark_malformed(std::uint64_t count = 1) noexcept
    {
        malformed_.fetch_add(count, std::memory_order_relaxed);
    }

    /// @brief 非法记录数
    std::uint64_t malformed() const noexcept
    {
        return malformed_.load(std::memory_order_relaxed);
    }

   protected:
    std::atomic<bool> polling_{false};
    std::atomic<bool> attached_{false};
    std::atomic<std::uint64_t> consumed_{0};
    std::atomic<std::uint64_t> consume_errors_{0};
    std::atomic<std::uint64_t> malformed_{0};
};

/**
 * @brief 采集聚合：单线程消费多条事件线并写入各自原始事件通道。
 * @details 线程由装配层创建；本类不持 std::thread。run() 用 epoll 等待各线
 *          ringbuf 的 eventfd，stop() 用 eventfd 唤醒。
 * @note 生命周期为 CONSTRUCTED → READY → RUNNING → STOPPED。所有线须由装配层
 *       构造并移交所有权；通道写端须比聚合对象活得更久。run() 返回前不得析构。
 * @see hng::Component
 */
class Collector final : public hng::Component {
   public:
    /**
     * @brief 接管各事件线并创建停机唤醒 fd。
     * @param lines 各线采集器；可为空
     * @note 空指针元素被忽略；所有权转移给本对象。
     */
    explicit Collector(std::vector<std::unique_ptr<CollectorType>> lines);
    ~Collector() override;

    Collector(const Collector&)            = delete;
    Collector& operator=(const Collector&) = delete;
    Collector(Collector&&)                 = delete;
    Collector& operator=(Collector&&)      = delete;

    /**
     * @brief 逐线 prepare()。
     * @return 全部成功为 true；任一失败为 false
     * @note 失败时已准备的线保留资源，由析构回收；只可在 CONSTRUCTED 调用。
     */
    bool prepare();
    /**
     * @brief 标记探针已挂载并转入 READY。
     * @return 成功为 true；状态不是 CONSTRUCTED 时为 false
     * @note 成功后逐线记录挂载状态，供统计读取。
     */
    bool mark_ready();
    /// @brief 各线累计计数快照；可从任意线程调用
    std::vector<hng::CollectorLineStats> stats() const;

    /**
     * @brief 聚合线程入口：epoll 等待各线 ringbuf，逐线 consume。
     * @pre state() 为 READY；否则立即返回且不改变状态
     * @note 退出前逐线记未挂载并排空 ringbuf；不创建线程，不摘探针。
     */
    void run() override;
    /**
     * @brief 置停止标志并唤醒 epoll；幂等，可从任意线程调用。
     * @note 未进入 RUNNING 时直接置 STOPPED。
     */
    void stop() override;
    /**
     * @brief 当前生命周期状态。
     * @note 可从任意线程读取。
     */
    hng::ComponentState state() const override;

   private:
    std::vector<std::unique_ptr<CollectorType>> lines_;
    std::atomic<hng::ComponentState> lifecycle_{hng::ComponentState::CONSTRUCTED};
    std::atomic<bool> stopped_{false};
    int stop_event_fd_ = -1;  ///< eventfd，stop() 写、run() 的 epoll 等待
};

/** @brief 系统调用事件采集线；借用的通道写端必须比采集器活得更久。 */
class SyscallEventCollector : public CollectorType {
   public:
    /**
     * @brief 绑定输出通道与系统调用 map 视图
     * @param sink 输出通道写端
     * @param maps 由装配层提供的 map 视图快照
     * @note 不管理 BPF 程序生命周期；视图只在对应 loader 存活期间有效。
     */
    explicit SyscallEventCollector(hng::EventChannelWriter<syscall_event>& sink,
                                   hng::SyscallProbeMaps maps);
    ~SyscallEventCollector() override;

    bool prepare() override;
    int consume(std::size_t budget) override;
    int epoll_fd() const noexcept override;
    const char* name() const noexcept override;
    hng::CollectorLineStats stats() const override;

   private:
    hng::EventChannelWriter<syscall_event>& syscall_sink;
    hng::SyscallProbeMaps maps_;
    std::unique_ptr<hng::detail::SyscallCollectorState> state_;
    static int handle_rb_event(void* ctx, const void* data,
                               std::size_t data_sz) noexcept;
};

#endif  // COLLECTOR_HPP
