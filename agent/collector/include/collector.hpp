/**
 * @file collector.hpp
 * @brief 原始事件采集线接口与单线程采集聚合。
 */
#ifndef COLLECTOR_HPP
#define COLLECTOR_HPP

#include "agent/util/include/component.hpp"
#include "agent/util/include/spsc_queue.hpp"
#include "kernel/include/files_type.h"
#include "kernel/include/networks_type.h"
#include "kernel/include/syscalls_type.h"

#include <atomic>
#include <cstddef>
#include <memory>
#include <vector>

// 生成骨架、libbpf 资源与释放方式均为实现细节，定义只存在于 src/。
namespace hng::detail {
struct FileCollectorState;
struct SyscallCollectorState;
struct NetworkCollectorState;
}  // namespace hng::detail

/**
 * @brief 单条事件线的采集接口。
 * @note 不持线程。prepare、attach、detach、consume 与析构须由同一调用方
 *       串行；单个实例仅允许一个消费线程。回调绑定对象地址，故禁止复制或移动。
 */
class CollectorType {
   public:
    CollectorType()                                 = default;
    virtual ~CollectorType()                        = default;

    CollectorType(const CollectorType&)             = delete;
    CollectorType& operator=(const CollectorType&)  = delete;
    CollectorType(CollectorType&&)                  = delete;
    CollectorType& operator=(CollectorType&&)       = delete;

    /**
     * @brief 加载骨架、创建 ringbuf 并校验过滤 map fd，不挂载探针。
     * @return 成功为 true；已准备或加载、map 校验、ringbuf 创建失败为 false
     * @note 成功后 role_filter_map_fd() 即可返回有效 fd，此时尚无事件产生；
     *       须再调用 attach()。失败时不保留任何已准备资源。
     */
    virtual bool prepare()                          = 0;
    /**
     * @brief 在 prepare() 成功后挂载探针。
     * @return 成功为 true；未准备、已挂载或挂载失败为 false
     * @note 挂载成功后可被 consume() 消费；挂载失败保留已准备资源。
     */
    virtual bool attach()                           = 0;
    /**
     * @brief 加载、创建 ringbuf 并挂载探针，等价于 prepare() 后 attach()。
     * @return 成功为 true；attach() 失败时回收已准备资源并返回 false
     * @note 重复初始化返回 false；已 prepare() 而未 attach() 时返回 false，
     *       且不改变已准备状态。
     */
    virtual bool init()                             = 0;
    /**
     * @brief 摘除探针；此后不再产生新事件。
     * @note 已准备但未挂载时为空操作。ringbuf 仍可继续 consume() 排空。
     */
    virtual void detach()                           = 0;
    /**
     * @brief 把 ringbuf 中就绪的记录搬到输出队列。
     * @param budget 本次最多消费的记录数；实现可忽略该上限
     * @return 搬到输出队列的记录数；负值为 ringbuf 错误
     * @note 未 prepare() 或从未 attach() 成功时返回 0，不访问 ringbuf；
     *       detach() 后仍可继续消费剩余记录。
     */
    virtual int consume(std::size_t budget)         = 0;
    /**
     * @brief 借用 ringbuf 的 epoll fd；prepare() 前或失败后返回 -1。
     * @note 调用方不得关闭 fd；fd 的生命周期由采集线持有。
     */
    virtual int epoll_fd() const noexcept           = 0;
    /**
     * @brief 借用角色过滤 map fd；prepare() 前或失败后返回 -1。
     * @note 调用方不得关闭 fd；须复制 fd 或保持采集器存活。
     *       fd 副本只延长 map 生命周期，不延长探针挂载的生命周期。
     */
    virtual int role_filter_map_fd() const noexcept = 0;
};

/**
 * @brief 采集聚合：单线程消费多条事件线并写入各自原始事件队列。
 * @details 线程由装配层创建；本类不持 std::thread。run() 用 epoll 等待各线
 *          ringbuf 的 eventfd，stop() 用 eventfd 唤醒。
 * @note 生命周期为 CONSTRUCTED → READY → RUNNING → STOPPED。所有线须由装配层
 *       构造并移交所有权；队列须比聚合对象活得更久。run() 返回前不得析构。
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
     * @brief 逐线 attach()；成功后状态为 READY。
     * @return 全部成功为 true；任一失败时摘除已挂载的线并返回 false
     * @note 只可在 CONSTRUCTED 且 prepare() 成功后调用。
     */
    bool attach();
    /**
     * @brief prepare() 后 attach()。
     * @return 全部成功为 true；否则 false
     */
    bool init();
    /**
     * @brief 汇总各线角色过滤 map fd。
     * @return 有效 fd 列表；未 prepare() 或对应线无 map 时为空
     * @note 调用方不得关闭 fd。
     */
    std::vector<int> role_filter_map_fds() const;

    /**
     * @brief 聚合线程入口：epoll 等待各线 ringbuf，逐线 consume。
     * @pre state() 为 READY；否则立即返回且不改变状态
     * @note 退出前逐线摘探针并排空 ringbuf；不创建线程。
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

/** @brief 文件事件采集线；借用的队列必须比采集器活得更久。 */
class FileEventCollector : public CollectorType {
   public:
    explicit FileEventCollector(hng::SPSC_Queue<file_access_data>& queue);
    ~FileEventCollector() override;

    bool prepare() override;
    bool attach() override;
    bool init() override;
    void detach() override;
    int consume(std::size_t budget) override;
    int epoll_fd() const noexcept override;
    int role_filter_map_fd() const noexcept override;

   private:
    hng::SPSC_Queue<file_access_data>& file_rawevent_queue;
    std::unique_ptr<hng::detail::FileCollectorState> state_;
    static int handle_rb_event(void* ctx, void* data,
                               std::size_t data_sz) noexcept;
};

/** @brief 系统调用事件采集线；借用的队列必须比采集器活得更久。 */
class SyscallEventCollector : public CollectorType {
   public:
    explicit SyscallEventCollector(hng::SPSC_Queue<syscall_event>& queue);
    ~SyscallEventCollector() override;

    bool prepare() override;
    bool attach() override;
    bool init() override;
    void detach() override;
    int consume(std::size_t budget) override;
    int epoll_fd() const noexcept override;
    int role_filter_map_fd() const noexcept override;

   private:
    hng::SPSC_Queue<syscall_event>& syscall_rawevent_queue;
    std::unique_ptr<hng::detail::SyscallCollectorState> state_;
    static int handle_rb_event(void* ctx, void* data,
                               std::size_t data_sz) noexcept;
};

/** @brief 网络事件采集线；借用的队列必须比采集器活得更久。 */
class NetworkEventCollector : public CollectorType {
   public:
    explicit NetworkEventCollector(hng::SPSC_Queue<network_data>& queue);
    ~NetworkEventCollector() override;

    bool prepare() override;
    bool attach() override;
    bool init() override;
    void detach() override;
    int consume(std::size_t budget) override;
    int epoll_fd() const noexcept override;
    int role_filter_map_fd() const noexcept override;

   private:
    hng::SPSC_Queue<network_data>& network_rawevent_queue;
    std::unique_ptr<hng::detail::NetworkCollectorState> state_;
    static int handle_rb_event(void* ctx, void* data,
                               std::size_t data_sz) noexcept;
};

/** @brief IPC 探针与载荷尚未定义，暂仅保留类型声明。 */
class IPCEventCollector;

#endif  // COLLECTOR_HPP
