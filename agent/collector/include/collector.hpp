/**
 * @file collector.hpp
 * @brief 原始事件采集与角色过滤 map 的借用接口。
 */
#ifndef COLLECTOR_HPP
#define COLLECTOR_HPP

#include "agent/util/include/spsc_queue.hpp"
#include "kernel/include/files_type.h"
#include "kernel/include/networks_type.h"
#include "kernel/include/syscalls_type.h"

#include <array>
#include <cstddef>
#include <memory>

// 生成骨架、libbpf 资源与释放方式均为实现细节，定义只存在于 src/。
namespace hng::detail {
struct FileCollectorState;
struct SyscallCollectorState;
struct NetworkCollectorState;
}  // namespace hng::detail

/** @brief 收集器的种类数，包含尚未实现的 IPC。 */
#define COLLECTOR_NUM 4

/**
 * @brief 采集器生命周期接口。
 * @note init、collect 与析构必须串行；单个实例仅允许一个采集线程。
 *       若在外部线程运行 collect，须等待其返回并 join 后再析构。
 *       回调绑定对象地址，故禁止复制或移动。
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
     * @brief 加载骨架、创建 ringbuf 并校验过滤 map fd，不挂载探针。
     * @return 成功为 true；已准备或加载、map 校验、ringbuf 创建失败为 false
     * @note 成功后 role_filter_map_fd() 即可返回有效 fd，此时尚无事件产生；
     *       须再调用 attach()。失败时不保留任何已准备资源。
     */
    virtual bool prepare()                         = 0;
    /**
     * @brief 在 prepare() 成功后挂载探针。
     * @return 成功为 true；未准备、已挂载或挂载失败为 false
     * @note 挂载失败保留已准备资源，调用方可析构或放弃。
     */
    virtual bool attach()                          = 0;
    /**
     * @brief 加载、创建 ringbuf 并挂载探针，等价于 prepare() 后 attach()。
     * @return 成功为 true；attach() 失败时回收已准备资源并返回 false
     * @note 重复初始化返回 false；已 prepare() 而未 attach() 时返回 false，
     *       且不改变已准备状态。
     */
    virtual bool init()                            = 0;
    /** @brief 轮询至中断或错误；未准备或未挂载时直接返回。 */
    virtual void collect()                         = 0;
};

class Collector {
   public:
    Collector();
    ~Collector();
    void collect();

   private:
    std::array<std::unique_ptr<CollectorType>, COLLECTOR_NUM> collector;
};

/** @brief 文件事件采集器；借用的队列必须比采集器活得更久。 */
class FileEventCollector : public CollectorType {
   public:
    explicit FileEventCollector(hng::SPSC_Queue<file_access_data>& queue);
    ~FileEventCollector() override;

    bool prepare() override;
    bool attach() override;
    bool init() override;
    void collect() override;
    /**
     * @brief 借用角色过滤 map fd；prepare() 前或失败后返回 -1。
     * @note 调用方不得关闭 fd；须复制 fd 或保持采集器存活。
     *       fd 副本只延长 map 生命周期，不延长探针挂载的生命周期。
     */
    int role_filter_map_fd() const noexcept;

   private:
    hng::SPSC_Queue<file_access_data>& file_rawevent_queue;
    std::unique_ptr<hng::detail::FileCollectorState> state_;
    static int handle_rb_event(void* ctx, void* data,
                               std::size_t data_sz) noexcept;
};

/** @brief 系统调用事件采集器；借用的队列必须比采集器活得更久。 */
class SyscallEventCollector : public CollectorType {
   public:
    explicit SyscallEventCollector(hng::SPSC_Queue<syscall_event>& queue);
    ~SyscallEventCollector() override;

    bool prepare() override;
    bool attach() override;
    bool init() override;
    void collect() override;
    /**
     * @brief 借用角色过滤 map fd；prepare() 前或失败后返回 -1。
     * @note 调用方不得关闭 fd；须复制 fd 或保持采集器存活。
     *       fd 副本只延长 map 生命周期，不延长探针挂载的生命周期。
     */
    int role_filter_map_fd() const noexcept;

   private:
    hng::SPSC_Queue<syscall_event>& syscall_rawevent_queue;
    std::unique_ptr<hng::detail::SyscallCollectorState> state_;
    static int handle_rb_event(void* ctx, void* data,
                               std::size_t data_sz) noexcept;
};

/** @brief 网络事件采集器；借用的队列必须比采集器活得更久。 */
class NetworkEventCollector : public CollectorType {
   public:
    explicit NetworkEventCollector(hng::SPSC_Queue<network_data>& queue);
    ~NetworkEventCollector() override;

    bool prepare() override;
    bool attach() override;
    bool init() override;
    void collect() override;
    /**
     * @brief 借用角色过滤 map fd；prepare() 前或失败后返回 -1。
     * @note 调用方不得关闭 fd；须复制 fd 或保持采集器存活。
     *       fd 副本只延长 map 生命周期，不延长探针挂载的生命周期。
     */
    int role_filter_map_fd() const noexcept;

   private:
    hng::SPSC_Queue<network_data>& network_rawevent_queue;
    std::unique_ptr<hng::detail::NetworkCollectorState> state_;
    static int handle_rb_event(void* ctx, void* data,
                               std::size_t data_sz) noexcept;
};

/** @brief IPC 探针与载荷尚未定义，暂仅保留类型声明。 */
class IPCEventCollector;

#endif  // COLLECTOR_HPP
