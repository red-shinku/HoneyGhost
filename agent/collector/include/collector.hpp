/**
 * @file
 * @brief 原始事件采集器及角色过滤 map 的借用接口。
 */
#ifndef COLLECTOR_HPP
#define COLLECTOR_HPP

#include "agent/util/include/spsc_queue.hpp"

#include "kernel/include/files_type.h"
#include "kernel/include/syscalls_type.h"
#include "kernel/include/networks_type.h"

#include "kernel/files.skel.h"
#include "kernel/syscalls.skel.h"
#include "kernel/networks.skel.h"

#include <array>
#include <memory>

/** @brief 收集器的种类数。 */
#define COLLECTOR_NUM 4

class CollectorType {
   public:
    virtual void collect() = 0;
    /** @brief 初始化采集器。 @return 成功为 true，失败为 false。 */
    virtual bool init() = 0;
    virtual ~CollectorType() = default;
};

class Collector {
   public:
    Collector();
    ~Collector();

    void collect();

   private:
    std::array<std::unique_ptr<CollectorType>, COLLECTOR_NUM> collector;
};

/** @brief 持有探针骨架和 ringbuf；借用的事件队列须比采集器活得更久。 */
class FileEventCollector : public CollectorType {
   public:
    FileEventCollector(hng::SPSC_Queue<struct file_access_data>& queue);
    ~FileEventCollector();

    /**
     * @brief 加载探针、挂载并创建 ringbuf；失败时回收本次申请的资源。
     * @return 成功为 true，失败或重复初始化为 false。
     */
    bool init() override;
    /** @brief 轮询事件直到中断或错误；未初始化时直接返回。 */
    void collect() override;
    /**
     * @brief 借用当前探针的角色过滤 map fd。
     * @return 初始化成功后返回 map fd，否则返回 -1。
     * @note fd 归采集器所有；调用方不得关闭它，须复制 fd 或保持采集器存活。
     */
    int role_filter_map_fd() const noexcept;

   private:
    hng::SPSC_Queue<struct file_access_data>& file_rawevent_queue;
    struct files_collector* files_collector;
    struct ring_buffer* rb;
    static int handle_rb_event(void* ctx, void* data, size_t data_sz);
};

/** @brief 持有探针骨架和 ringbuf；借用的事件队列须比采集器活得更久。 */
class SyscallEventCollector : public CollectorType {
   public:
    SyscallEventCollector(hng::SPSC_Queue<struct syscall_event>& queue);
    ~SyscallEventCollector();

    /**
     * @brief 加载探针、挂载并创建 ringbuf；失败时回收本次申请的资源。
     * @return 成功为 true，失败或重复初始化为 false。
     */
    bool init() override;
    /** @brief 轮询事件直到中断或错误；未初始化时直接返回。 */
    void collect() override;
    /**
     * @brief 借用当前探针的角色过滤 map fd。
     * @return 初始化成功后返回 map fd，否则返回 -1。
     * @note fd 归采集器所有；调用方不得关闭它，须复制 fd 或保持采集器存活。
     */
    int role_filter_map_fd() const noexcept;

   private:
    hng::SPSC_Queue<struct syscall_event>& syscall_rawevent_queue;
    struct syscalls_collector* syscalls_collector;
    struct ring_buffer* rb;
    static int handle_rb_event(void* ctx, void* data, size_t data_sz);
};

/** @brief 持有探针骨架和 ringbuf；借用的事件队列须比采集器活得更久。 */
class NetworkEventCollector : public CollectorType {
   public:
    NetworkEventCollector(hng::SPSC_Queue<struct network_data>& queue);
    ~NetworkEventCollector();

    /**
     * @brief 加载探针、挂载并创建 ringbuf；失败时回收本次申请的资源。
     * @return 成功为 true，失败或重复初始化为 false。
     */
    bool init() override;
    /** @brief 轮询事件直到中断或错误；未初始化时直接返回。 */
    void collect() override;
    /**
     * @brief 借用当前探针的角色过滤 map fd。
     * @return 初始化成功后返回 map fd，否则返回 -1。
     * @note fd 归采集器所有；调用方不得关闭它，须复制 fd 或保持采集器存活。
     */
    int role_filter_map_fd() const noexcept;

   private:
    hng::SPSC_Queue<struct network_data>& network_rawevent_queue;
    struct networks_collector* networks_collector;
    struct ring_buffer* rb;
    static int handle_rb_event(void* ctx, void* data, size_t data_sz);
};

/** @brief IPC 探针及载荷尚未定义，暂仅保留类型声明。 */
class IPCEventCollector;

#endif  // COLLECTOR_HPP
