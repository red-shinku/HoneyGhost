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

// 收集器的种类数
#define COLLECTOR_NUM 4

class CollectorType {
   public:
    virtual void collect() = 0;
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

class FileEventCollector : public CollectorType {
   public:
    FileEventCollector(hng::SPSC_Queue<struct file_access_data>& queue);
    ~FileEventCollector();

    bool init() override;
    void collect() override;
    // init 成功后返回借用 fd；调用方须复制 fd 或保持采集器存活。
    int role_filter_map_fd() const noexcept;

   private:
    hng::SPSC_Queue<struct file_access_data>& file_rawevent_queue;
    struct files_collector* files_collector;
    struct ring_buffer* rb;
    static int handle_rb_event(void* ctx, void* data, size_t data_sz);
};

class SyscallEventCollector : public CollectorType {
   public:
    SyscallEventCollector(hng::SPSC_Queue<struct syscall_event>& queue);
    ~SyscallEventCollector();

    bool init() override;
    void collect() override;
    // init 成功后返回借用 fd；调用方须复制 fd 或保持采集器存活。
    int role_filter_map_fd() const noexcept;

   private:
    hng::SPSC_Queue<struct syscall_event>& syscall_rawevent_queue;
    struct syscalls_collector* syscalls_collector;
    struct ring_buffer* rb;
    static int handle_rb_event(void* ctx, void* data, size_t data_sz);
};

class NetworkEventCollector : public CollectorType {
   public:
    NetworkEventCollector(hng::SPSC_Queue<struct network_data>& queue);
    ~NetworkEventCollector();

    bool init() override;
    void collect() override;
    // init 成功后返回借用 fd；调用方须复制 fd 或保持采集器存活。
    int role_filter_map_fd() const noexcept;

   private:
    hng::SPSC_Queue<struct network_data>& network_rawevent_queue;
    struct networks_collector* networks_collector;
    struct ring_buffer* rb;
    static int handle_rb_event(void* ctx, void* data, size_t data_sz);
};

// IPC 探针/载荷尚未定义；保留类型声明，不提前设计队列元素 ABI。
class IPCEventCollector;

#endif  // COLLECTOR_HPP