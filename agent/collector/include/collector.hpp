#ifndef COLLECTOR_HPP
#define COLLECTOR_HPP

#include "../../util/include/raw_event_queue_ss.hpp"
#include "../../kernel/files.skel.h"
#include "../../kernel/syscalls.skel.h"

#include <array>

// 收集器的种类数
#define COLLECTOR_NUM 4

class CollectorType {
   public:
    virtual void collect()   = 0;
    virtual ~CollectorType() = default;
};

class Collector {
   public:
    Collector();
    ~Collector();

    void collect();

   private:
    std::array<CollectorType, COLLECTOR_NUM> collector;
};

class FileEventCollector : public CollectorType {
   public:
    FileEventCollector(hng::RawEventQueue_SS<struct file_access_data>& queue);
    ~FileEventCollector();

    bool init();
    void collect() override;

   private:
    hng::RawEventQueue_SS<struct file_access_data>& file_rawevent_queue;
    struct files_collector* files_collector;
    struct ring_buffer* rb;
    static int handle_rb_event(void* ctx, void* data, size_t data_sz);
};

class SyscallEventCollector : public CollectorType {
   public:
    SyscallEventCollector(hng::RawEventQueue_SS<struct syscall_event>& queue);
    ~SyscallEventCollector();

    bool init();
    void collect() override;

   private:
    hng::RawEventQueue_SS<struct syscall_event>& syscall_rawevent_queue;
    struct syscalls_collector* syscalls_collector;
    struct ring_buffer* rb;
    static int handle_rb_event(void* ctx, void* data, size_t data_sz);
};

class NetworkEventCollector : public CollectorType {
   public:
    NetworkEventCollector(RawEventQueue& queue);
    ~NetworkEventCollector();

    void collect() override;

   private:
    RawEventQueue& network_rawevent_queue;
};

class IPCEventCollector : public CollectorType {
   public:
    IPCEventCollector(RawEventQueue& queue);
    ~IPCEventCollector();

    void collect() override;

   private:
    RawEventQueue& ipc_rawevent_queue;
};

#endif  // COLLECTOR_HPP