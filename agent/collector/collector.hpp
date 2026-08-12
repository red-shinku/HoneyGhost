#ifndef COLLECTOR_HPP
#define COLLECTOR_HPP

# include "include/raw_event_queue.hpp"
#include "../kernel/files.skel.h" 

#include <array>

// 收集器的种类数
#define COLLECTOR_NUM 4

class CollectorType {
public:
    virtual void collect() = 0;
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
    FileEventCollector(RawEventQueue& queue);
    ~FileEventCollector();

    bool init();
    void collect() override;

private:
    RawEventQueue& file_rawevent_queue;
    struct files_collector *files_collector;
    struct ring_buffer *rb;
    static int handle_rb_event(void *ctx, void *data, size_t data_sz);
};

class SyscallEventCollector : public CollectorType {
public:
    SyscallEventCollector(RawEventQueue& queue);
    ~SyscallEventCollector();

    void collect() override;
private:
    RawEventQueue& syscall_rawevent_queue;
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


#endif // COLLECTOR_HPP