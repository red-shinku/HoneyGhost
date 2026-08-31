/**
 * @file file_event_collector.cc
 * @brief 用户态文件事件收集器 实现
 * @details
 *
 * 显式继承并实现CollectorType接口。
 * 从ringbuf获取数据，推送到文件原始事件队列
 *
 * @author red_shinku
 * @date 2026.08.12
 */

#include "./include/collector.hpp"
#include "../../kernel/include/files_type.h"

FileEventCollector::FileEventCollector(
    hng::SPSC_Queue<struct file_access_data>& queue)
    : file_rawevent_queue(queue), files_collector(NULL), rb(NULL)
{
}

FileEventCollector::~FileEventCollector()
{
    files_collector__destroy(files_collector);
    ring_buffer__free(rb);
}

/**
 * @brief ringbuf接受事件的回调函数
 */
int FileEventCollector::handle_rb_event(void* ctx, void* data, size_t data_sz)
{
    if (data_sz < sizeof(struct file_access_data)) {
        return -1;
    }
    // void* -> file_access_data*
    struct file_access_data* ev = (struct file_access_data*)data;
    // 获取 this 指针
    FileEventCollector* self    = static_cast<FileEventCollector*>(ctx);

    self->file_rawevent_queue.push(*ev);
    return 0;
}

/**
 * @brief 文件事件收集器初始化函数
 * @details 挂载并连接内核程序，初始化ringbuf
 */
bool FileEventCollector::init()
{
    int err;
    files_collector = files_collector__open_and_load();
    if (!files_collector) {
        return false;
    }
    err = files_collector__attach(files_collector);
    if (err) {
        return false;
    }
    // this 指针作为 ctx 注册到回调
    rb = ring_buffer__new(bpf_map__fd(files_collector->maps.file_access_events),
                          handle_rb_event, this, NULL);
    if (!rb) {
        return false;
    }
    return true;
}

/**
 * @brief 持续获取文件事件
 */
void FileEventCollector::collect()
{
    while (true) {
        // 300 ms timeout
        int err = ring_buffer__poll(rb, 300);
        // TODO: 错误处理与退出处理
        if (err == -EINTR) {
            break;
        }
        if (err < 0) {
            break;
        }
    }
}