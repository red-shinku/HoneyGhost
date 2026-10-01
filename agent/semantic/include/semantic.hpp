#ifndef SEMANTIC_HPP
#define SEMANTIC_HPP

#include <array>
#include <memory>
#include "agent/util/include/spsc_queue.hpp"
#include "agent/event_data/include/file_event.hpp"
#include "agent/event_data/include/syscall_event.hpp"
#include "kernel/include/files_type.h"
#include "kernel/include/syscalls_type.h"

#define SEMANTIC_MODULE_NUM 4

/**
 * @brief 语义化模块接口
 */
class SemanticType {
   public:
    virtual ~SemanticType() = default;
    virtual void work()     = 0;
};

/**
 * @brief 语义化模块集合
 */
class Semantic {
   public:
    Semantic();
    ~Semantic();

    void run();

   private:
    std::array<std::unique_ptr<SemanticType>, SEMANTIC_MODULE_NUM> module;
};

/**
 * @brief 语义化处理器：文件事件
 */
class Semantic_file : public SemanticType {
   public:
    Semantic_file(hng::SPSC_Queue<struct file_access_data>& in_queue,
                  hng::SPSC_Queue<hng::file_semantic_data>& out_queue);
    ~Semantic_file();

    /**
     * @brief 工作循环
     */
    void work() override;

   private:
    hng::SPSC_Queue<struct file_access_data>& raw_event_queue;
    hng::SPSC_Queue<hng::file_semantic_data>& event_queue;
    /**
     * @brief 执行语义化
     */
    void transform();
};

/**
 * @brief 语义化处理器：系统调用事件
 * @details 从系统调用原始事件队列取出 struct syscall_event，按 hdr.type 分派到
 * 八种语义载荷，组装为 syscall_semantic_data 推入下游语义事件队列。
 */
class Semantic_syscall : public SemanticType {
   public:
    Semantic_syscall(hng::SPSC_Queue<struct syscall_event>& in_queue,
                     hng::SPSC_Queue<hng::syscall_semantic_data>& out_queue);
    ~Semantic_syscall();

    void work() override;

    /**
     * @brief 单条原始事件 → 语义事件（纯转换）
     * @details 无状态、无队列依赖：给定原始事件产出语义事件。公开供表驱动
     * 单测直接调用，编排路径 transform() 复用本函数。
     */
    void transform_one(const struct syscall_event& raw,
                       hng::syscall_semantic_data& out);

   private:
    hng::SPSC_Queue<struct syscall_event>& raw_event_queue;
    hng::SPSC_Queue<hng::syscall_semantic_data>& event_queue;
    void transform();
};

/**
 * @brief 语义化处理器：网络事件
 */
class Semantic_network : public SemanticType {
   public:
    Semantic_network();
    ~Semantic_network();

    void work() override;

   private:
};

/**
 * @brief 语义化处理器：IPC 事件
 */
class Semantic_ipc : public SemanticType {
   public:
    Semantic_ipc();
    ~Semantic_ipc();

    void work() override;

   private:
};

#endif  // SEMANTIC_HPP