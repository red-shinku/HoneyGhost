#ifndef SEMANTIC_HPP
#define SEMANTIC_HPP

#include <array>
#include <memory>
#include "agent/util/include/raw_event_queue_ss.hpp"
#include "agent/event_data/file_event.hpp"
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
    Semantic_file(hng::RawEventQueue_SS<struct file_access_data>& in_queue,
                  hng::RawEventQueue_SS<struct file_semantic_data>& out_queue);
    ~Semantic_file();

    /**
     * @brief 工作循环
     */
    void work() override;

   private:
    hng::RawEventQueue_SS<struct file_access_data>& raw_event_queue;
    hng::RawEventQueue_SS<struct file_semantic_data>& event_queue;
    /**
     * @brief 执行语义化
     */
    void transform();
};

/**
 * @brief 语义化处理器：系统调用事件
 */
class Semantic_syscall : public SemanticType {
   public:
    Semantic_syscall();
    ~Semantic_syscall();

    void work() override;

   private:
    hng::RawEventQueue_SS<struct syscall_event>& raw_event_queue;
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