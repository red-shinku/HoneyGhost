/**
 * @file spsc_queue.cc
 * @brief SPSC 无锁队列 —— 显式实例化单元
 * @details
 *
 * 模板实现位于 raw_event_queue_ss.hpp。
 * 本编译单元用于为收集器使用的具体事件类型生成显式实例化，以预先编译、缩短
 * 各收集器编译时间：
 *
 * 以下事件类型定义于 kernel/include 的类型头文件，而它们会引入 vmlinux.h，
 * 其中包含 `false`、`private`、`template`、`delete` 等 C++ 关键字，
 * 导致无法编译，问题待解决。
 *
 * @author red_shinku
 * @date 2026.08.13
 */

#include "agent/util/include/spsc_queue.hpp"

template class hng::SPSC_Queue<struct file_access_data>;
template class hng::SPSC_Queue<struct syscall_event>;
template class hng::SPSC_Queue<struct network_data>;
// TODO: 显式实例化