/**
 * @file bpf_core_read.h
 * @brief 路径解析主机测试使用的 CO-RE 读取宏替身。
 * @note 直接访问测试结构体字段，不验证真实内核的 CO-RE 重定位与读取失败行为。
 */
#ifndef HNG_TEST_KERNEL_PATH_BPF_CORE_READ_H_
#define HNG_TEST_KERNEL_PATH_BPF_CORE_READ_H_

#include <stddef.h>

/// @brief 直接读字段：支持 a 与 a.b 两种访问式
#define BPF_CORE_READ(src, ...) ((src)->__VA_ARGS__)

/// @brief 直接把字段写入 dst（结构体字段按值复制）
#define BPF_CORE_READ_INTO(dst, src, ...) (*(dst) = (src)->__VA_ARGS__)

/// @brief 字段偏移取本地布局的 offsetof
#define bpf_core_field_offset(type, field) offsetof(type, field)

#endif  // HNG_TEST_KERNEL_PATH_BPF_CORE_READ_H_
