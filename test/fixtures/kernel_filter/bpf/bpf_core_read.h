/**
 * @file bpf_core_read.h
 * @brief 内核过滤主机测试使用的 CO-RE 读取宏替身。
 * @note 仅直接访问测试结构体，不验证真实内核的 CO-RE 重定位或读取失败行为。
 */
#ifndef HNG_TEST_BPF_CORE_READ_H_
#define HNG_TEST_BPF_CORE_READ_H_
#define HNG_TEST_CORE1(src, a) ((src)->a)
#define HNG_TEST_CORE2(src, a, b) ((src)->a->b)
#define HNG_TEST_SELECT(_1, _2, name, ...) name
#define BPF_CORE_READ(src, ...) HNG_TEST_SELECT(__VA_ARGS__, HNG_TEST_CORE2, HNG_TEST_CORE1)(src, __VA_ARGS__)
#endif
