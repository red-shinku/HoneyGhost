/**
 * @file bpf_helpers.h
 * @brief 为路径解析主机测试提供 map 声明与节属性宏替身。
 * @note 仅供主机编译使用，不会创建或加载真实 eBPF map。
 */
#ifndef HNG_TEST_KERNEL_PATH_BPF_HELPERS_H_
#define HNG_TEST_KERNEL_PATH_BPF_HELPERS_H_

#define __uint(name, val) int(*name)[val]
#define __type(name, val) val *name
#define SEC(name)

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

#endif  // HNG_TEST_KERNEL_PATH_BPF_HELPERS_H_
