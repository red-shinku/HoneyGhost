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

//! @note 与 libbpf 同定义：阻止编译器据上下文推断变量取值，保留 verifier 需要的
//!       边界检查。主机侧只是空操作，不影响被测逻辑。
#ifndef barrier_var
#define barrier_var(var) asm volatile("" : "+r"(var))
#endif

#endif  // HNG_TEST_KERNEL_PATH_BPF_HELPERS_H_
