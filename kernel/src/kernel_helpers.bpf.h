#ifndef HNG_KERNEL_HELPERS_BPF_H_
#define HNG_KERNEL_HELPERS_BPF_H_

#include <bpf/bpf_helpers.h>

/// @brief union bpf_attr 中 attach_type 的偏移（BPF_PROG_ATTACH/DETACH）
#define HNG_BPF_ATTR_ATTACH_TYPE_OFF 8

/// @brief 用户态 siginfo_t 中 si_code 的偏移（x86_64 UAPI 布局）
#define HNG_SIGINFO_SI_CODE_OFF 8

/**
 * @brief 读取 tracepoint raw entry 里的字符串字段。
 * @param[out] dst 目标缓冲
 * @param[in] sz 容量
 * @param[in] ctx tracepoint 上下文（raw entry 起始）
 * @param[in] field_off 该字段在 entry 中的字节偏移
 * @note 字段既可能是 __data_loc char[]，也可能是定长数组：先按 4 字节描述符
 *       读取，描述符落在 entry 内且长度非零时按其中偏移取串，否则直接把该
 *       偏移处当字符数组读。
 * @note 偏移一律相对 entry 起点，取自 tracepoint 的 format 布局。
 */
static __always_inline void hng_read_trace_string(char *dst, __u32 sz,
                                                  const void *ctx,
                                                  __u32 field_off)
{
    if (!dst || sz == 0) {
        return;
    }
    dst[0] = '\0';
    if (!ctx) {
        return;
    }
    __u32 loc = 0;
    if (bpf_probe_read_kernel(&loc, sizeof(loc), (const char *)ctx + field_off)) {
        return;
    }
    __u32 data_off = loc & 0xffff;
    __u32 data_len = loc >> 16;
    //! @note __data_loc 的数据区在 entry 内，且不覆盖描述符自身
    if (data_len != 0 && data_off >= field_off + 4 && data_off < 4096) {
        bpf_probe_read_kernel_str(dst, sz, (const char *)ctx + data_off);
        return;
    }
    bpf_probe_read_kernel_str(dst, sz, (const char *)ctx + field_off);
}

/**
 * @brief 按 bpf 命令解出 union bpf_attr 里的类型字段
 * @param[in] cmd bpf 命令（BPF_*）
 * @param[in] attr 用户态 union bpf_attr
 * @return map_type（BPF_MAP_CREATE）、prog_type（BPF_PROG_LOAD）或 attach_type
 *         （BPF_PROG_ATTACH/DETACH）；其它命令或读取失败返回 0
 * @note 三个字段都落在 union 的前 16 字节：map_type/prog_type 是首个 u32，
 *       attach_type 是 ATTACH/DETACH 匿名结构的第三个 u32（偏移 8）。
 */
static __always_inline __u32 decode_bpf_type(__u32 cmd, const void *attr)
{
    __u32 offset = 0;
    switch (cmd) {
        case BPF_MAP_CREATE:
        case BPF_PROG_LOAD:
            break;
        case BPF_PROG_ATTACH:
        case BPF_PROG_DETACH:
            offset = HNG_BPF_ATTR_ATTACH_TYPE_OFF;
            break;
        default:
            return 0;
    }
    if (!attr) {
        return 0;
    }
    __u32 value = 0;
    if (bpf_probe_read_user(&value, sizeof(value), (const char *)attr + offset)) {
        return 0;
    }
    return value;
}
#endif
