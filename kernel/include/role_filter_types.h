/**
 * @file role_filter_types.h
 * @brief 用户态与 eBPF 共享的角色过滤 map 名称、容量和进程身份 ABI。
 */
#ifndef HNG_ROLE_FILTER_TYPES_H_
#define HNG_ROLE_FILTER_TYPES_H_

#ifndef __bpf__
#include <linux/types.h>
#endif

/** @brief 每份角色过滤 map 最多容纳的进程身份数量。 */
#define HNG_ROLE_FILTER_MAX_ENTRIES 65536
/** @brief 用户态查找角色过滤 map 时使用的名称。 */
#define HNG_ROLE_FILTER_MAP_NAME "hng_role_filter"

/**
 * @brief 角色过滤 map 的固定 16 字节键，以 TGID 和启动时间区分进程。
 * @details 用户态与 eBPF 必须采用相同布局，并将显式填充字段置零。
 * 启动时间取线程组组长的 start_boottime，转换为 USER_HZ 时钟滴答，
 * 与 /proc/<tgid>/stat 的第 22 字段采用相同单位。
 */
struct hng_role_filter_key {
    __u32 tgid;        ///< 线程组 ID。
    __u32 reserved;    ///< 显式填充，写入和查询时均须为零。
    __u64 start_time;  ///< 线程组组长启动时间，单位为 USER_HZ 时钟滴答。
};

#endif
