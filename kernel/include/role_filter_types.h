#ifndef HNG_ROLE_FILTER_TYPES_H_
#define HNG_ROLE_FILTER_TYPES_H_

#ifndef __bpf__
#include <linux/types.h>
#endif

#define HNG_ROLE_FILTER_MAX_ENTRIES 65536
#define HNG_ROLE_FILTER_MAP_NAME "hng_role_filter"

/* 固定 ABI：显式填充必须置零；start_time 与 /proc/<tgid>/stat 字段 22 同单位。 */
struct hng_role_filter_key {
    __u32 tgid;
    __u32 reserved;
    __u64 start_time;
};

#endif
