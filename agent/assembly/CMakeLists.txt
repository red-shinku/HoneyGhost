# ============================================================
# 装配层
#
# 初始化协调器按固定顺序驱动控制面三组件与 RoleFilter 的一次性初始化；
# /proc 快照读取器为它提供输入。组件线程由装配方在初始化之后启动。
# ============================================================
add_library(hng_assembly STATIC
    src/assembly.cc
    src/initialization_coordinator.cc
    src/proc_snapshot.cc
)
target_include_directories(hng_assembly PUBLIC
    ${HNG_SOURCE_DIR}
)
target_link_libraries(hng_assembly PUBLIC
    hng_process_manager
    hng_context_manager
    hng_control_plane
    hng_context_maintainer
    hng_role_filter
)
