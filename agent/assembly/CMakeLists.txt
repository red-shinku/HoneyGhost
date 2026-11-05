# ============================================================
# 装配层
#
# 初始化协调器按固定顺序驱动控制面三组件与 RoleFilter 的一次性初始化；
# /proc 快照读取器为它提供输入。组件线程由装配方在初始化之后启动。
# ============================================================
add_library(hng_assembly STATIC
    src/assembly.cc
    src/initialization_coordinator.cc
    src/kernel_preflight.cc
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
    hng_semantic
    hng_runtime_engine
    hng_role_discovery_component
    Threads::Threads
)
# 采集器缺失时装配层以 --no-collect 运行，可用性宏只在本目标内生效
if(TARGET hng_collector)
    target_link_libraries(hng_assembly PUBLIC hng_collector)
    target_compile_definitions(hng_assembly PRIVATE HNG_HAVE_COLLECTOR=1)
endif()
target_link_libraries(hng_assembly PRIVATE hng_log)
target_compile_definitions(hng_assembly PRIVATE HNG_LOG_TAG="init")
