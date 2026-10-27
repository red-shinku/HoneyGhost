# 生产采集器只在 libbpf 与骨架可用时构建；替身测试独立注册。
option(HNG_ENABLE_COLLECTOR "构建原始事件采集器（需 libbpf 与 eBPF 骨架）" ON)
if(NOT HNG_ENABLE_COLLECTOR)
    return()
endif()

get_target_property(HNG_COLLECTOR_CAN_GENERATE hng_ebpf HNG_HAS_SKELETON_GENERATION)
if(NOT HNG_COLLECTOR_CAN_GENERATE)
    foreach(probe files syscalls networks)
        if(NOT EXISTS "${HNG_SOURCE_DIR}/kernel/${probe}.skel.h")
            message(STATUS "eBPF 骨架不可用，跳过 hng_collector")
            return()
        endif()
    endforeach()
endif()

find_path(HNG_COLLECTOR_LIBBPF_INCLUDE_DIR bpf/libbpf.h)
find_library(HNG_COLLECTOR_LIBBPF_LIBRARY NAMES bpf)
if(NOT HNG_COLLECTOR_LIBBPF_INCLUDE_DIR OR NOT HNG_COLLECTOR_LIBBPF_LIBRARY)
    message(STATUS "libbpf 未找到，跳过 hng_collector")
    return()
endif()

add_library(hng_collector STATIC
    src/collector.cc
    src/collector_component.cc
    src/file_event_collector.cc
    src/syscall_event_collector.cc
    src/network_event_collector.cc)
target_include_directories(hng_collector
    PUBLIC ${HNG_SOURCE_DIR}
    PRIVATE ${HNG_COLLECTOR_LIBBPF_INCLUDE_DIR})
target_link_libraries(hng_collector
    PRIVATE ${HNG_COLLECTOR_LIBBPF_LIBRARY}
            hng_log)
target_compile_definitions(hng_collector PRIVATE HNG_LOG_TAG="collector")
add_dependencies(hng_collector hng_ebpf)
