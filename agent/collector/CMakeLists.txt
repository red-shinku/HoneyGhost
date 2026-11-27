# 生产采集器只在 BPF 加载器可用时构建；替身测试独立注册。
option(HNG_ENABLE_COLLECTOR "构建原始事件采集器（需 libbpf 与 eBPF 骨架）" ON)
if(NOT HNG_ENABLE_COLLECTOR)
    return()
endif()

if(NOT TARGET hng_bpf_loader)
    message(STATUS "hng_bpf_loader 不可用，跳过 hng_collector")
    return()
endif()

add_library(hng_collector STATIC
    src/collector.cc
    src/collector_component.cc
    src/syscall_event_collector.cc)
target_include_directories(hng_collector
    PUBLIC ${HNG_SOURCE_DIR})
target_link_libraries(hng_collector
    PRIVATE hng_bpf_loader
            hng_log
            hng_util)
target_compile_definitions(hng_collector PRIVATE HNG_LOG_TAG="collector")
