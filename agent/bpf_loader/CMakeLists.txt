# ============================================================
# BPF map 基础设施
#
# hng_bpf_map 只依赖标准库与 bpf syscall，始终构建；hng_bpf_loader 依赖
# libbpf 与 syscalls 骨架，供装配层预检、加载与后续 collector 使用。
# ============================================================
add_library(hng_bpf_map STATIC
    src/bpf_map.cc
)
target_include_directories(hng_bpf_map PUBLIC
    ${HNG_SOURCE_DIR}
)

get_target_property(HNG_BPF_LOADER_CAN_GENERATE hng_ebpf
    HNG_HAS_SKELETON_GENERATION)
if(NOT HNG_BPF_LOADER_CAN_GENERATE AND
   NOT EXISTS "${HNG_SOURCE_DIR}/kernel/syscalls.skel.h")
    message(STATUS "eBPF 骨架不可用，跳过 hng_bpf_loader")
    return()
endif()

find_path(HNG_BPF_LOADER_LIBBPF_INCLUDE_DIR bpf/libbpf.h)
find_library(HNG_BPF_LOADER_LIBBPF_LIBRARY NAMES bpf)
if(NOT HNG_BPF_LOADER_LIBBPF_INCLUDE_DIR OR
   NOT HNG_BPF_LOADER_LIBBPF_LIBRARY)
    message(STATUS "libbpf 未找到，跳过 hng_bpf_loader")
    return()
endif()

add_library(hng_bpf_loader STATIC
    src/bpf_map_reader.cc
    src/bpf_environment.cc
    src/bpf_program_group.cc
    src/probe_attach.cc
    src/ringbuf_reader.cc
    src/syscall_probe_loader.cc
)
target_include_directories(hng_bpf_loader
    PUBLIC ${HNG_SOURCE_DIR}
    PRIVATE ${HNG_BPF_LOADER_LIBBPF_INCLUDE_DIR}
)
target_link_libraries(hng_bpf_loader
    PUBLIC hng_bpf_map
    PRIVATE ${HNG_BPF_LOADER_LIBBPF_LIBRARY}
            hng_util
            hng_log
)
target_compile_definitions(hng_bpf_loader PRIVATE HNG_LOG_TAG="bpf_loader")
if(TARGET hng_ebpf)
    add_dependencies(hng_bpf_loader hng_ebpf)
endif()
