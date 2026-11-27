# ============================================================
# BPF map 基础设施
#
# hng_bpf_map 只依赖标准库与 bpf syscall，始终构建；hng_bpf_loader 依赖
# libbpf，供装配层预检与后续 loader 使用。
# ============================================================
add_library(hng_bpf_map STATIC
    src/bpf_map.cc
)
target_include_directories(hng_bpf_map PUBLIC
    ${HNG_SOURCE_DIR}
)

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
