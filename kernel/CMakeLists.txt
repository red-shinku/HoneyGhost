# ============================================================
# eBPF 探针与骨架
#
# 产物落源码树：kernel/<n>.skel.h 与 kernel/build/<n>.bpf.o。
# 理由：collector.hpp 以 "kernel/files.skel.h" 包含骨架、verify_starttime.cc
# 默认读 "kernel/build/syscalls.bpf.o"，落源码树可做到零代码改动。两者均已被
# .gitignore 覆盖（*.skel.h 与 build/）。
#
# 骨架名必须显式给 <n>_collector：bpftool 的默认名只去掉 .o 扩展名（得
# files_bpf），而 collector.hpp 与 *_collector.cc 引用的是 files_collector。
#
# 探针的 include 一律仓库根相对，故 -I 指向仓库根，与 C++ 侧同款。
#
# clang 或 bpftool 缺失时只跳过本目录，不使整体构建失败（同 HNG_ENABLE_ROLE_SYSTEMD
# 的策略）。hng_ebpf 目标在任何分支下都存在，否则 Makefile 的 ebpf 目标会变成
# unknown target。
# ============================================================

# 防呆：独立配置时顶层项目未设置 HNG_SOURCE_DIR
if(NOT HNG_SOURCE_DIR)
    message(FATAL_ERROR
        "kernel/ 是顶层项目的子目录，请从仓库根构建：\n"
        "  cmake -S . -B build-agent && cmake --build build-agent\n"
        "（不要直接对 kernel/ 执行 cmake）")
endif()

option(HNG_ENABLE_EBPF "构建 eBPF 探针与骨架（需 clang 与 bpftool）" ON)

# ipc.bpf.c 尚为空文件，未纳入
set(HNG_EBPF_PROBES files networks syscalls)

set(HNG_EBPF_OBJ_DIR ${CMAKE_CURRENT_SOURCE_DIR}/build)
set(HNG_VMLINUX ${CMAKE_CURRENT_SOURCE_DIR}/include/vmlinux.h)
set(HNG_BTF /sys/kernel/btf/vmlinux)

# 探针依赖的全部头。共用头若不在依赖里，改它不会触发重编，骨架会静默沿用旧 BTF。
set(HNG_EBPF_HEADERS
    ${HNG_VMLINUX}
    ${CMAKE_CURRENT_SOURCE_DIR}/include/role_filter_types.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/role_filter.bpf.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/event_head.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/files_type.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/networks_type.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/syscall_event_head.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/syscalls_type.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/uapi_const.h
)

if(NOT HNG_ENABLE_EBPF)
    add_custom_target(hng_ebpf)
    message(STATUS "HNG_ENABLE_EBPF=OFF，跳过 eBPF 构建")
    return()
endif()

find_program(HNG_CLANG NAMES clang)

# /usr/sbin 不在 find_program 的默认搜索路径（只含 /bin），bpftool 常装在那里，
# 故显式给 HINTS；否则会静默判为未找到。
find_program(HNG_BPFTOOL NAMES bpftool HINTS /usr/sbin /usr/local/sbin /sbin)

if(NOT HNG_CLANG OR NOT HNG_BPFTOOL)
    add_custom_target(hng_ebpf)
    message(STATUS "clang 或 bpftool 未找到，跳过 eBPF 构建")
    return()
endif()

# vmlinux.h 只在缺失时生成。已存在时它仍作为探针的 DEPENDS，内核升级可触发重建。
if(NOT EXISTS ${HNG_VMLINUX})
    if(NOT EXISTS ${HNG_BTF})
        add_custom_target(hng_ebpf)
        message(STATUS "${HNG_BTF} 不存在，跳过 eBPF 构建")
        return()
    endif()

    # bpftool 没有输出到文件的选项，只能靠重定向；重定向与 VERBATIM 冲突，故经 sh -c。
    # 先写 .tmp 再 mv：直接重定向时若 bpftool 中途失败，目标文件已被截断，而下次
    # 构建见其 mtime 新即认为已最新，会把残缺文件当成完成品。
    add_custom_command(OUTPUT ${HNG_VMLINUX}
        COMMAND sh -c "\"${HNG_BPFTOOL}\" btf dump file ${HNG_BTF} format c > \"${HNG_VMLINUX}.tmp\" && mv \"${HNG_VMLINUX}.tmp\" \"${HNG_VMLINUX}\""
        DEPENDS ${HNG_BTF}
        COMMENT "生成 vmlinux.h（bpftool btf dump ${HNG_BTF}）"
        VERBATIM)
endif()

foreach(probe IN LISTS HNG_EBPF_PROBES)
    set(probe_src ${CMAKE_CURRENT_SOURCE_DIR}/probes/${probe}.bpf.c)
    set(probe_obj ${HNG_EBPF_OBJ_DIR}/${probe}.bpf.o)
    set(probe_skel ${CMAKE_CURRENT_SOURCE_DIR}/${probe}.skel.h)

    # 目标架构当前只支持 x86_64
    add_custom_command(OUTPUT ${probe_obj}
        COMMAND ${CMAKE_COMMAND} -E make_directory ${HNG_EBPF_OBJ_DIR}
        COMMAND ${HNG_CLANG} -O2 -g -target bpf -D__TARGET_ARCH_x86
                -I${HNG_SOURCE_DIR} -c ${probe_src} -o ${probe_obj}
        DEPENDS ${probe_src} ${HNG_EBPF_HEADERS}
        COMMENT "编译 eBPF 探针 ${probe}"
        VERBATIM)

    add_custom_command(OUTPUT ${probe_skel}
        COMMAND sh -c "\"${HNG_BPFTOOL}\" gen skeleton \"${probe_obj}\" name ${probe}_collector > \"${probe_skel}.tmp\" && mv \"${probe_skel}.tmp\" \"${probe_skel}\""
        DEPENDS ${probe_obj}
        COMMENT "生成骨架 ${probe}.skel.h（name ${probe}_collector）"
        VERBATIM)

    list(APPEND HNG_EBPF_OUTPUTS ${probe_obj} ${probe_skel})
endforeach()

# ALL：既有的 `cmake --build build-agent`（不带 --target）也要产出探针与骨架
add_custom_target(hng_ebpf ALL DEPENDS ${HNG_EBPF_OUTPUTS})

# 仅供 clangd / CLion 等：CMake 只为编译目标导出 compile_commands.json，而上面探针是
# add_custom_command 直接调 clang，不是编译目标，语言服务器因此拿不到探针参数（会退化成
# 套用邻近 C++ 文件的 -std=gnu++17 等，与探针的 C 语言冲突）。此目标只用来导出条目，
# EXCLUDE_FROM_ALL 使其不参与正常构建。
#
# C 编译器必须指定为 clang：探针用了 __builtin_preserve_access_index 等 clang 内建，
# gcc 无法解析；CLion 收集编译信息时若调用 gcc 会直接报错。
set(CMAKE_C_COMPILER ${HNG_CLANG})
enable_language(C)
add_library(hng_ebpf_cdb OBJECT EXCLUDE_FROM_ALL)
foreach(probe IN LISTS HNG_EBPF_PROBES)
    target_sources(hng_ebpf_cdb PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/probes/${probe}.bpf.c)
endforeach()
target_include_directories(hng_ebpf_cdb PRIVATE ${HNG_SOURCE_DIR})
target_compile_options(hng_ebpf_cdb PRIVATE
    -target bpf -D__TARGET_ARCH_x86 -O2 -g)
