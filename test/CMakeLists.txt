# ============================================================
# 文件语义化表驱动单元测试
#
# 本目录是顶层项目的子目录，不可独立配置（cmake test/），必须经顶层
# add_subdirectory(test) 构建，以便链接 hng_semantic 及其传递的 include 要求：
#   cmake -S . -B build-agent            # BUILD_TESTING 默认 ON
#   cmake --build build-agent --target test_semantic_file
#   ctest --test-dir build-agent
# ============================================================

# 防呆：独立配置时顶层目标不存在，给出明确指引
if(NOT TARGET hng_semantic)
    message(FATAL_ERROR
        "test/ 是顶层项目的子目录，请从仓库根构建：\n"
        "  cmake -S . -B build-agent && cmake --build build-agent\n"
        "（不要直接对 test/ 执行 cmake）")
endif()

add_executable(test_semantic_file test_semantic_file.cc)
target_link_libraries(test_semantic_file PRIVATE hng_semantic)
add_test(NAME test_semantic_file COMMAND test_semantic_file)

add_executable(test_semantic_syscall test_semantic_syscall.cc)
target_link_libraries(test_semantic_syscall PRIVATE hng_semantic)
add_test(NAME test_semantic_syscall COMMAND test_semantic_syscall)

add_executable(test_context_rule test_context_rule.cc)
target_link_libraries(test_context_rule PRIVATE hng_context_rule)
add_test(NAME test_context_rule COMMAND test_context_rule)

add_executable(test_context_maintainer test_context_maintainer.cc)
target_link_libraries(test_context_maintainer PRIVATE hng_context_maintainer)
add_test(NAME test_context_maintainer COMMAND test_context_maintainer)

# ============================================================
# 阶段 01 端到端校验（需 root 与 BPF 权限，不注册为 ctest 用例）
#
#   clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -c \
#       kernel/probes/syscalls.bpf.c -o kernel/build/syscalls.bpf.o
#   sudo build-agent/test/verify_starttime
#
# libbpf 缺失时跳过，不影响其余目标
# ============================================================
find_library(LIBBPF_LIB bpf)
if(LIBBPF_LIB)
    add_executable(verify_starttime verify_starttime.cc)
    target_include_directories(verify_starttime PRIVATE ${HNG_SOURCE_DIR})
    target_link_libraries(verify_starttime PRIVATE ${LIBBPF_LIB})
else()
    message(STATUS "libbpf 未找到，跳过 verify_starttime")
endif()
