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
