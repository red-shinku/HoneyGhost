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

# 角色发现公共骨架：状态表与 cgroup 读取，无 IO / 无特权
add_executable(test_role_signal_table test_role_signal_table.cc)
target_link_libraries(test_role_signal_table PRIVATE hng_role_discovery)
add_test(NAME test_role_signal_table COMMAND test_role_signal_table)

add_executable(test_role_cgroup_reader test_role_cgroup_reader.cc)
target_link_libraries(test_role_cgroup_reader PRIVATE hng_role_discovery)
add_test(NAME test_role_cgroup_reader COMMAND test_role_cgroup_reader)

# 控制平面的上下文管理器：五个写接口经队列落地，无 IO / 无特权
add_executable(test_context_manager test_context_manager.cc)
target_link_libraries(test_context_manager PRIVATE hng_context_manager)
add_test(NAME test_context_manager COMMAND test_context_manager)

# 控制平面的进程管理器：三个注入点走替身，无 IO / 无特权
add_executable(test_process_manager test_process_manager.cc)
target_link_libraries(test_process_manager PRIVATE hng_process_manager)
add_test(NAME test_process_manager COMMAND test_process_manager)

# 通知队列（公共件，header-only）：无 IO / 无特权
add_executable(test_notification_queue test_notification_queue.cc)
target_include_directories(test_notification_queue PRIVATE ${HNG_SOURCE_DIR})
add_test(NAME test_notification_queue COMMAND test_notification_queue)

# 运行时信息过滤器（公共件，header-only；经 event_data 头传递需要 proto 生成物）
add_executable(test_runtime_info_filter test_runtime_info_filter.cc)
target_link_libraries(test_runtime_info_filter PRIVATE hng_event_data)
add_test(NAME test_runtime_info_filter COMMAND test_runtime_info_filter)

# 运行时引擎的包装器：纯转换，无 IO / 无特权
add_executable(test_runtime_packaging test_runtime_packaging.cc)
target_link_libraries(test_runtime_packaging PRIVATE hng_runtime_engine)
add_test(NAME test_runtime_packaging COMMAND test_runtime_packaging)

# 控制平面的角色关系表：纯内存，无 IO / 无特权
add_executable(test_role_relation_store test_role_relation_store.cc)
target_link_libraries(test_role_relation_store PRIVATE hng_control_plane)
add_test(NAME test_role_relation_store COMMAND test_role_relation_store)

# 控制平面的角色管理器：队列与消费线程，cgroup 读取走注入点，无特权
add_executable(test_role_manager test_role_manager.cc)
target_link_libraries(test_role_manager PRIVATE hng_control_plane)
add_test(NAME test_role_manager COMMAND test_role_manager)

# 角色管理器端到端校验：装配形态 + 假发现器 + 真实 cgroup 读取，无特权
add_executable(verify_role_manager verify_role_manager.cc)
target_link_libraries(verify_role_manager PRIVATE hng_control_plane)
add_test(NAME verify_role_manager COMMAND verify_role_manager)

# containerd 角色发现源：经真实 Unix socket 与假翻译进程对打，无特权
if(TARGET hng_role_containerd)
    add_executable(test_role_containerd_discoverer test_role_containerd_discoverer.cc)
    target_link_libraries(test_role_containerd_discoverer PRIVATE hng_role_containerd)
    add_test(NAME test_role_containerd_discoverer COMMAND test_role_containerd_discoverer)

    # 阶段 04 端到端校验（需先起翻译进程，不注册为 ctest 用例）
    #   sudo build-agent/test/verify_role_containerd
    add_executable(verify_role_containerd verify_role_containerd.cc)
    target_link_libraries(verify_role_containerd PRIVATE hng_role_containerd)
endif()

# systemd 角色发现源：libsystemd 不可用时该目标不存在，一并跳过
if(TARGET hng_role_systemd)
    add_executable(test_role_systemd_discoverer test_role_systemd_discoverer.cc)
    target_link_libraries(test_role_systemd_discoverer PRIVATE hng_role_systemd)
    add_test(NAME test_role_systemd_discoverer COMMAND test_role_systemd_discoverer)

    # 阶段 03 端到端校验（需 root 连真实 system bus，不注册为 ctest 用例）
    #   sudo build-agent/test/verify_role_systemd
    add_executable(verify_role_systemd verify_role_systemd.cc)
    target_link_libraries(verify_role_systemd PRIVATE hng_role_systemd)
endif()

# ============================================================
# 阶段 01 端到端校验（需 root 与 BPF 权限，不注册为 ctest 用例）
#
#   make ebpf        # 产出 kernel/build/syscalls.bpf.o，见 kernel/CMakeLists.txt
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
