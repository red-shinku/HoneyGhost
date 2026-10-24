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

# 控制平面的上下文关系存储层：单线程直调，无队列 / 无 IO / 无特权
add_executable(test_context_store test_context_store.cc)
target_link_libraries(test_context_store PRIVATE hng_context_manager)
add_test(NAME test_context_store COMMAND test_context_store)

# 控制平面的进程管理器：三个注入点走替身，无 IO / 无特权
add_executable(test_process_manager test_process_manager.cc)
target_link_libraries(test_process_manager PRIVATE hng_process_manager)
add_test(NAME test_process_manager COMMAND test_process_manager)

# 通知队列（公共件，header-only）：无 IO / 无特权
add_executable(test_notification_queue test_notification_queue.cc)
target_include_directories(test_notification_queue PRIVATE ${HNG_SOURCE_DIR})
add_test(NAME test_notification_queue COMMAND test_notification_queue)

# 延迟关系表（公共件，header-only）：无 IO / 无特权
add_executable(test_deferred_relation_table test_deferred_relation_table.cc)
target_include_directories(test_deferred_relation_table PRIVATE ${HNG_SOURCE_DIR})
add_test(NAME test_deferred_relation_table COMMAND test_deferred_relation_table)

# 墓碑表（公共件，header-only）：无 IO / 无特权
add_executable(test_tombstone_table test_tombstone_table.cc)
target_include_directories(test_tombstone_table PRIVATE ${HNG_SOURCE_DIR})
add_test(NAME test_tombstone_table COMMAND test_tombstone_table)

# SPSC 无锁队列（公共件，header-only）：单生产者单消费者，无 IO / 无特权
add_executable(test_spsc_queue test_spsc_queue.cc)
target_include_directories(test_spsc_queue PRIVATE ${HNG_SOURCE_DIR})
add_test(NAME test_spsc_queue COMMAND test_spsc_queue)

# 运行时信息过滤器（公共件，header-only；经 event_data 头传递需要 proto 生成物）
add_executable(test_runtime_info_filter test_runtime_info_filter.cc)
target_link_libraries(test_runtime_info_filter PRIVATE hng_event_data)
add_test(NAME test_runtime_info_filter COMMAND test_runtime_info_filter)

# 运行时引擎的包装器：纯转换，无 IO / 无特权
add_executable(test_runtime_packaging test_runtime_packaging.cc)
target_link_libraries(test_runtime_packaging PRIVATE hng_runtime_engine)
add_test(NAME test_runtime_packaging COMMAND test_runtime_packaging)

# 运行时引擎的流水线：控制平面的注入点走替身，语义队列为真实 SPSC，无特权
add_executable(test_runtime_pipeline test_runtime_pipeline.cc)
target_link_libraries(test_runtime_pipeline PRIVATE hng_runtime_engine)
add_test(NAME test_runtime_pipeline COMMAND test_runtime_pipeline)

# 运行时引擎的分发器：订阅者走替身，无 IO / 无特权
add_executable(test_runtime_event_dispatcher test_runtime_event_dispatcher.cc)
target_link_libraries(test_runtime_event_dispatcher PRIVATE hng_runtime_engine)
add_test(NAME test_runtime_event_dispatcher COMMAND test_runtime_event_dispatcher)

# 运行时引擎的主循环：控制平面走替身，引擎独占一条测试线程，无特权
add_executable(test_runtime_engine test_runtime_engine.cc)
target_link_libraries(test_runtime_engine PRIVATE hng_runtime_engine)
add_test(NAME test_runtime_engine COMMAND test_runtime_engine)

# ============================================================
# CLI 服务端模块
#
# 订阅队列与订阅流的挂起要用协程引擎，故链接 hng_cli_server（传递 userver::core）
# 与 hng_cli_proto；-DHNG_ENABLE_CLI_SERVER=OFF 时该目标不存在，整段跳过
# ============================================================
if(TARGET hng_cli_server)
    # 订阅流的事件队列：生产者普通线程、消费者 userver 任务
    add_executable(test_cli_event_queue test_cli_event_queue.cc)
    target_link_libraries(test_cli_event_queue PRIVATE hng_cli_server)
    add_test(NAME test_cli_event_queue COMMAND test_cli_event_queue)

    # 订阅流与流表：引擎走替身，无特权
    add_executable(test_cli_stream test_cli_stream.cc)
    target_link_libraries(test_cli_stream PRIVATE hng_cli_server)
    add_test(NAME test_cli_stream COMMAND test_cli_stream)

    # 订阅参数 → 过滤器：表驱动，纯值对象
    add_executable(test_cli_subscription_params test_cli_subscription_params.cc)
    target_link_libraries(test_cli_subscription_params PRIVATE hng_cli_server)
    add_test(NAME test_cli_subscription_params COMMAND test_cli_subscription_params)

    # 事件 → 响应报文：纯转换，无 IO
    add_executable(test_cli_event_converter test_cli_event_converter.cc)
    target_link_libraries(test_cli_event_converter PRIVATE hng_cli_server)
    add_test(NAME test_cli_event_converter COMMAND test_cli_event_converter)

    # 静态配置 schema：解析 YAML 文本并核对配置项
    add_executable(test_cli_server_config test_cli_server_config.cc)
    target_link_libraries(test_cli_server_config PRIVATE hng_cli_server)
    add_test(NAME test_cli_server_config COMMAND test_cli_server_config)

    # 端到端：子进程跑粗糙装配的 userver 应用，父进程用标准 gRPC 客户端断言
    # 依赖 Unix socket 与 fork，故仅在类 Unix 平台注册
    add_executable(e2e_cli_server e2e_cli_server.cc)
    target_link_libraries(e2e_cli_server PRIVATE hng_cli_server userver::grpc)
    add_test(NAME e2e_cli_server COMMAND e2e_cli_server)
    set_tests_properties(e2e_cli_server PROPERTIES TIMEOUT 120)
endif()

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

# 采集器角色过滤接口：仅本测试目标使用骨架替身，不依赖真实 eBPF 加载。
set(HNG_COLLECTOR_MOCK_DIR ${CMAKE_CURRENT_BINARY_DIR}/collector-mocks)
file(MAKE_DIRECTORY ${HNG_COLLECTOR_MOCK_DIR}/kernel)
foreach(probe files syscalls networks)
    configure_file(fixtures/collector_skeleton_stub.hpp
        ${HNG_COLLECTOR_MOCK_DIR}/kernel/${probe}.skel.h COPYONLY)
endforeach()
add_executable(test_collector_filter_map
    test_collector_filter_map.cc
    ${HNG_SOURCE_DIR}/agent/collector/src/file_event_collector.cc
    ${HNG_SOURCE_DIR}/agent/collector/src/syscall_event_collector.cc
    ${HNG_SOURCE_DIR}/agent/collector/src/network_event_collector.cc)
target_include_directories(test_collector_filter_map PRIVATE
    ${HNG_COLLECTOR_MOCK_DIR} ${HNG_SOURCE_DIR})
add_test(NAME test_collector_filter_map COMMAND test_collector_filter_map)

# 公共头独立编译：不提供骨架替身或 libbpf 的 include 路径。
add_library(test_collector_public_header OBJECT test_collector_public_header.cc)
target_include_directories(test_collector_public_header PRIVATE ${HNG_SOURCE_DIR})
