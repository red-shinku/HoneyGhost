cmake_minimum_required(VERSION 3.16)
project(HoneyGhostAgent LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
# 供 clangd 等语言服务器使用：导出编译数据库到构建目录
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()
add_compile_options(-Wall -Wextra)

# 仓库根目录作为 include 根，统一以 repo-root-relative 形式包含头文件
set(HNG_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR})

# ============================================================
# eBPF 探针与骨架
#
# 不依赖任何 C++ 目标，产物落源码树；clang / bpftool 缺失时整个子目录为空目标。
# ============================================================
add_subdirectory(kernel)

# ============================================================
# 事件数据结构：proto 生成载荷 + 手写组合结构
#   proto/file_event.proto   → ${PROTO_GEN_DIR}/file_event.pb.{h,cc}
#   proto/syscall_event.proto → ${PROTO_GEN_DIR}/syscall_event.pb.{h,cc}
# ============================================================
find_package(Protobuf REQUIRED)
set(PROTO_GEN_DIR ${CMAKE_BINARY_DIR}/generated/event_data)
file(MAKE_DIRECTORY ${PROTO_GEN_DIR})

# 载荷由 proto 生成；手写 file_event.hpp / syscall_event.hpp 为 header-only
add_library(hng_event_data STATIC)
target_include_directories(hng_event_data PUBLIC
    ${PROTO_GEN_DIR}
    ${HNG_SOURCE_DIR}
)
target_link_libraries(hng_event_data PUBLIC protobuf::libprotobuf)
protobuf_generate(TARGET hng_event_data LANGUAGE cpp
    PROTOS proto/file_event.proto
          proto/syscall_event.proto
    IMPORT_DIRS ${HNG_SOURCE_DIR}/proto
    PROTOC_OUT_DIR ${PROTO_GEN_DIR}
)

# ============================================================
# 语义化模块
# ============================================================
add_library(hng_semantic STATIC
    agent/semantic/src/path/path_normalizer.cc
    agent/semantic/src/path/path_rule.cc
    agent/semantic/src/path/token_validator.cc
    agent/semantic/src/semantic_file.cc
    agent/semantic/src/semantic_syscall.cc
)
target_include_directories(hng_semantic PUBLIC
    ${HNG_SOURCE_DIR}
)
target_link_libraries(hng_semantic PUBLIC hng_event_data)

# ============================================================
# context 派生规则模块
# ============================================================
add_library(hng_context_rule STATIC
    agent/context_maintainer/src/rule/derive_types.cc
    agent/context_maintainer/src/rule/pending_table.cc
)
target_include_directories(hng_context_rule PUBLIC
    ${HNG_SOURCE_DIR}
)
target_link_libraries(hng_context_rule PUBLIC hng_event_data)

# ============================================================
# context 维护模块（ContextMaintainer，消费 rule 派生规则，经 ContextService 接入）
# ============================================================
add_library(hng_context_maintainer STATIC
    agent/context_maintainer/src/context_maintainer.cc
)
target_include_directories(hng_context_maintainer PUBLIC
    ${HNG_SOURCE_DIR}
)
target_link_libraries(hng_context_maintainer PUBLIC
    hng_context_rule
    hng_event_data
)

# ============================================================
# 角色发现模块（公共骨架：状态表与 cgroup 读取）
#
# 无第三方依赖，也不链接 hng_event_data——锚点类型 hng::Process 所在的
# agent/event_data/include/process.hpp 是 header-only 且只依赖 <cstdint>。
# 各发现源按源再配一个 STATIC 库（libsystemd / gRPC）。
# ============================================================
add_library(hng_role_discovery STATIC
    agent/role_discovery/src/role_signal_table.cc
    agent/role_discovery/src/role_cgroup_reader.cc
)
target_include_directories(hng_role_discovery PUBLIC
    ${HNG_SOURCE_DIR}
)

# ============================================================
# systemd 角色发现源（sd-bus）
#
# libsystemd 不可用时只跳过本目标，不使整体构建失败——纯 k8s 节点上不装
# libsystemd-dev 是常见情况。探测先走 pkg-config，退回 find_path/find_library。
# ============================================================
option(HNG_ENABLE_ROLE_SYSTEMD "构建 systemd 角色发现器（需 libsystemd-dev）" ON)
if(HNG_ENABLE_ROLE_SYSTEMD)
    set(HNG_SYSTEMD_DEP "")
    find_package(PkgConfig QUIET)
    if(PKG_CONFIG_FOUND)
        pkg_check_modules(SYSTEMD QUIET IMPORTED_TARGET libsystemd)
        if(TARGET PkgConfig::SYSTEMD)
            set(HNG_SYSTEMD_DEP PkgConfig::SYSTEMD)
        endif()
    endif()

    if(NOT HNG_SYSTEMD_DEP)
        find_path(SYSTEMD_INCLUDE_DIR systemd/sd-bus.h)
        find_library(SYSTEMD_LIBRARY systemd)
        if(SYSTEMD_INCLUDE_DIR AND SYSTEMD_LIBRARY)
            add_library(hng_systemd_dep UNKNOWN IMPORTED)
            set_target_properties(hng_systemd_dep PROPERTIES
                IMPORTED_LOCATION "${SYSTEMD_LIBRARY}"
                INTERFACE_INCLUDE_DIRECTORIES "${SYSTEMD_INCLUDE_DIR}"
            )
            set(HNG_SYSTEMD_DEP hng_systemd_dep)
        endif()
    endif()

    if(HNG_SYSTEMD_DEP)
        add_library(hng_role_systemd STATIC
            agent/role_discovery/src/role_systemd_discoverer.cc
        )
        target_include_directories(hng_role_systemd PUBLIC
            ${HNG_SOURCE_DIR}
        )
        target_link_libraries(hng_role_systemd
            PUBLIC hng_role_discovery
            PRIVATE ${HNG_SYSTEMD_DEP}
        )
    else()
        message(STATUS "libsystemd 未找到，跳过 hng_role_systemd")
    endif()
endif()

# ============================================================
# containerd 角色发现源（经翻译进程，无 gRPC）
#
# C++ 侧只连翻译进程的 Unix socket，协议 .proto 由本仓库双端生成：C++ 侧在
# 构建时生成，Go 侧产物入库（见 agent/role_discovery/containerd_bridge/gen.sh）。
# 翻译进程的构建不接 CMake，见 agent/role_discovery/containerd_bridge/README.md。
# ============================================================
option(HNG_ENABLE_ROLE_CONTAINERD "构建 containerd 角色发现器（需 protobuf）" ON)
if(HNG_ENABLE_ROLE_CONTAINERD)
    set(ROLE_BRIDGE_GEN_DIR ${CMAKE_BINARY_DIR}/generated/role_bridge)
    file(MAKE_DIRECTORY ${ROLE_BRIDGE_GEN_DIR})

    add_library(hng_role_containerd STATIC
        agent/role_discovery/src/role_containerd_discoverer.cc
    )
    target_include_directories(hng_role_containerd PUBLIC
        ${HNG_SOURCE_DIR}
        ${ROLE_BRIDGE_GEN_DIR}
    )
    # 生成物头文件自身包含 protobuf 头，故 protobuf 是公开依赖：
    # 单测要构造真实帧来验解码
    target_link_libraries(hng_role_containerd
        PUBLIC hng_role_discovery
               protobuf::libprotobuf
    )
    protobuf_generate(TARGET hng_role_containerd LANGUAGE cpp
        PROTOS proto/role_containerd_bridge.proto
        IMPORT_DIRS ${HNG_SOURCE_DIR}/proto
        PROTOC_OUT_DIR ${ROLE_BRIDGE_GEN_DIR}
    )
endif()

# ============================================================
# 控制平面（角色关系表 + 角色管理器）
#
# 依赖角色发现公共骨架（RoleEvent / RolePayload 类型与 RoleCgroupReader）。
# 目前只纳入本组件的两个 .cc，ProcessManager / ContextManager 尚未进 CMake。
# ============================================================
add_library(hng_control_plane STATIC
    agent/control_plane/src/role_label_builder.cc
    agent/control_plane/src/role_manager.cc
    agent/control_plane/src/role_relation_store.cc
)
target_include_directories(hng_control_plane PUBLIC
    ${HNG_SOURCE_DIR}
)
target_link_libraries(hng_control_plane PUBLIC hng_role_discovery)

# ============================================================
# 控制平面（进程管理器）
#
# 只依赖 event_data 与两个服务接口（均 header-only），不含 ContextManager。
# ============================================================
add_library(hng_process_manager STATIC
    agent/control_plane/src/process_manager.cc
)
target_include_directories(hng_process_manager PUBLIC
    ${HNG_SOURCE_DIR}
)

# ============================================================
# 控制平面（上下文管理器）
#
# 只依赖 event_data 与 context 服务接口（均 header-only）；
# 工作平面的 ContextMaintainer 不在本目标内。
# ============================================================
add_library(hng_context_manager STATIC
    agent/control_plane/src/context_manager.cc
    agent/control_plane/src/context_store.cc
)
target_include_directories(hng_context_manager PUBLIC
    ${HNG_SOURCE_DIR}
)

# ============================================================
# 运行时引擎（语义事件流的分发中枢）
#
# 依赖 event_data 的事件契约（含 proto 生成物）、context_maintainer 的派生决策
# 与控制平面的两个服务接口（header-only）。本模块对外接口在 include/，实现细节
# 在 src/。
# ============================================================
add_library(hng_runtime_engine STATIC
    agent/runtime_engine/src/runtime_engine.cc
    agent/runtime_engine/src/runtime_event_dispatcher.cc
    agent/runtime_engine/src/runtime_packaging.cc
    agent/runtime_engine/src/runtime_pipeline.cc
)
target_include_directories(hng_runtime_engine PUBLIC
    ${HNG_SOURCE_DIR}
)
target_link_libraries(hng_runtime_engine PUBLIC
    hng_context_maintainer
    hng_event_data
)

# ============================================================
# CLI 服务端
# ============================================================
option(HNG_ENABLE_CLI_SERVER "构建 CLI 服务端模块（需 userver）" ON)
if(HNG_ENABLE_CLI_SERVER)
    # 临时抬 c++ 标准
    set(HNG_CXX_STANDARD_SAVED "${CMAKE_CXX_STANDARD}")
    set(CMAKE_CXX_STANDARD 20)
    get_property(HNG_COMPILE_OPTIONS_SAVED DIRECTORY PROPERTY COMPILE_OPTIONS)

    find_package(userver QUIET COMPONENTS core grpc)

    set(CMAKE_CXX_STANDARD "${HNG_CXX_STANDARD_SAVED}")

    set(CMAKE_CXX_STANDARD "${HNG_CXX_STANDARD_SAVED}")
    unset(CMAKE_CXX_EXTENSIONS)             # userver 置 OFF；本项目未使用该变量
    unset(CMAKE_VISIBILITY_INLINES_HIDDEN)  # userver 置 ON；同上
    set_property(DIRECTORY PROPERTY COMPILE_OPTIONS "${HNG_COMPILE_OPTIONS_SAVED}")
    unset(HNG_CXX_STANDARD_SAVED)
    unset(HNG_COMPILE_OPTIONS_SAVED)

    if(NOT userver_FOUND)
        message(FATAL_ERROR
            "未找到 userver（find_package(userver COMPONENTS core grpc) 失败）。\n"
            "  容器内：先执行 scripts/install-userver.sh，见 .devcontainer/README.md 第 3 节\n"
            "  容器外：给 -Duserver_ROOT=<userver 安装前缀>，或设同名环境变量\n"
            "  只想要其余模块：-DHNG_ENABLE_CLI_SERVER=OFF")
    endif()

    add_subdirectory(agent/cli_server)
endif()

# ============================================================
# 单元测试（表驱动，独立子目录；-DBUILD_TESTING=OFF 可跳过）
# ============================================================
include(CTest)
if(BUILD_TESTING)
    add_subdirectory(test)
endif()
