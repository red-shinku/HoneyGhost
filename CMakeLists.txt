cmake_minimum_required(VERSION 3.16)
project(HoneyGhostAgent LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()
add_compile_options(-Wall -Wextra)

# 仓库根目录作为 include 根，统一以 repo-root-relative 形式包含头文件
set(HNG_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR})

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
    agent/semantic/path/path_normalizer.cc
    agent/semantic/path/path_rule.cc
    agent/semantic/path/token_validator.cc
    agent/semantic/semantic_file.cc
    agent/semantic/semantic_syscall.cc
)
target_include_directories(hng_semantic PUBLIC
    ${HNG_SOURCE_DIR}
)
target_link_libraries(hng_semantic PUBLIC hng_event_data)

# ============================================================
# context 派生规则模块
# ============================================================
add_library(hng_context_rule STATIC
    agent/context/rule/derive_types.cc
    agent/context/rule/pending_table.cc
)
target_include_directories(hng_context_rule PUBLIC
    ${HNG_SOURCE_DIR}
)
target_link_libraries(hng_context_rule PUBLIC hng_event_data)

# ============================================================
# 单元测试（表驱动，独立子目录；-DBUILD_TESTING=OFF 可跳过）
# ============================================================
include(CTest)
if(BUILD_TESTING)
    add_subdirectory(test)
endif()
