# 可独立构建名单模块；不依赖 protobuf/systemd/libbpf。
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    cmake_minimum_required(VERSION 3.16)
    project(HoneyGhostRoleFilter LANGUAGES CXX)
    set(CMAKE_CXX_STANDARD 17)
    set(CMAKE_CXX_STANDARD_REQUIRED ON)
    get_filename_component(HNG_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)
    include(CTest)
endif()

find_package(Threads REQUIRED)
add_library(hng_role_filter STATIC
    src/role_filter_config.cc
    src/role_filter_policy.cc
    src/role_filter.cc
    src/process_liveness.cc
    src/process_filter_map.cc
)
target_include_directories(hng_role_filter PUBLIC ${HNG_SOURCE_DIR})
target_compile_features(hng_role_filter PUBLIC cxx_std_17)
target_link_libraries(hng_role_filter PUBLIC Threads::Threads)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR AND BUILD_TESTING)
    add_executable(test_role_filter ${HNG_SOURCE_DIR}/test/test_role_filter.cc)
    target_link_libraries(test_role_filter PRIVATE hng_role_filter)
    add_test(NAME test_role_filter COMMAND test_role_filter)
    set_tests_properties(test_role_filter PROPERTIES WORKING_DIRECTORY ${HNG_SOURCE_DIR})
endif()
