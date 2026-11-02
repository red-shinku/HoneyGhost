# 用户态角色过滤只依赖公共头与线程库，不修改控制平面实现。
find_package(Threads REQUIRED)
add_library(hng_role_filter STATIC
    src/role_filter_config.cc
    src/role_filter_policy.cc
    src/process_filter_map.cc
    src/process_liveness.cc
    src/role_filter.cc
    src/role_filter_component.cc)
target_include_directories(hng_role_filter PUBLIC ${HNG_SOURCE_DIR})
target_link_libraries(hng_role_filter PUBLIC Threads::Threads)
