# ============================================================
# 装配层
#
# 目前只有 /proc 快照读取器；初始化协调器与各组件初始化器在后续阶段接入。
# ============================================================
add_library(hng_assembly STATIC
    src/assembly.cc
    src/proc_snapshot.cc
)
target_include_directories(hng_assembly PUBLIC
    ${HNG_SOURCE_DIR}
)
