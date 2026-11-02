#!/bin/sh
# 把 userver 的安装前缀就位到 $USERVER_PREFIX/prefix，供开发容器内的 CMake 经
# find_package(userver) 消费。
#
# 定位：只负责依赖就位，不参与项目的 CMake 构建，不在仓库内产生任何产物。
#
# 边界：userver 本体（安装前缀约 1G，含两变体；构建目录约 8G）不进镜像，改由本脚本放进
# 命名卷 hng-userver；镜像只提供它的系统依赖（见 .devcontainer/Dockerfile）。故本脚本须在
# 容器内运行，且依赖容器已提供 git / cmake / ninja。
#
# 变体：两个都装。本仓库的 CMake 默认 CMAKE_BUILD_TYPE=Debug，而 userver 的导出配置按该
# 变量在 release/ 与 debug/ 之间二选一（见 userverConfig.cmake），只装一个会让另一种配置
# 直接失败。两变体须同源同选项，否则产物不可互换。
#
# 幂等：默认按 $USERVER_PREFIX/state 下的 version 与 variants 判断，两者都相符即直接退出。
#
# 用法：
#   scripts/install-userver.sh                    从源码构建后安装（需联网，耗时数十分钟）
#   scripts/install-userver.sh --from-seed DIR    从已有的安装前缀播种，不编译
#   scripts/install-userver.sh --force            忽略已就位判断，重做
#   scripts/install-userver.sh --keep-build       保留构建目录（默认安装后删除）
#
# 可覆盖的取值（环境变量）：
#   USERVER_VERSION         默认 3.2            就位判断与源码的 git 标签都用它
#   USERVER_PREFIX          默认 /opt/userver   命名卷挂载点
#   USERVER_GIT_BASE        默认官方仓库        受限网络下指向镜像
#   USERVER_VARIANTS        默认 Release Debug  要构建并校验的变体
#   USERVER_BUILD_PARALLEL  默认 4              构建并行度；userver 的翻译单元较重，
#                                               Debug 变体尤甚，本机 7G 内存下取高会 OOM
#
# 注意事项：
#   * userver 的安装规则整体由 USERVER_INSTALL 开关控制（默认 OFF，见其 cmake/PrepareInstall.cmake），
#     关着时 cmake --install 退出 0 却不装任何文件，故上面必须显式打开。
#   * 从源码构建时 configure 会建 Python venv 并 pip install，故还需能访问 PyPI
#     （PIP_INDEX_URL 可换源）；--from-seed 不走这条路径。
#   * 与 cmake 的接缝是环境变量 userver_ROOT（CMake 的 <PackageName>_ROOT 机制），
#     由 Dockerfile 的 ENV 给出，等于 $USERVER_PREFIX/prefix；改前缀须同步改那处。
#   * 源码目录已存在但非 git 仓库时按原样使用，不克隆也不删除：受限网络下重克隆会失败，
#     删掉重建等于丢掉唯一一份源码。

set -eu

USERVER_VERSION=${USERVER_VERSION:-3.2}
USERVER_PREFIX=${USERVER_PREFIX:-/opt/userver}
USERVER_GIT_BASE=${USERVER_GIT_BASE:-https://github.com/userver-framework/userver.git}
USERVER_VARIANTS=${USERVER_VARIANTS:-Release Debug}
USERVER_BUILD_PARALLEL=${USERVER_BUILD_PARALLEL:-4}

prefix_dir=$USERVER_PREFIX/prefix
src_dir=$USERVER_PREFIX/src/userver
state_dir=$USERVER_PREFIX/state

seed=
force=0
keep_build=0

usage() {
    cat >&2 <<'EOF'
用法：scripts/install-userver.sh [--from-seed DIR] [--force] [--keep-build]

  --from-seed DIR   从已有的 userver 安装前缀播种（DIR 下须有 lib/cmake/userver），不编译
  --force           忽略已就位判断，重做
  --keep-build      保留构建目录（默认安装后删除）
EOF
}

while [ $# -gt 0 ]; do
    case $1 in
        --from-seed) seed=${2:?--from-seed 需要一个目录}; shift 2 ;;
        --from-seed=*) seed=${1#*=}; shift ;;
        --force) force=1; shift ;;
        --keep-build) keep_build=1; shift ;;
        -h | --help) usage; exit 0 ;;
        *)
            echo "未知参数：$1" >&2
            usage
            exit 2
            ;;
    esac
done

if [ -n "$seed" ] && [ ! -d "$seed/lib/cmake/userver" ]; then
    echo "--from-seed 指向的不是 userver 安装前缀（缺 lib/cmake/userver）：$seed" >&2
    exit 2
fi

mkdir -p "$state_dir"

if [ "$force" -eq 0 ] \
    && [ "$(cat "$state_dir/version" 2>/dev/null || true)" = "$USERVER_VERSION" ] \
    && [ "$(cat "$state_dir/variants" 2>/dev/null || true)" = "$USERVER_VARIANTS" ]; then
    echo "userver $USERVER_VERSION（$USERVER_VARIANTS）已就位：$prefix_dir（--force 可重做）"
    exit 0
fi

if [ -n "$seed" ]; then
    echo "从 $seed 播种"
    rm -rf "$prefix_dir"
    mkdir -p "$prefix_dir"
    cp -a "$seed/." "$prefix_dir/"
    record="seed $seed"
else
    command -v ninja >/dev/null 2>&1 || {
        echo "缺 ninja：apt-get install ninja-build" >&2
        exit 1
    }
    mkdir -p "$USERVER_PREFIX/src"
    if [ ! -d "$src_dir" ]; then
        echo "克隆 $USERVER_GIT_BASE（v$USERVER_VERSION）"
        git clone --depth 1 --branch "v$USERVER_VERSION" "$USERVER_GIT_BASE" "$src_dir"
    elif [ ! -d "$src_dir/.git" ]; then
        echo "警告：$src_dir 已存在且非 git 仓库，按原样使用，无法校验是否为 v$USERVER_VERSION" >&2
    fi

    for variant in $USERVER_VARIANTS; do
        build_dir=$USERVER_PREFIX/build-$variant
        echo "构建 userver $USERVER_VERSION（$variant，并行度 $USERVER_BUILD_PARALLEL）"
        cmake -S "$src_dir" -B "$build_dir" -G Ninja \
            -DCMAKE_BUILD_TYPE="$variant" \
            -DCMAKE_INSTALL_PREFIX="$prefix_dir" \
            -DUSERVER_INSTALL=ON \
            -DUSERVER_FORCE_DOWNLOAD_FMT=ON \
            -DUSERVER_BUILD_TESTS=OFF \
            -DUSERVER_BUILD_SAMPLES=OFF \
            -DUSERVER_BUILD_ALL_COMPONENTS=OFF \
            -DUSERVER_DOWNLOAD_PACKAGES=OFF \
            -DUSERVER_FEATURE_CORE=ON \
            -DUSERVER_FEATURE_GRPC=ON \
            -DUSERVER_FEATURE_JEMALLOC=ON \
            -DUSERVER_FEATURE_STACKTRACE=ON
        cmake --build "$build_dir" --parallel "$USERVER_BUILD_PARALLEL"
        cmake --install "$build_dir"
        [ "$keep_build" -eq 1 ] || rm -rf "$build_dir"
    done
    record=build
fi

if [ ! -f "$prefix_dir/lib/cmake/userver/userverConfig.cmake" ]; then
    echo "安装前缀不完整，缺 $prefix_dir/lib/cmake/userver/userverConfig.cmake" >&2
    exit 1
fi

missing=
for variant in $USERVER_VARIANTS; do
    case $variant in
        Release) variant_dir=release ;;
        Debug) variant_dir=debug ;;
        *)
            echo "未知变体：$variant（只支持 Release 与 Debug）" >&2
            exit 2
            ;;
    esac
    [ -d "$prefix_dir/lib/cmake/userver/$variant_dir" ] || missing="$missing $variant"
done
if [ -n "$missing" ]; then
    echo "安装前缀缺变体：$missing。--from-seed 的源前缀须已含它们；否则改用源码构建。" >&2
    exit 1
fi

printf '%s\n' "$USERVER_VERSION" > "$state_dir/version"
printf '%s\n' "$USERVER_VARIANTS" > "$state_dir/variants"
printf '%s\t%s\n' "$(date -Iseconds)" "$record" >> "$state_dir/record"

echo "userver $USERVER_VERSION（$USERVER_VARIANTS）已就位：$prefix_dir"
