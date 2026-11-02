#!/bin/sh
# 把 fmt 与 spdlog 装到同一前缀，供 userver 与 hng_agent 链接同一份。
#
# 动机：userver 3.x 的 cmake/SetupFmt.cmake 固定 fmt 11.1.4，而 Debian 13 只有
# fmt 10；发行版的 spdlog 又按 fmt 10 编译。三者混进同一次链接会在链接
# hng_agent 时报未定义符号，故 fmt 与 spdlog 一律源码安装，且不安装系统的
# libfmt-dev / libspdlog-dev。
#
# 用法：
#   sh scripts/install-fmt-spdlog.sh [--force]
#
# 可覆盖的取值（环境变量）：
#   FMT_VERSION        默认 11.1.4  须与 userver 的 SetupFmt.cmake 一致
#   SPDLOG_VERSION     默认 1.15.3
#   FMT_SOURCE_URL     默认 fmt 的 GitHub 归档（fmt 的 release 只发 .zip）
#   SPDLOG_SOURCE_URL  默认 spdlog 的 GitHub 归档
#   PREFIX             默认 /usr/local
#   BUILD_PARALLEL     默认 4
#
# 注意：
#   * spdlog 以 SPDLOG_FMT_EXTERNAL=ON 编译，复用上面那份 fmt，不内嵌一份。
#   * PREFIX 为 /usr/local 时末尾执行 ldconfig；其它前缀须自行让动态加载器
#     找到库文件。
set -eu

FMT_VERSION=${FMT_VERSION:-11.1.4}
SPDLOG_VERSION=${SPDLOG_VERSION:-1.15.3}
FMT_SOURCE_URL=${FMT_SOURCE_URL:-https://github.com/fmtlib/fmt/archive/refs/tags/${FMT_VERSION}.tar.gz}
SPDLOG_SOURCE_URL=${SPDLOG_SOURCE_URL:-https://github.com/gabime/spdlog/archive/refs/tags/v${SPDLOG_VERSION}.tar.gz}
PREFIX=${PREFIX:-/usr/local}
BUILD_PARALLEL=${BUILD_PARALLEL:-4}

force=0
case "${1:-}" in
    --force) force=1 ;;
    -h | --help)
        sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'
        exit 0
        ;;
    '') ;;
    *)
        echo "未知参数：$1" >&2
        exit 2
        ;;
esac

state_file=$PREFIX/share/hng/fmt-spdlog
stamp="$FMT_VERSION $SPDLOG_VERSION"
if [ "$force" -eq 0 ] && [ "$(cat "$state_file" 2>/dev/null || true)" = "$stamp" ]; then
    echo "fmt $FMT_VERSION 与 spdlog $SPDLOG_VERSION 已就位：$PREFIX（--force 可重做）"
    exit 0
fi

work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT

echo "安装 fmt $FMT_VERSION 到 $PREFIX"
curl -fsSL "$FMT_SOURCE_URL" -o "$work_dir/fmt.tar.gz"
mkdir -p "$work_dir/fmt"
tar -xzf "$work_dir/fmt.tar.gz" -C "$work_dir/fmt" --strip-components=1
cmake -S "$work_dir/fmt" -B "$work_dir/fmt/build" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$PREFIX" \
    -DBUILD_SHARED_LIBS=ON \
    -DFMT_TEST=OFF -DFMT_DOC=OFF
cmake --build "$work_dir/fmt/build" --parallel "$BUILD_PARALLEL"
cmake --install "$work_dir/fmt/build"

echo "安装 spdlog $SPDLOG_VERSION 到 $PREFIX（external fmt）"
curl -fsSL "$SPDLOG_SOURCE_URL" -o "$work_dir/spdlog.tar.gz"
mkdir -p "$work_dir/spdlog"
tar -xzf "$work_dir/spdlog.tar.gz" -C "$work_dir/spdlog" --strip-components=1
cmake -S "$work_dir/spdlog" -B "$work_dir/spdlog/build" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$PREFIX" \
    -DCMAKE_PREFIX_PATH="$PREFIX" \
    -DSPDLOG_BUILD_SHARED=ON \
    -DSPDLOG_FMT_EXTERNAL=ON \
    -DSPDLOG_BUILD_EXAMPLE=OFF -DSPDLOG_BUILD_TESTS=OFF
cmake --build "$work_dir/spdlog/build" --parallel "$BUILD_PARALLEL"
cmake --install "$work_dir/spdlog/build"

if [ ! -f "$PREFIX/lib/cmake/fmt/fmt-config.cmake" ]; then
    echo "安装前缀不完整，缺 fmt 的 CMake 配置：$PREFIX" >&2
    exit 1
fi
if [ ! -f "$PREFIX/lib/cmake/spdlog/spdlogConfig.cmake" ]; then
    echo "安装前缀不完整，缺 spdlog 的 CMake 配置：$PREFIX" >&2
    exit 1
fi

if [ "$PREFIX" = /usr/local ]; then
    ldconfig
fi

mkdir -p "$(dirname "$state_file")"
printf '%s\n' "$stamp" > "$state_file"

echo "fmt $FMT_VERSION 与 spdlog $SPDLOG_VERSION 已就位：$PREFIX"
