# ============================================================
# 节点代理镜像（hng_agent）
#
# 构建上下文是仓库根：
#   docker build -f deploy/docker/agent.Dockerfile -t hng/agent:dev .
# ============================================================

ARG BASE_IMAGE=debian:13-slim

FROM ${BASE_IMAGE} AS builder

ARG DEBIAN_FRONTEND=noninteractive
ARG APT_MIRROR=deb.debian.org
# 须与 scripts/install-userver.sh 的默认版本一致
ARG USERVER_VERSION=3.2
ARG USERVER_GIT_BASE=https://github.com/userver-framework/userver.git
ARG USERVER_BUILD_PARALLEL=4
ARG BUILD_PARALLEL=4
# 可选：userver 配置阶段建 venv 时用的 pip 源
ARG PIP_INDEX_URL=

# userver 3.x 要求 fmt 11，而 Debian 13 只有 fmt 10；系统的 spdlog 又是按
# fmt 10 编译的，两者混进同一次链接就会报未定义符号。故 fmt 与 spdlog 都
# 从源码装到 /usr/local，并且不安装系统的 -dev 包。
ARG FMT_VERSION=11.1.4
ARG SPDLOG_VERSION=1.15.3
ARG FMT_SOURCE_URL=https://github.com/fmtlib/fmt/archive/refs/tags/${FMT_VERSION}.tar.gz
ARG SPDLOG_SOURCE_URL=https://github.com/gabime/spdlog/archive/refs/tags/v${SPDLOG_VERSION}.tar.gz

RUN set -eux; \
    if [ "${APT_MIRROR}" != "deb.debian.org" ]; then \
        sed -i "s|deb\.debian\.org|${APT_MIRROR}|g" /etc/apt/sources.list.d/debian.sources; \
    fi; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        build-essential cmake ninja-build pkg-config \
        python3 python3-dev python3-venv \
        git ca-certificates curl \
        clang bpftool libbpf-dev libsystemd-dev \
        protobuf-compiler libprotobuf-dev libprotoc-dev \
        libgrpc-dev libgrpc++-dev protobuf-compiler-grpc \
        libboost-dev libboost-context-dev libboost-coroutine-dev \
        libboost-filesystem-dev libboost-iostreams-dev libboost-locale-dev \
        libboost-program-options-dev libboost-stacktrace-dev \
        libc-ares-dev libcctz-dev libcrypto++-dev libcurl4-openssl-dev \
        libev-dev libjemalloc-dev libkrb5-dev libldap2-dev \
        liblzma-dev libnghttp2-dev libre2-dev libssl-dev \
        libgtest-dev \
        libgmock-dev \
        libbenchmark-dev \
        clang-format \
        liburing-dev libyaml-cpp-dev libzstd-dev zlib1g-dev; \
    rm -rf /var/lib/apt/lists/*

RUN test -r /sys/kernel/btf/vmlinux || { \
        echo "cannot find /sys/kernel/btf/vmlinux: eBPF probes need it" >&2; \
        exit 1; }

# fmt 与 spdlog：与开发容器共用 scripts/install-fmt-spdlog.sh，装到 /usr/local
COPY scripts/install-fmt-spdlog.sh /tmp/install-fmt-spdlog.sh
RUN FMT_VERSION="${FMT_VERSION}" \
    SPDLOG_VERSION="${SPDLOG_VERSION}" \
    FMT_SOURCE_URL="${FMT_SOURCE_URL}" \
    SPDLOG_SOURCE_URL="${SPDLOG_SOURCE_URL}" \
    BUILD_PARALLEL="${BUILD_PARALLEL}" \
    sh /tmp/install-fmt-spdlog.sh

# userver 的配置阶段与本仓库的配置都要取 /usr/local 的 fmt/spdlog
ENV CMAKE_PREFIX_PATH=/usr/local

# 先只拷用户态依赖的就位脚本：这一层不随源码改动失效
COPY scripts/install-userver.sh /src/scripts/install-userver.sh
RUN set -eux; \
    if [ -n "${PIP_INDEX_URL}" ]; then export PIP_INDEX_URL; else unset PIP_INDEX_URL; fi; \
    USERVER_VERSION="${USERVER_VERSION}" \
    USERVER_GIT_BASE="${USERVER_GIT_BASE}" \
    USERVER_VARIANTS=Release \
    USERVER_BUILD_PARALLEL="${USERVER_BUILD_PARALLEL}" \
    sh /src/scripts/install-userver.sh

# find_package(userver) 经 CMake 的 <PackageName>_ROOT 机制读这个变量
ENV userver_ROOT=/opt/userver/prefix

WORKDIR /src
COPY . /src

RUN cmake -S /src -B /build \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_TESTING=OFF

RUN grep -q '^fmt_DIR:PATH=/usr/local/' /build/CMakeCache.txt \
 && grep -q '^spdlog_DIR:PATH=/usr/local/' /build/CMakeCache.txt \
 || { echo "fmt/spdlog 未取自 /usr/local，链接会因 fmt 版本错配失败" >&2; exit 1; }

RUN cmake --build /build --target hng_agent --parallel "${BUILD_PARALLEL}"

RUN test -f /src/kernel/files.skel.h \
 && test -f /src/kernel/syscalls.skel.h \
 && test -f /src/kernel/networks.skel.h \
 && test -f /build/agent/collector/libhng_collector.a

# 运行时库取 ldd 闭包：运行阶段与构建阶段是同一基础镜像，复制来的库与
# 链接时使用的完全一致，运行阶段因此不必再按包名列一遍依赖。
#
# 落点用目录的真实路径（/lib 是 usr/lib 的符号链接，直接按原路径复制会
# 让 COPY 撞上符号链接），文件名保持 ldd 给出的 soname，否则动态加载器
# 找不到 DT_NEEDED 里的名字。
RUN mkdir -p /staging \
 && ldd /build/hng_agent | awk '{ for (i = 1; i <= NF; ++i) if ($i ~ /^\//) print $i }' | sort -u > /tmp/libs.txt \
 && while read -r lib; do \
        dir=$(readlink -f "$(dirname "$lib")"); \
        mkdir -p "/staging$dir"; \
        cp -L "$lib" "/staging$dir/$(basename "$lib")"; \
    done < /tmp/libs.txt

FROM ${BASE_IMAGE} AS runtime

# 运行时共享库与动态加载器一并来自构建阶段，不在此处安装任何包
COPY --from=builder /staging/ /
COPY --from=builder /build/hng_agent /usr/local/bin/hng_agent

# 内建默认配置；部署时可用卷覆盖整个目录
COPY deploy/docker/config/ /etc/honeyghost/

# CLI 服务端与 containerd 桥接 socket 的父目录；运行期通常由卷覆盖
RUN mkdir -p /run/honeyghost

# fmt/spdlog 落在 /usr/local/lib，登记进动态加载器缓存
RUN ldconfig

# 缺库在构建期就失败，而不是运行期报 "libxxx.so not found"
RUN ! ldd /usr/local/bin/hng_agent | grep -q 'not found'

# eBPF 加载需要 root（bpf(2) 与熔断的 memlock 调整），不做降权
ENTRYPOINT ["/usr/local/bin/hng_agent"]
CMD ["--config", "/etc/honeyghost/agent.conf"]

# 就绪判据：CLI 服务端的 Unix socket 已建立
HEALTHCHECK --interval=30s --timeout=3s --start-period=60s --retries=3 \
    CMD test -S /run/honeyghost/cli.sock
