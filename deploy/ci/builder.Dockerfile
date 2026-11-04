# ============================================================
# 构建工具链镜像
#
# 提供 agent 镜像与 CI 测试作业共用的编译环境：系统依赖、Go、fmt/spdlog
# 与 userver 的 Release/Debug 两变体。userver 只在此处编译一次。
#
#   docker build -f deploy/ci/builder.Dockerfile \
#       -t ghcr.io/red-shinku/honeyghost-builder:latest .
#
# 构建上下文是仓库根；本文件依赖 scripts/ 下的两个依赖安装脚本。
# ============================================================

ARG BASE_IMAGE=debian:13-slim
FROM ${BASE_IMAGE}

ARG DEBIAN_FRONTEND=noninteractive
ARG APT_MIRROR=deb.debian.org
# 须与 scripts/install-userver.sh 的默认版本一致，也是镜像 tag 的组成部分
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

ARG GO_VERSION=1.26.3
ARG GO_DOWNLOAD_BASE=https://go.dev/dl
ARG GO_SHA256_BASE=https://dl.google.com/go
ARG GOPROXY=https://goproxy.cn,direct
# 与 cli/README.md 给出的版本一致；gen.sh 按这两个名字查找插件
ARG PROTOC_GEN_GO_VERSION=1.36.12
ARG PROTOC_GEN_GO_GRPC_VERSION=1.6.2

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
        libgtest-dev libgmock-dev libbenchmark-dev \
        clang-format \
        liburing-dev libyaml-cpp-dev libzstd-dev zlib1g-dev; \
    rm -rf /var/lib/apt/lists/*

# fmt 与 spdlog：与开发容器共用 scripts/install-fmt-spdlog.sh，装到 /usr/local
COPY scripts/install-fmt-spdlog.sh scripts/install-userver.sh /tmp/

RUN FMT_VERSION="${FMT_VERSION}" \
    SPDLOG_VERSION="${SPDLOG_VERSION}" \
    FMT_SOURCE_URL="${FMT_SOURCE_URL}" \
    SPDLOG_SOURCE_URL="${SPDLOG_SOURCE_URL}" \
    BUILD_PARALLEL="${BUILD_PARALLEL}" \
    sh /tmp/install-fmt-spdlog.sh

# 两变体都装：测试用 Debug（CMake 默认），agent 镜像用 Release
RUN set -eux; \
    if [ -n "${PIP_INDEX_URL}" ]; then export PIP_INDEX_URL; else unset PIP_INDEX_URL; fi; \
    USERVER_VERSION="${USERVER_VERSION}" \
    USERVER_GIT_BASE="${USERVER_GIT_BASE}" \
    USERVER_VARIANTS="Release Debug" \
    USERVER_BUILD_PARALLEL="${USERVER_BUILD_PARALLEL}" \
    sh /tmp/install-userver.sh; \
    rm -rf /tmp/install-fmt-spdlog.sh /tmp/install-userver.sh /opt/userver/src

# 官方无 1.26.3 的 deb 包，只能走压缩包；校验值取自 Google 的发布站点
RUN set -eux; \
    file="go${GO_VERSION}.linux-amd64.tar.gz"; \
    curl -fsSL --retry 3 "${GO_DOWNLOAD_BASE}/${file}" -o /tmp/go.tar.gz; \
    curl -fsSL --retry 3 "${GO_SHA256_BASE}/${file}.sha256" -o /tmp/go.sha256; \
    expect="$(cut -d' ' -f1 /tmp/go.sha256)"; \
    actual="$(sha256sum /tmp/go.tar.gz | cut -d' ' -f1)"; \
    [ "${expect}" = "${actual}" ] || { echo "Go 压缩包 SHA256 不匹配：期望 ${expect}，实际 ${actual}" >&2; exit 1; }; \
    tar -C /usr/local -xzf /tmp/go.tar.gz; \
    rm -f /tmp/go.tar.gz /tmp/go.sha256; \
    ln -sf /usr/local/go/bin/go /usr/local/bin/go; \
    ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt

# 协议代码生成插件：make go-cli 与 make test-go 都会经 cli/gen.sh 调用
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@v${PROTOC_GEN_GO_VERSION} \
 && go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v${PROTOC_GEN_GO_GRPC_VERSION} \
 && cp /root/go/bin/protoc-gen-go /root/go/bin/protoc-gen-go-grpc /usr/local/bin/

# userver 的配置阶段与本仓库的配置都要取 /usr/local 的 fmt/spdlog
ENV CMAKE_PREFIX_PATH=/usr/local
# find_package(userver) 经 CMake 的 <PackageName>_ROOT 机制读这个变量
ENV userver_ROOT=/opt/userver/prefix
ENV PATH=/usr/local/go/bin:${PATH}
ENV GOPROXY=${GOPROXY}
ENV LANG=C.UTF-8

LABEL org.opencontainers.image.title="honeyghost-builder" \
      org.opencontainers.image.description="HoneyGhost 构建工具链（含 userver 与 Go）" \
      org.opencontainers.image.source="https://github.com/red-shinku/HoneyGhost" \
      org.opencontainers.image.licenses="MIT"

WORKDIR /src
