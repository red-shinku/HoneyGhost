# ============================================================
# 节点代理镜像（hng_agent）
#
# 构建上下文是仓库根：
#   docker build -f deploy/docker/agent.Dockerfile -t hng/agent:dev .
#
# 工具链与 userver 来自 builder 镜像（deploy/ci/builder.Dockerfile），
# 本文件只编译仓库源码并组装运行时层。
# ============================================================

ARG BASE_IMAGE=debian:13-slim
ARG BUILDER_IMAGE=ghcr.io/red-shinku/honeyghost-builder:latest

FROM ${BUILDER_IMAGE} AS builder

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
ARG BUILD_PARALLEL=4

# eBPF 探针的 CO-RE 重定位依赖构建机的 BTF；缺它时骨架会静默沿用旧内容
RUN test -r /sys/kernel/btf/vmlinux || { \
        echo "cannot find /sys/kernel/btf/vmlinux: eBPF probes need it" >&2; \
        exit 1; }

WORKDIR /src
COPY . /src

RUN cmake -S /src -B /build \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_TESTING=OFF \
        -DHNG_VERSION="${VERSION}" \
        -DHNG_COMMIT="${COMMIT}" \
        -DHNG_BUILD_DATE="${BUILD_DATE}"

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

# 构建来源只作追溯用：VERSION 与构建该镜像使用的 builder digest。
ARG VERSION=dev
ARG BUILDER_DIGEST=unknown

LABEL org.opencontainers.image.title="honeyghost-agent" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.source="https://github.com/red-shinku/HoneyGhost" \
      org.opencontainers.image.licenses="MIT" \
      org.honeyghost.builder-digest="${BUILDER_DIGEST}"

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
