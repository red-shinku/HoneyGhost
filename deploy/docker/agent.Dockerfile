# ============================================================
# 节点代理镜像（hng_agent）
#
# 构建上下文是仓库根：
#   docker build -f deploy/docker/agent.Dockerfile -t hng/agent:dev .
#
# 工具链与 userver 来自 builder 镜像（deploy/ci/builder.Dockerfile），
# 本文件只编译仓库源码并组装运行时层。
#
# 运行阶段基于 distroless，不含 shell：该阶段只写 COPY、LABEL、ENTRYPOINT、
# CMD、HEALTHCHECK，出现 RUN 即构建失败。
# ============================================================

ARG BASE_IMAGE=gcr.io/distroless/cc-debian13:latest
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
        -DHNG_TRIM_USERVER_LIBS=ON \
        -DHNG_VERSION="${VERSION}" \
        -DHNG_COMMIT="${COMMIT}" \
        -DHNG_BUILD_DATE="${BUILD_DATE}"

RUN grep -q '^fmt_DIR:PATH=/usr/local/' /build/CMakeCache.txt \
 && grep -q '^spdlog_DIR:PATH=/usr/local/' /build/CMakeCache.txt \
 || { echo "fmt/spdlog not taken from /usr/local, link may fail due to mismatch of fmt version" >&2; exit 1; }

RUN cmake --build /build --target hng_agent --parallel "${BUILD_PARALLEL}"

# 发布镜像不带调试信息：userver 的导出编译选项给全部翻译单元加了 -g，链接后
# DWARF 约占二进制体积的九成。保留 .symtab，backtrace 仍能出函数名；需要行号级
# 调试或性能分析时用本地构建产物（本地构建仍带 DWARF）。
RUN strip --strip-debug /build/hng_agent

RUN test -f /src/kernel/files.skel.h \
 && test -f /src/kernel/syscalls.skel.h \
 && test -f /src/kernel/networks.skel.h \
 && test -f /build/agent/collector/libhng_collector.a

# 运行时库取 ldd 闭包；装配阶段再按内容与基础镜像比对，只保留基础镜像没有的文件。
#
# 落点用目录的真实路径（/lib 指向 usr/lib），文件名保持 ldd 给出的 soname，
# 否则动态加载器找不到 DT_NEEDED 里的名字。
RUN mkdir -p /staging \
 && ldd /build/hng_agent | awk '{ for (i = 1; i <= NF; ++i) if ($i ~ /^\//) print $i }' | sort -u > /tmp/libs.txt \
 && while read -r lib; do \
        dir=$(readlink -f "$(dirname "$lib")"); \
        mkdir -p "/staging$dir"; \
        cp -L "$lib" "/staging$dir/$(basename "$lib")"; \
    done < /tmp/libs.txt

# 只作文件来源，不执行任何命令
FROM ${BASE_IMAGE} AS base-root

# 装配阶段：有 shell，做剪枝、生成加载器缓存、合并运行根并校验
FROM ${BUILDER_IMAGE} AS assemble

COPY --from=base-root / /rootfs/
COPY --from=builder /staging/ /staging/
COPY --from=builder /build/hng_agent /staging/usr/local/bin/hng_agent

# 剪枝：与基础镜像同名同内容（基础镜像为同名符号链接且指向同内容也算）的文件删除
RUN set -eu; \
    : > /tmp/dropped; \
    : > /tmp/kept; \
    : > /tmp/overrides; \
    find /staging -type f | while read -r src; do \
        rel="${src#/staging}"; \
        dst="/rootfs$rel"; \
        if [ -e "$dst" ] && cmp -s "$src" "$dst"; then \
            stat -c '%s' "$src" >> /tmp/dropped; \
            rm -f "$src"; \
        else \
            stat -c '%s' "$src" >> /tmp/kept; \
            if [ -e "$dst" ]; then printf '%s\n' "$rel" >> /tmp/overrides; fi; \
        fi; \
    done; \
    find /staging -mindepth 1 -type d -empty -delete; \
    awk '{ s += $1; n += 1 } END { printf "Skip existing files in the basic image:%d, %d bytes\n", n, s }' /tmp/dropped; \
    awk '{ s += $1; n += 1 } END { printf "Reserved: %d files, %d bytes\n", n, s }' /tmp/kept; \
    if [ -s /tmp/overrides ]; then \
        echo "The following files have the same name as the base image but different content, and will be overwritten by version when linked (the base image may have drifted):"; \
        sed 's/^/  /' /tmp/overrides; \
    fi; \
    rm -f /tmp/dropped /tmp/kept /tmp/overrides

# 加载器缓存须构建期生成：/usr/local/lib 不在默认搜索路径，distroless 不带该缓存；
# 增量与基础镜像在此合并成完整运行根，供 chroot 校验
RUN set -eu; \
    cp -a /staging/. /rootfs/; \
    ldconfig -r /rootfs; \
    mkdir -p /staging/etc /staging/run/honeyghost; \
    cp /rootfs/etc/ld.so.cache /staging/etc/ld.so.cache

# 构建期断言：Boost.Locale 已从链接接口里摘掉（见 CMakeLists.txt），DT_NEEDED 不含 libicu
RUN ! readelf -d /staging/usr/local/bin/hng_agent | grep -q libicu

# 构建期断言：在最终根里跑一次 --version，确认动态加载链路完整
RUN chroot /rootfs /usr/local/bin/hng_agent --version

FROM ${BASE_IMAGE} AS runtime

# 构建来源只作追溯用：VERSION 与构建该镜像使用的 builder digest。
ARG VERSION=dev
ARG BUILDER_DIGEST=unknown

LABEL org.opencontainers.image.title="honeyghost-agent" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.source="https://github.com/red-shinku/HoneyGhost" \
      org.opencontainers.image.licenses="MIT" \
      org.honeyghost.builder-digest="${BUILDER_DIGEST}"

# 增量层：剪枝后的 ldd 闭包、ld.so.cache、/run/honeyghost 与二进制
COPY --from=assemble /staging/ /

# 内建默认配置；部署时可用卷覆盖整个目录
COPY deploy/docker/config/ /etc/honeyghost/

ENTRYPOINT ["/usr/local/bin/hng_agent"]
CMD ["--config", "/etc/honeyghost/agent.conf"]

# 无 shell，健康检查走 agent 自带的开关
HEALTHCHECK --interval=30s --timeout=3s --start-period=60s --retries=3 \
    CMD ["/usr/local/bin/hng_agent", "--health-check"]
