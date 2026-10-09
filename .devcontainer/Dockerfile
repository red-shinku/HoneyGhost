# ============================================================
# 开发容器工具链镜像
# ============================================================

# 基础镜像可覆盖，供内网以同发行版同版本的副本代用时使用
ARG BASE_IMAGE=debian:13-slim
FROM ${BASE_IMAGE}

ARG DEBIAN_FRONTEND=noninteractive

# 供 BuildKit 之外的构建器兜底：未定义时 Go 下载地址会拼错
ARG TARGETARCH=amd64

# 官方无 1.26.3 的 deb 包，只能走压缩包
ARG GO_VERSION=1.26.3

# 须与宿主开发机一致，否则绑定挂载的工作区在宿主侧归属错误
ARG USERNAME=dev
ARG USER_UID=1000
ARG USER_GID=1000

# apt 源主机名可覆盖，逐档兜底：APT_MIRROR → APT_MIRROR_FALLBACK → 官方源
ARG APT_MIRROR=deb.debian.org
ARG APT_MIRROR_FALLBACK=

# 工具链与系统依赖。
#
# --error-on=any 不可省：默认语义下源全部不可达时 apt-get update 仍退出 0，
# 兜底形同虚设。每轮从原文件重生成，故上一档的替换不会累积到下一档。
RUN set -eux; \
    src=/etc/apt/sources.list.d/debian.sources; \
    cp "$src" /tmp/debian.sources.orig; \
    ok=''; \
    for m in "${APT_MIRROR}" "${APT_MIRROR_FALLBACK}" deb.debian.org; do \
        [ -n "$m" ] || continue; \
        sed "s|deb\.debian\.org|$m|g" /tmp/debian.sources.orig > "$src"; \
        if apt-get update --error-on=any; then ok="$m"; break; fi; \
        echo "apt 源 $m 不可用，尝试下一档"; \
    done; \
    [ -n "$ok" ] || { echo "所有 apt 源均不可用" >&2; exit 1; }; \
    echo "apt 源已选用：$ok"; \
    apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
        ninja-build \
        ccache \
        python3 \
        python3-dev \
        python3-venv \
        clang \
        clang-format-19 \
        clang-tidy-19 \
        clangd-19 \
        bpftool \
        libbpf-dev \
        libsystemd-dev \
        pkg-config \
        git \
        ca-certificates \
        curl \
        sudo \
        gdb \
        less \
        vim \
        protobuf-compiler \
        libprotobuf-dev \
        libprotoc-dev \
        libgrpc-dev \
        libgrpc++-dev \
        protobuf-compiler-grpc \
        libboost-dev \
        libboost-context-dev \
        libboost-coroutine-dev \
        libboost-filesystem-dev \
        libboost-iostreams-dev \
        libboost-locale-dev \
        libboost-program-options-dev \
        libboost-stacktrace-dev \
        libbenchmark-dev \
        libc-ares-dev \
        libcctz-dev \
        libcrypto++-dev \
        libcurl4-openssl-dev \
        libev-dev \
        libfmt-dev \
        libgmock-dev \
        libgtest-dev \
        libjemalloc-dev \
        libkrb5-dev \
        libldap2-dev \
        liblzma-dev \
        libnghttp2-dev \
        libre2-dev \
        libssl-dev \
        liburing-dev \
        libyaml-cpp-dev \
        libzstd-dev \
        zlib1g-dev \
        netbase; \
    rm -rf /var/lib/apt/lists/*

# Go 下载源同样逐档兜底，语义与上面的 apt 源一致
ARG GO_DOWNLOAD_BASE=https://go.dev/dl
ARG GO_DOWNLOAD_FALLBACK=

# GO_SHA256 非空则直接用作期望值，不联网取；其值为 none 则跳过校验
ARG GO_SHA256=
ARG GO_SHA256_BASE=https://dl.google.com/go

# 装 Go 工具链。
RUN set -eux; \
    file="go${GO_VERSION}.linux-${TARGETARCH}.tar.gz"; \
    ok=''; \
    for b in "${GO_DOWNLOAD_BASE}" "${GO_DOWNLOAD_FALLBACK}" https://go.dev/dl; do \
        [ -n "$b" ] || continue; \
        if curl -fsSL "$b/$file" -o /tmp/go.tar.gz && tar -tzf /tmp/go.tar.gz > /dev/null 2>&1; then \
            ok="$b"; break; \
        fi; \
        echo "Go 下载源 $b 不可用，尝试下一档"; \
    done; \
    [ -n "$ok" ] || { echo "所有 Go 下载源均不可用" >&2; exit 1; }; \
    echo "Go 下载源已选用：$ok"; \
    if [ "$GO_SHA256" = none ]; then \
        echo "警告：GO_SHA256=none，已跳过 Go 压缩包的完整性校验" >&2; \
    else \
        expect="$GO_SHA256"; \
        if [ -z "$expect" ]; then \
            curl -fsSL "${GO_SHA256_BASE}/${file}.sha256" -o /tmp/go.sha256 \
                || { echo "无法从 ${GO_SHA256_BASE} 取校验文件。" >&2; \
                     echo "可用 --build-arg GO_SHA256=<hash> 指定期望值，" >&2; \
                     echo "或以 --build-arg GO_SHA256=none 跳过校验。" >&2; \
                     exit 1; }; \
            expect=$(cut -d' ' -f1 < /tmp/go.sha256); \
            case "$expect" in \
                *[!0-9a-f]*|'') \
                    echo "取自 ${GO_SHA256_BASE} 的校验值不是十六进制串，多半落到了 HTML 页面：$expect" >&2; \
                    exit 1;; \
            esac; \
        fi; \
        actual=$(sha256sum /tmp/go.tar.gz | cut -d' ' -f1); \
        [ "$expect" = "$actual" ] \
            || { echo "Go 压缩包 SHA256 不匹配：期望 $expect，实际 $actual" >&2; exit 1; }; \
        echo "Go 压缩包 SHA256 校验通过：$actual"; \
    fi; \
    tar -C /usr/local -xzf /tmp/go.tar.gz; \
    rm -f /tmp/go.tar.gz /tmp/go.sha256

# 不设则部分网络下 make go 必 i/o timeout
ARG GOPROXY=https://goproxy.cn,direct
ENV GOPROXY=${GOPROXY}

# 建用户与 sudo 免密，并预建命名卷的挂载点、归属 dev。
# 命名卷首次挂载继承镜像中该路径的归属，未预建则会以 root 新建，容器内写入失败。
# 两个 Go 目录在 $HOME 下，由末尾的 chown -R 覆盖；/opt/userver 不在其下，单独 chown。
RUN groupadd --gid ${USER_GID} ${USERNAME} \
    && useradd --uid ${USER_UID} --gid ${USER_GID} --create-home --shell /bin/bash ${USERNAME} \
    && echo "${USERNAME} ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/${USERNAME} \
    && chmod 0440 /etc/sudoers.d/${USERNAME} \
    && mkdir -p /home/${USERNAME}/go/pkg/mod /home/${USERNAME}/.cache/go-build \
    && chown -R ${USER_UID}:${USER_GID} /home/${USERNAME} \
    && mkdir -p /opt/userver \
    && chown ${USER_UID}:${USER_GID} /opt/userver

ENV LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    PATH=/usr/local/go/bin:/home/${USERNAME}/go/bin:$PATH

# CMake 的 <PackageName>_ROOT 机制：find_package(userver) 读这个环境变量定位安装前缀，
# 故项目的 CMakeLists 不必为 userver 的落点做任何接线
ENV userver_ROOT=/opt/userver/prefix

# Debian 的 /etc/profile 会无条件 export PATH，覆盖上面的 ENV，登录 shell 里 go 即消失。
RUN printf 'export PATH="/usr/local/go/bin:$HOME/go/bin:$PATH"\n' > /etc/profile.d/go-path.sh \
    && chmod 0644 /etc/profile.d/go-path.sh \
    && ln -sf /usr/local/go/bin/go /usr/local/bin/go \
    && ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt

# userver 的混沌代码生成按 `clang-format` 这个名字 find_program，而 trixie 只提供带后缀的
# 包，故补一个软链。只影响从源码构建 userver，消费已装好的前缀不需要。
RUN ln -s /usr/bin/clang-format-19 /usr/local/bin/clang-format

# 构建期打印一次全部版本，供确认工具链与预期一致。go 走 bash -lc 是刻意的：
# PATH 被 /etc/profile 重置这类问题只在登录 shell 上暴露。
RUN set -x \
    && g++ --version | head -1 \
    && clang --version | head -1 \
    && clang-format-19 --version | head -1 \
    && clang-format --version | head -1 \
    && cmake --version | head -1 \
    && bpftool version \
    && protoc --version \
    && pkg-config --modversion libsystemd \
    && bash -lc 'go version'

# 预建并归属非 root 用户，免首次挂载时由 Docker 以 root 创建父目录
RUN mkdir -p /workspaces && chown ${USER_UID}:${USER_GID} /workspaces

USER ${USERNAME}
WORKDIR /workspaces

CMD ["/bin/bash"]
