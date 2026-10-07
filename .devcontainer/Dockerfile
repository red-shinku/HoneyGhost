# ============================================================
# 开发容器工具链镜像
#
# 定位、边界、使用注意事项与各取值的理由见同目录 README.md；此处只留与本文件各
# 取值直接相关的说明。
#
# 本镜像只承载「编译 + 单测」，不申请任何特权——eBPF 的加载与对 systemd、
# containerd 的观测都在宿主上做。
# ============================================================

# 基础镜像可覆盖，供内网以同发行版同版本的副本代用时使用。覆盖它即放弃下面的版本
# 对齐前提——非同一 trixie 快照的镜像不保证可用。
ARG BASE_IMAGE=debian:13-slim
FROM ${BASE_IMAGE}

ARG DEBIAN_FRONTEND=noninteractive

# 供 BuildKit 之外的构建器兜底：TARGETARCH 未定义时为空，Go 下载地址会拼错
ARG TARGETARCH=amd64

# 官方无 1.26.3 的 deb 包，只能走压缩包；按确切版本固定，免 GOTOOLCHAIN 联网取工具链
ARG GO_VERSION=1.26.3

# 与宿主开发机一致，否则绑定挂载的工作区在宿主侧归属错误；不一致时用构建参数覆盖
ARG USERNAME=dev
ARG USER_UID=1000
ARG USER_GID=1000

# apt 源可在构建时覆盖：受限网络下 deb.debian.org 可能不可达或极慢。APT_MIRROR 是首选
# 主机名，APT_MIRROR_FALLBACK 是它的备选，官方源始终作为最后一档兜底——故不改默认值时
# 行为与不设覆盖一致。两者只替换主机名，协议与路径保持不变。
ARG APT_MIRROR=deb.debian.org
ARG APT_MIRROR_FALLBACK=

# 只装元包 `clang` 而非 `clang-19`：kernel/CMakeLists.txt 的 find_program 按 `clang`
# 这个名字查找，元包才会建出 /usr/bin/clang 这个符号链接。clang-format / clangd 反之
# 显式带 19 后缀——.clang-format 的换行行为随版本变化，语言服务器的诊断也随版本增删。
#
# 逐档试源而非直接写死：每轮都从原文件重生成，故上一档的替换不会累积到下一档。
#
# --error-on=any 不可省：默认语义下源全部不可达时 apt-get update 仍退出 0，循环会在第一档
# 就 break，兜底形同虚设，报错还会推迟到 apt-get install 且信息误导。
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
        clang \
        clang-format-19 \
        clang-tidy-19 \
        clangd-19 \
        bpftool \
        libbpf-dev \
        libsystemd-dev \
        pkg-config \
        protobuf-compiler \
        libprotobuf-dev \
        git \
        ca-certificates \
        curl \
        sudo \
        gdb \
        less \
        vim; \
    rm -rf /var/lib/apt/lists/*

# Go 下载源同样可覆盖与逐档兜底，取值语义与上面的 apt 源一致，官方源始终是最后一档。
ARG GO_DOWNLOAD_BASE=https://go.dev/dl
ARG GO_DOWNLOAD_FALLBACK=

# GO_SHA256 非空则直接用作期望值，不联网取（触达不到 dl.google.com，或需要钉死版本时用）；
# 其值为 none 则跳过校验，是上述两者都不可行时的最后退路。
ARG GO_SHA256=
ARG GO_SHA256_BASE=https://dl.google.com/go

# 系统级安装而非装进用户家目录，工作区与家目录之间无隐含依赖。
# 用到的 curl 由上面的 apt 步装入，故本步须排在它之后。
#
# 取包后先 `tar -tzf` 过一遍再认这一档，这里不能只靠后面的 sha256 代替：镜像站返回
# 被截断或非 gzip 的内容时 curl 未必退出非零，若留到 sha256 才判失败，报错会变成"哈希
# 不匹配"——正确但指向错误的方向，且不会去试下一档镜像。
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

# 不设则部分网络下 make go 必 i/o timeout，详见 README 的「注意事项」
ARG GOPROXY=https://goproxy.cn,direct
ENV GOPROXY=${GOPROXY}

# 容器内不需特权：特权动作一律在宿主上做，sudo 只为偶发的装包与调试保留。
#
# 两个 Go 目录是 devcontainer.json 命名卷的挂载点，须预建并归属对：命名卷首次挂载
# 继承镜像中该路径的归属，未预建则会以 root 新建，容器内以 dev 写入直接失败。
RUN groupadd --gid ${USER_GID} ${USERNAME} \
    && useradd --uid ${USER_UID} --gid ${USER_GID} --create-home --shell /bin/bash ${USERNAME} \
    && echo "${USERNAME} ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/${USERNAME} \
    && chmod 0440 /etc/sudoers.d/${USERNAME} \
    && mkdir -p /home/${USERNAME}/go/pkg/mod /home/${USERNAME}/.cache/go-build \
    && chown -R ${USER_UID}:${USER_GID} /home/${USERNAME}

ENV LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    PATH=/usr/local/go/bin:/home/${USERNAME}/go/bin:$PATH

# Debian 的 /etc/profile 会无条件 export PATH 覆盖掉上面的 ENV，登录 shell 里 go 即消失，
# 而 devcontainer 默认走登录 shell。两条修复都留，只留其一会漏，详见 README 的「注意事项」。
RUN printf 'export PATH="/usr/local/go/bin:$HOME/go/bin:$PATH"\n' > /etc/profile.d/go-path.sh \
    && chmod 0644 /etc/profile.d/go-path.sh \
    && ln -sf /usr/local/go/bin/go /usr/local/bin/go \
    && ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt

# 构建期打印一次全部版本，供确认工具链与预期一致——版本漂移在此处最易发现。
# 走 bash -lc 是刻意的——PATH 被 /etc/profile 重置这类问题只在登录 shell 上暴露。
RUN set -x \
    && g++ --version | head -1 \
    && clang --version | head -1 \
    && clang-format-19 --version | head -1 \
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
