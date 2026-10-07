# ============================================================
# 开发容器工具链镜像
#
# 定位、边界、使用注意事项与各取值的理由见同目录 README.md；此处只留与本文件各
# 取值直接相关的说明。
#
# 本镜像只承载「编译 + 单测」，不申请任何特权——eBPF 的加载与对 systemd、
# containerd 的观测都在宿主上做。
# ============================================================

FROM debian:13-slim

ARG DEBIAN_FRONTEND=noninteractive

# 供 BuildKit 之外的构建器兜底：TARGETARCH 未定义时为空，Go 下载地址会拼错
ARG TARGETARCH=amd64

# 官方无 1.26.3 的 deb 包，只能走压缩包；按确切版本固定，免 GOTOOLCHAIN 联网取工具链
ARG GO_VERSION=1.26.3

# 与宿主开发机一致，否则绑定挂载的工作区在宿主侧归属错误；不一致时用构建参数覆盖
ARG USERNAME=dev
ARG USER_UID=1000
ARG USER_GID=1000

# 只装元包 `clang` 而非 `clang-19`：kernel/CMakeLists.txt 的 find_program 按 `clang`
# 这个名字查找，元包才会建出 /usr/bin/clang 这个符号链接。clang-format / clangd 反之
# 显式带 19 后缀——.clang-format 的换行行为随版本变化，语言服务器的诊断也随版本增删。
RUN apt-get update && apt-get install -y --no-install-recommends \
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
        vim \
    && rm -rf /var/lib/apt/lists/*

# 系统级安装而非装进用户家目录，工作区与家目录之间无隐含依赖
RUN curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${TARGETARCH}.tar.gz" -o /tmp/go.tar.gz \
    && tar -C /usr/local -xzf /tmp/go.tar.gz \
    && rm /tmp/go.tar.gz

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
