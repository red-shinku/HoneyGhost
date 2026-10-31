# ============================================================
# containerd 翻译进程镜像
#
# 构建上下文是本目录（独立 Go module）：
#   docker build -t hng/containerd-bridge:dev agent/role_discovery/containerd_bridge
# ============================================================

ARG BASE_IMAGE=debian:13-slim
ARG GO_IMAGE=golang:1.26

FROM ${GO_IMAGE} AS builder

ARG VERSION=dev
ARG GOPROXY=https://goproxy.cn,direct
ENV GOPROXY=${GOPROXY}

WORKDIR /src

# 先只拷依赖清单：源码改动不触发重新下载模块
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath \
        -ldflags "-s -w -X main.version=${VERSION}" \
        -o /out/containerd-bridge ./cmd/containerd-bridge


FROM ${BASE_IMAGE}

# 静态二进制，无运行时依赖；基础镜像只提供 shell 供排障（可换 distroless）
COPY --from=builder /out/containerd-bridge /usr/local/bin/containerd-bridge

# 宿主 containerd socket 属 root:root 且为 0660，本进程须以 root 读取
ENTRYPOINT ["/usr/local/bin/containerd-bridge"]
CMD ["-socket=/run/honeyghost/containerd-bridge.sock", "-containerd=/run/containerd/containerd.sock"]
