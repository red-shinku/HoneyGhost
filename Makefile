# ============================================================
# 顶层唯一构建入口
#
#   make agent    构建 C++ 与 eBPF（转调 CMake，注入版本信息）
#   make ebpf     只构建 eBPF 探针与骨架（agent 的子集）
#   make go       构建 Go 程序，产物落 bin/
#   make test     单测（ctest）
#   make test-go  Go 单测（cli 与 bridge）
#   make package  生成发布用二进制包与校验和，产物落 dist/
#   make image    本地构建两个容器镜像（不推送）
#   make all      agent + go
#   make clean    清构建产物
# ============================================================

BUILD_DIR ?= build-agent
BIN_DIR   ?= bin
DIST_DIR  ?= dist
CMAKE     ?= cmake
CLI_DIR    := cli
BRIDGE_DIR := agent/role_discovery/containerd_bridge

VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT     ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo unknown)
# 镜像 tag 不取 v 前缀；git describe 的 -dirty 等后缀原样保留，便于识别本地构建
IMAGE_VERSION ?= $(patsubst v%,%,$(VERSION))

IMAGE_PREFIX  ?= fifseason
BASE_IMAGE    ?= debian:13-slim
BUILDER_IMAGE ?= ghcr.io/red-shinku/honeyghost-builder:latest

.PHONY: all agent ebpf go go-bridge go-cli test test-go test-go-cli \
        test-go-bridge package image clean

all: agent go

agent:
	$(CMAKE) -S . -B $(BUILD_DIR) \
		-DHNG_VERSION="$(VERSION)" \
		-DHNG_COMMIT="$(COMMIT)" \
		-DHNG_BUILD_DATE="$(BUILD_DATE)"
	$(CMAKE) --build $(BUILD_DIR) --parallel

# 只改了探针时用，避免重走整个 CMake 构建
ebpf:
	$(CMAKE) -S . -B $(BUILD_DIR) \
		-DHNG_VERSION="$(VERSION)" \
		-DHNG_COMMIT="$(COMMIT)" \
		-DHNG_BUILD_DATE="$(BUILD_DATE)"
	$(CMAKE) --build $(BUILD_DIR) --target hng_ebpf

# 需 go >= 1.26.3（go.mod 要求）；低位版本会经 GOTOOLCHAIN 取工具链。
# 各 Go module 独立构建，后续 central 在此追加。
go: go-bridge go-cli

go-bridge:
	mkdir -p $(BIN_DIR)
	cd $(BRIDGE_DIR) && go build -trimpath \
		-ldflags "-X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(BUILD_DATE)" \
		-o $(CURDIR)/$(BIN_DIR)/containerd-bridge ./cmd/containerd-bridge

# CLI 构建前先生成协议代码，产物与生成物都不入库。
go-cli:
	mkdir -p $(BIN_DIR)
	cd $(CLI_DIR) && ./gen.sh
	cd $(CLI_DIR) && go build \
		-ldflags "-X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(BUILD_DATE)" \
		-o $(CURDIR)/$(BIN_DIR)/hghost ./cmd/hghost

test: agent
	ctest --test-dir $(BUILD_DIR) --output-on-failure

# Go 测试独立目标：先重新生成协议代码，不改变 make test 的语义。
test-go: test-go-cli test-go-bridge

test-go-cli:
	cd $(CLI_DIR) && ./gen.sh
	cd $(CLI_DIR) && go test -race ./...

test-go-bridge:
	cd $(BRIDGE_DIR) && go test -race ./...

# 只打 hghost 与 containerd-bridge；agent 走镜像，不在此打包。
# 部署包需要镜像 digest，由发布流程在推送后生成。
package: go
	rm -rf $(DIST_DIR)
	mkdir -p $(DIST_DIR)/hghost $(DIST_DIR)/containerd-bridge
	cp $(BIN_DIR)/hghost LICENSE $(DIST_DIR)/hghost/
	cp $(BIN_DIR)/containerd-bridge LICENSE $(DIST_DIR)/containerd-bridge/
	tar -C $(DIST_DIR)/hghost -czf \
		$(DIST_DIR)/honeyghost-hghost_$(IMAGE_VERSION)_linux-amd64.tar.gz .
	tar -C $(DIST_DIR)/containerd-bridge -czf \
		$(DIST_DIR)/honeyghost-containerd-bridge_$(IMAGE_VERSION)_linux-amd64.tar.gz .
	rm -rf $(DIST_DIR)/hghost $(DIST_DIR)/containerd-bridge
	cd $(DIST_DIR) && sha256sum *.tar.gz > SHA256SUMS && cat SHA256SUMS

# 工具链与 userver 来自 builder 镜像；BUILDER_IMAGE 可覆盖为按 digest 固定的引用。
image:
	docker build -f deploy/docker/agent.Dockerfile \
		--build-arg BASE_IMAGE=$(BASE_IMAGE) \
		--build-arg BUILDER_IMAGE=$(BUILDER_IMAGE) \
		--build-arg VERSION=$(IMAGE_VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		-t $(IMAGE_PREFIX)/honeyghost-agent:$(IMAGE_VERSION) .
	docker build -f $(BRIDGE_DIR)/Dockerfile \
		--build-arg VERSION=$(IMAGE_VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		-t $(IMAGE_PREFIX)/honeyghost-containerd-bridge:$(IMAGE_VERSION) \
		$(BRIDGE_DIR)

# 只清 .gitignore 覆盖的产物。kernel/include/vmlinux.h 不删：重生成需 bpftool，
# 且内核未升级前其内容有效。
clean:
	$(CMAKE) -E remove_directory $(BUILD_DIR)
	$(CMAKE) -E remove_directory $(BIN_DIR)
	$(CMAKE) -E remove_directory $(DIST_DIR)
	$(CMAKE) -E remove_directory kernel/build
	$(CMAKE) -E rm -f kernel/files.skel.h kernel/networks.skel.h kernel/syscalls.skel.h
