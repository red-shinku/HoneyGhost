# ============================================================
# 顶层唯一构建入口
#
#   make agent   构建 C++ 与 eBPF（转调 CMake）
#   make ebpf    只构建 eBPF 探针与骨架（agent 的子集）
#   make go      构建 Go 程序，产物落 bin/
#   make test    单测（ctest）
#   make test-go Go 单测（独立目标，不并入 test）
#   make all     agent + go
#   make clean   清构建产物
#
# image / package 待构建系统落地，暂不提供。
# ============================================================

BUILD_DIR ?= build-agent
BIN_DIR   ?= bin
CMAKE     ?= cmake
CLI_DIR    := cli
BRIDGE_DIR := agent/role_discovery/containerd_bridge

VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT     ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo unknown)

.PHONY: all agent ebpf go go-bridge go-cli test test-go clean

all: agent go

agent:
	$(CMAKE) -S . -B $(BUILD_DIR)
	$(CMAKE) --build $(BUILD_DIR) --parallel

# 只改了探针时用，避免重走整个 CMake 构建
ebpf:
	$(CMAKE) -S . -B $(BUILD_DIR)
	$(CMAKE) --build $(BUILD_DIR) --target hng_ebpf

# 需 go >= 1.26.3（go.mod 要求）；低位版本会经 GOTOOLCHAIN 取工具链。
# 各 Go module 独立构建，后续 central 在此追加。
go: go-bridge go-cli

go-bridge:
	mkdir -p $(BIN_DIR)
	cd $(BRIDGE_DIR) && go build -o $(CURDIR)/$(BIN_DIR)/containerd-bridge ./cmd/containerd-bridge

# CLI 构建前先生成协议代码，产物与生成物都不入库。
go-cli:
	mkdir -p $(BIN_DIR)
	cd $(CLI_DIR) && ./gen.sh
	cd $(CLI_DIR) && go build \
		-ldflags "-X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(BUILD_DATE)" \
		-o $(CURDIR)/$(BIN_DIR)/hghost ./cmd/hghost

test: agent
	ctest --test-dir $(BUILD_DIR) --output-on-failure

# Go 测试单独成目标：先重新生成协议代码，不改变 make test 的语义。
test-go:
	cd $(CLI_DIR) && ./gen.sh
	cd $(CLI_DIR) && go test -race ./...

# 只清 .gitignore 覆盖的产物。kernel/include/vmlinux.h 不删：重生成需 bpftool，
# 且内核未升级前其内容有效。
clean:
	$(CMAKE) -E remove_directory $(BUILD_DIR)
	$(CMAKE) -E remove_directory $(BIN_DIR)
	$(CMAKE) -E remove_directory kernel/build
	$(CMAKE) -E rm -f kernel/files.skel.h kernel/networks.skel.h kernel/syscalls.skel.h
