# ============================================================
# 顶层唯一构建入口
#
#   make agent   构建 C++ 与 eBPF（转调 CMake）
#   make ebpf    只构建 eBPF 探针与骨架（agent 的子集）
#   make go      构建 Go 程序，产物落 bin/
#   make test    单测（ctest）
#   make all     agent + go
#   make clean   清构建产物
#
# image / package 待构建系统落地，暂不提供。
# ============================================================

BUILD_DIR ?= build-agent
BIN_DIR   ?= bin
CMAKE     ?= cmake
BRIDGE_DIR := agent/control_plane/role_discovery/containerd_bridge

.PHONY: all agent ebpf go test clean

all: agent go

agent:
	$(CMAKE) -S . -B $(BUILD_DIR)
	$(CMAKE) --build $(BUILD_DIR) --parallel

# 只改了探针时用，避免重走整个 CMake 构建
ebpf:
	$(CMAKE) -S . -B $(BUILD_DIR)
	$(CMAKE) --build $(BUILD_DIR) --target hng_ebpf

# 需 go >= 1.26.3（go.mod 要求）；低位版本会经 GOTOOLCHAIN 取工具链。
# 各 Go module 独立构建，后续 central / cli 在此追加。
go:
	mkdir -p $(BIN_DIR)
	cd $(BRIDGE_DIR) && go build -o $(CURDIR)/$(BIN_DIR)/containerd-bridge ./cmd/containerd-bridge

test: agent
	ctest --test-dir $(BUILD_DIR) --output-on-failure

# 只清 .gitignore 覆盖的产物。kernel/include/vmlinux.h 不删：重生成需 bpftool，
# 且内核未升级前其内容有效。
clean:
	$(CMAKE) -E remove_directory $(BUILD_DIR)
	$(CMAKE) -E remove_directory $(BIN_DIR)
	$(CMAKE) -E remove_directory kernel/build
	$(CMAKE) -E rm -f kernel/files.skel.h kernel/networks.skel.h kernel/syscalls.skel.h
