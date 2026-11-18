#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
out=build-agent/collector-filter-map
compiler="${CXX:-g++}"
flags=(-std=c++17 -O2 -Wall -Wextra -Werror)
sanitizers="${HNG_COLLECTOR_SANITIZERS:-0}"
if [[ "$sanitizers" == 1 ]]; then
    sanitizers=address,undefined
fi
if [[ "$sanitizers" != 0 ]]; then
    flags+=(-O1 -g "-fsanitize=$sanitizers" -fno-omit-frame-pointer)
fi
if ! pkg-config --exists fmt spdlog; then
    echo "fmt/spdlog 的 pkg-config 元数据缺失" >&2
    exit 1
fi
read -r -a deps <<< "$(pkg-config --cflags fmt spdlog)"
flags+=("${deps[@]}")
read -r -a links <<< "$(pkg-config --libs fmt spdlog)"
mkdir -p "$out/mocks/kernel" "$out/mocks/bpf"
# 此次编译刻意不提供替身头路径，防止公共头重新依赖生成骨架。
"$compiler" "${flags[@]}" -I. -fsyntax-only test/test_collector_public_header.cc
cp test/fixtures/collector_skeleton_stub.hpp "$out/mocks/kernel/syscalls.skel.h"
cp test/fixtures/collector_skeleton_stub.hpp "$out/mocks/bpf/libbpf.h"
"$compiler" "${flags[@]}" -I"$out/mocks" -I. -DHNG_LOG_TAG='"collector"' \
    agent/collector/src/probe_attach.cc \
    agent/collector/src/syscall_event_collector.cc \
    agent/util/src/tracefs.cc \
    agent/util/src/log.cc \
    test/test_collector_filter_map.cc -o "$out/test_collector_filter_map" \
    "${links[@]}"
"$out/test_collector_filter_map"
