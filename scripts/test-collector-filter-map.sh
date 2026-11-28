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
"$compiler" "${flags[@]}" -I. -fsyntax-only test/test_bpf_public_header.cc
cp test/fixtures/collector_skeleton_stub.hpp "$out/mocks/kernel/syscalls.skel.h"
cp test/fixtures/collector_skeleton_stub.hpp "$out/mocks/bpf/libbpf.h"
cp test/fixtures/collector_skeleton_stub.hpp "$out/mocks/bpf/bpf.h"
cp test/fixtures/libbpf_version_stub.h "$out/mocks/bpf/libbpf_version.h"

common=(
    -I"$out/mocks" -I.
    agent/bpf_loader/src/bpf_map.cc
    agent/util/src/tracefs.cc
    agent/util/src/log.cc
)
loader=(
    agent/bpf_loader/src/probe_attach.cc
    agent/bpf_loader/src/syscall_probe_loader.cc
)

"$compiler" "${flags[@]}" "${common[@]}" "${loader[@]}" \
    -DHNG_LOG_TAG='"bpf_loader"' \
    test/test_bpf_loader.cc -o "$out/test_bpf_loader" \
    -Wl,--wrap=syscall "${links[@]}"
"$out/test_bpf_loader"

"$compiler" "${flags[@]}" -I. \
    agent/bpf_loader/src/bpf_program_group.cc \
    test/test_bpf_program_group.cc -o "$out/test_bpf_program_group"
"$out/test_bpf_program_group"

"$compiler" "${flags[@]}" "${common[@]}" \
    agent/bpf_loader/src/ringbuf_reader.cc \
    test/test_bpf_ringbuf_reader.cc -o "$out/test_bpf_ringbuf_reader" \
    -Wl,--wrap=syscall -Wl,--wrap=fcntl "${links[@]}"
"$out/test_bpf_ringbuf_reader"

"$compiler" "${flags[@]}" "${common[@]}" "${loader[@]}" \
    agent/bpf_loader/src/bpf_map_reader.cc \
    agent/bpf_loader/src/ringbuf_reader.cc \
    agent/collector/src/syscall_event_collector.cc \
    -DHNG_LOG_TAG='"collector"' \
    test/test_collector_syscall_line.cc \
    -o "$out/test_collector_syscall_line" \
    -Wl,--wrap=syscall -Wl,--wrap=fcntl \
    -Wl,--wrap=bpf_map_lookup_elem \
    -Wl,--wrap=libbpf_num_possible_cpus "${links[@]}"
"$out/test_collector_syscall_line"
