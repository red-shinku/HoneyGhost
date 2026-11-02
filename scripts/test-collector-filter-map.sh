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
mkdir -p "$out/mocks/kernel"
# 此次编译刻意不提供替身头路径，防止公共头重新依赖生成骨架。
"$compiler" "${flags[@]}" -I. -fsyntax-only test/test_collector_public_header.cc
for name in files syscalls networks; do
    cp test/fixtures/collector_skeleton_stub.hpp "$out/mocks/kernel/$name.skel.h"
done
"$compiler" "${flags[@]}" -I"$out/mocks" -I. \
    agent/collector/src/file_event_collector.cc \
    agent/collector/src/syscall_event_collector.cc \
    agent/collector/src/network_event_collector.cc \
    test/test_collector_filter_map.cc -o "$out/test_collector_filter_map"
"$out/test_collector_filter_map"
