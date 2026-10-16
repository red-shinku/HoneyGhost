#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
out=build-agent/collector-filter-map
mkdir -p "$out/mocks/kernel"
for name in files syscalls networks; do
    cp test/fixtures/collector_skeleton_stub.hpp "$out/mocks/kernel/$name.skel.h"
done
"${CXX:-g++}" -std=c++17 -O2 -Wall -Wextra -Werror \
    -I"$out/mocks" -I. \
    agent/collector/src/file_event_collector.cc \
    agent/collector/src/syscall_event_collector.cc \
    agent/collector/src/network_event_collector.cc \
    test/test_collector_filter_map.cc -o "$out/test_collector_filter_map"
"$out/test_collector_filter_map"
