#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
out=build-agent/role-filter
mkdir -p "$out"
compiler="${CXX:-g++}"
flags=(-std=c++17 -O2 -Wall -Wextra -Werror -pthread -I.)
sources=(agent/role_filter/src/*.cc)
"$compiler" "${flags[@]}" "${sources[@]}" test/test_role_filter.cc -o "$out/test_role_filter"
"$out/test_role_filter"
"$compiler" "${flags[@]}" "${sources[@]}" \
    agent/control_plane/src/role_label_builder.cc \
    agent/control_plane/src/role_relation_store.cc \
    agent/control_plane/src/role_manager.cc \
    agent/role_discovery/src/role_cgroup_reader.cc \
    test/test_role_filter_integration.cc -o "$out/test_role_filter_integration"
"$out/test_role_filter_integration"
"$compiler" "${flags[@]}" agent/role_filter/src/process_filter_map.cc \
    test/test_process_filter_map_backend.cc -Wl,--wrap=syscall \
    -o "$out/test_process_filter_map_backend"
"$out/test_process_filter_map_backend"
