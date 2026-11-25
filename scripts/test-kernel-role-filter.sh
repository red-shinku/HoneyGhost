#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
out=build-agent/kernel-role-filter
mkdir -p "$out"
"${CXX:-g++}" -std=c++17 -O2 -Wall -Wextra -Werror \
    -Wno-unused-function -Itest/fixtures/kernel_filter -I. \
    test/test_kernel_role_filter.cc -o "$out/test_kernel_role_filter"
"$out/test_kernel_role_filter"
# 确保生命周期初始化绕过名单、其他初始化在占用事件槽之前检查。
python3 - <<'PY'
from pathlib import Path
s = Path('kernel/src/syscall_event_builders.bpf.h').read_text()
for kind in ('process', 'exec', 'credential', 'namespace', 'file',
             'memory', 'network', 'kernel', 'signal'):
    body = s.split('init_' + kind + '_event(', 1)[1].split('\n}', 1)[0]
    if kind in ('process', 'exec'):
        assert 'hng_should_collect' not in body, kind
    else:
        assert body.index('hng_should_collect') < body.index('hng_scratch_event'), kind
print('PASS: lifecycle bypass and filtering before scratch slot')
PY
