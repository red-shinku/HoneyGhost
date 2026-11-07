#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
out=build-agent/kernel-event-head
mkdir -p "$out"
"${CXX:-g++}" -std=c++17 -O2 -Wall -Wextra -Werror \
    -Wno-unused-function -Itest/fixtures/kernel_filter -I. \
    test/test_kernel_event_head.cc -o "$out/test_kernel_event_head"
"$out/test_kernel_event_head"
# 父进程字段只能由 init_event_head_parent 填写，探针不得自行拼接父进程键。
python3 - <<'PY'
from pathlib import Path

def body(text, signature):
    assert signature in text, signature
    return text.split(signature, 1)[1].split('\n}', 1)[0]

s = Path('kernel/probes/syscalls.bpf.c').read_text()
for signature in ('trace_process_birth(struct pt_regs *ctx)',
                  'trace_process_exit(void *ctx)'):
    part = body(s, signature)
    assert 'init_event_head_self' in part, signature
    assert 'init_event_head_parent' in part, signature
    assert '.pid' not in part and '.ppid' not in part, signature

h = Path('kernel/include/event_head.h').read_text()
part = body(h, 'init_event_head(struct event_head *head)')
assert 'init_event_head_self' in part and 'init_event_head_parent' in part
assert '.pid' not in part and '.ppid' not in part
print('PASS: identity fields filled only through the event head helpers')
PY
