#!/bin/sh
# 多订阅流端到端压测：并发启动 N 条 hghost events，再用 openat 突发产生事件。
#
# 用法（socket 通常仅 root 可连）：
#   sudo scripts/bench-event-stream.sh <hghost> [streams] [opens] [batch] [role]
#
# 例：
#   sudo scripts/bench-event-stream.sh bin/hghost 8 10000 64 ssh.service
#
# 判定：每条流都必须 received > 0 且 dropped == 0；否则以 1 退出。
# 结束后打印 hghost status 的 runtime_stats，便于核对上游计数。

set -eu

if [ "$#" -lt 1 ]; then
    echo "usage: $0 <hghost> [streams] [opens] [batch] [role]" >&2
    exit 2
fi

hghost=$1
streams=${2:-8}
opens=${3:-10000}
batch=${4:-64}
role=${5:-ssh.service}
socket=${HGHOST_SOCKET:-/run/honeyghost/cli.sock}

if [ "$(id -u)" -ne 0 ]; then
    echo "must run as root: the CLI socket is normally 0755 root-owned" >&2
    exit 2
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

pids=""
i=1
while [ "$i" -le "$streams" ]; do
    "$hghost" events --socket "$socket" -i "role=$role" --batch "$batch" \
        --duration 20s >/dev/null 2>"$tmp/s$i.err" &
    pids="$pids $!"
    i=$((i + 1))
done

# 给订阅留出建立时间，再发突发
sleep 2
python3 - "$opens" <<'PY'
import os
import sys

for _ in range(int(sys.argv[1])):
    os.close(os.open("/etc/hostname", os.O_RDONLY))
PY

for pid in $pids; do
    wait "$pid" || true
done

fail=0
for f in "$tmp"/s*.err; do
    line=$(grep '^events:' "$f" | tail -1 || true)
    received=$(printf '%s\n' "$line" | awk -F'[ ,]+' '{print $2}')
    dropped=$(printf '%s\n' "$line" | awk -F'[ ,]+' '{print $4}')
    echo "$(basename "$f"): ${line:-<no summary>}"
    if [ -z "$received" ] || [ -z "$dropped" ] || \
       [ "$received" -le 0 ] || [ "$dropped" -ne 0 ]; then
        fail=1
    fi
done

echo "== runtime stats =="
"$hghost" status --socket "$socket" -o json | python3 -c '
import json
import sys

stats = json.load(sys.stdin)["runtime_stats"]
print("cli", stats["cli"])
print("collector", [(line["line"], line["channel_dropped"],
                    line["reserve_failures"]) for line in stats["collector"]])
print("engine", stats["engine"]["syscall_dropped"],
      stats["engine"]["file_dropped"])
'

if [ "$fail" -ne 0 ]; then
    echo "FAIL: at least one stream dropped events" >&2
    exit 1
fi
echo "PASS: $streams stream(s), 0 dropped"
