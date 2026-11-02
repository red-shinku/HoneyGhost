#!/bin/sh
# hghost 与 C++ CLIServer 的端到端联调。
#
# 复用 test/e2e_cli_server.cc 的替身装配：设置 HNG_CLI_E2E_SERVE=1 启动该二进制，
# 它在 /tmp/honeyghost-cli-e2e.sock 上驻留服务，直到收到 SIGTERM。
#
# 前置：make agent（或至少构建 e2e_cli_server）、make go-cli。
set -eu

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
server=$root/build-agent/test/e2e_cli_server
cli=$root/bin/hghost
socket=/tmp/honeyghost-cli-e2e.sock
log=${TMPDIR:-/tmp}/hghost-cli-e2e-server.log
err_file=${TMPDIR:-/tmp}/hghost-cli-e2e-stderr.txt

[ -x "$server" ] || { echo "缺少 $server：先 make agent" >&2; exit 1; }
[ -x "$cli" ] || { echo "缺少 $cli：先 make go-cli" >&2; exit 1; }

out=
err=
code=0
fail=0
server_pid=

pass() { printf '  ok   %s\n' "$1"; }
fail_case() { printf '  FAIL %s\n' "$1"; fail=1; }

assert_eq() { # desc want got
    if [ "$2" = "$3" ]; then
        pass "$1"
    else
        fail_case "$1"
        printf '       want: %s\n       got:  %s\n' "$2" "$3"
    fi
}

assert_contains() { # desc needle haystack
    case "$3" in
        *"$2"*) pass "$1" ;;
        *)
            fail_case "$1"
            printf '       missing: %s\n       got:  %s\n' "$2" "$3"
            ;;
    esac
}

assert_not_contains() { # desc needle haystack
    case "$3" in
        *"$2"*)
            fail_case "$1"
            printf '       unexpected: %s\n       got:  %s\n' "$2" "$3"
            ;;
        *) pass "$1" ;;
    esac
}

assert_match() { # desc extended-regexp text
    if printf '%s\n' "$3" | grep -Eq -- "$2"; then
        pass "$1"
    else
        fail_case "$1"
        printf '       pattern: %s\n       got:  %s\n' "$2" "$3"
    fi
}

run() { # desc want-exit command...
    desc=$1
    want=$2
    shift 2
    set +e
    out=$("$@" 2>"$err_file")
    code=$?
    set -e
    err=$(cat "$err_file")
    assert_eq "$desc（退出码）" "$want" "$code"
}

cleanup() {
    if [ -n "$server_pid" ]; then
        kill -TERM "$server_pid" 2>/dev/null || true
        wait "$server_pid" 2>/dev/null || true
    fi
    rm -f "$socket" "$err_file"
}
trap cleanup EXIT INT TERM

rm -f "$socket"
HNG_CLI_E2E_SERVE=1 "$server" >"$log" 2>&1 &
server_pid=$!

ready=0
i=0
while [ "$i" -lt 200 ]; do
    if "$cli" --socket "$socket" role list >/dev/null 2>&1; then
        ready=1
        break
    fi
    i=$((i + 1))
    sleep 0.05
done
if [ "$ready" -ne 1 ]; then
    echo "服务端未在期限内就绪；日志：" >&2
    cat "$log" >&2
    exit 1
fi

echo "查询面"

run "role list" 0 "$cli" --socket "$socket" role list
assert_eq "role list 输出" "ID  LABEL
7   e2e" "$out"

run "role list -a" 0 "$cli" --socket "$socket" role list -a
assert_eq "role list -a 输出" "ID  LABEL
7   e2e" "$out"

run "role list -o json" 0 "$cli" --socket "$socket" role list -o json
assert_contains "JSON role_id" '"role_id": 7' "$out"
assert_contains "JSON role_label" '"role_label": "e2e"' "$out"

run "role show 7" 0 "$cli" --socket "$socket" role show 7
assert_contains "ID" "ID     7" "$out"
assert_contains "LABEL" "LABEL  e2e" "$out"
assert_contains "进程段" "PROCESSES (root 1001)" "$out"
assert_contains "成员进程" "  2002" "$out"
assert_contains "上下文段" "CONTEXTS" "$out"

run "role show e2e" 0 "$cli" --socket "$socket" role show e2e
assert_contains "按标签解析" "ID     7" "$out"

run "role show --label e2e" 0 "$cli" --socket "$socket" role show --label e2e
assert_contains "--label" "LABEL  e2e" "$out"

run "role show -o json" 0 "$cli" --socket "$socket" role show 7 -o json
assert_contains "JSON label" '"role_label": "e2e"' "$out"
assert_contains "JSON root_pid" '"root_pid": 1001' "$out"
assert_contains "JSON context_ids" '"context_ids": [' "$out"

run "role stats" 0 "$cli" --socket "$socket" role stats
assert_match "rejected" '^rejected +1$' "$out"
assert_match "unknown_instance" '^unknown_instance +2$' "$out"
assert_match "owner_conflict" '^owner_conflict +3$' "$out"
assert_match "anchors_removed" '^anchors_removed +4$' "$out"
assert_match "cgroup_read_empty" '^cgroup_read_empty +5$' "$out"
assert_match "queue_rejected" '^queue_rejected +6$' "$out"
assert_match "bind_deferred" '^bind_deferred +7$' "$out"
assert_match "bind_resolved" '^bind_resolved +8$' "$out"
assert_match "bind_rejected" '^bind_rejected +9$' "$out"
assert_match "bind_expired" '^bind_expired +10$' "$out"
assert_match "bind_ignored" '^bind_ignored +11$' "$out"
assert_match "late_adopt_rejected" '^late_adopt_rejected +12$' "$out"
assert_match "tombstone_depth" '^tombstone_depth +13$' "$out"
assert_match "dead_member_rejected" '^dead_member_rejected +14$' "$out"
assert_match "dead_anchor_rejected" '^dead_anchor_rejected +15$' "$out"

run "role which 1001" 0 "$cli" --socket "$socket" role which 1001
assert_eq "role which 输出" "7" "$out"

run "role which 未找到" 0 "$cli" --socket "$socket" role which 999999
assert_eq "未找到 stdout" "" "$out"
assert_eq "未找到 stderr" "pid 999999 has no role" "$err"

run "context list" 0 "$cli" --socket "$socket" context list
assert_eq "context list 输出" "KIND   CONTEXT_ID
excep  3" "$out"

run "context list -k extra" 0 "$cli" --socket "$socket" context list -k extra
assert_eq "context list extra" "KIND   CONTEXT_ID
extra  4" "$out"

run "context list -k all" 0 "$cli" --socket "$socket" context list -k all
assert_contains "excep 行" "excep  3" "$out"
assert_contains "extra 行" "extra  4" "$out"

run "context show 3" 0 "$cli" --socket "$socket" context show 3
assert_eq "context show 输出" "CONTEXT  3

PROCESSES (root 1001)
  1001
  2002" "$out"

run "context stats" 0 "$cli" --socket "$socket" context stats
assert_match "ctxroot_parent_unsettled" '^ctxroot_parent_unsettled +11$' "$out"
assert_match "unknown_unregister" '^unknown_unregister +12$' "$out"
assert_match "pending_deferred" '^pending_deferred +13$' "$out"
assert_match "pending_resolved" '^pending_resolved +14$' "$out"
assert_match "pending_rejected" '^pending_rejected +15$' "$out"
assert_match "pending_expired" '^pending_expired +16$' "$out"
assert_match "pending_cancelled" '^pending_cancelled +17$' "$out"
assert_match "pending_depth" '^pending_depth +18$' "$out"
assert_match "bind_orphaned" '^bind_orphaned +19$' "$out"
assert_match "extra_orphaned" '^extra_orphaned +20$' "$out"
assert_match "parent_missing" '^parent_missing +21$' "$out"
assert_match "late_register" '^late_register +22$' "$out"
assert_match "late_bind" '^late_bind +23$' "$out"
assert_match "duplicate_context" '^duplicate_context +24$' "$out"
assert_match "ownership_conflict" '^ownership_conflict +25$' "$out"
assert_match "tombstone_hits" '^tombstone_hits +26$' "$out"
assert_match "tombstone_depth" '^tombstone_depth +27$' "$out"

run "process stats" 0 "$cli" --socket "$socket" process stats
assert_match "pid_reused" '^pid_reused +1$' "$out"
assert_match "stale_add" '^stale_add +2$' "$out"
assert_match "parent_missing" '^parent_missing +3$' "$out"
assert_match "tombstone_depth" '^tombstone_depth +4$' "$out"

run "context which 1001" 0 "$cli" --socket "$socket" context which 1001
assert_eq "context which 输出" "3" "$out"

run "status" 0 "$cli" --socket "$socket" status
assert_match "监管角色数" '^SUPERVISED ROLES +1$' "$out"
assert_match "异常上下文数" '^EXCEPTION CONTEXTS +1$' "$out"
assert_match "附属上下文数" '^EXTRA CONTEXTS +1$' "$out"
assert_contains "角色计数段" "ROLE STATS" "$out"
assert_contains "上下文计数段" "CONTEXT STATS" "$out"
assert_contains "进程计数段" "PROCESS STATS" "$out"

run "status -o json" 0 "$cli" --socket "$socket" status -o json
assert_contains "监管角色数" '"supervised_role_count": 1' "$out"
assert_contains "异常上下文数" '"exception_context_count": 1' "$out"
assert_contains "附属上下文数" '"extra_context_count": 1' "$out"
assert_contains "角色计数" '"rejected": 1' "$out"
assert_contains "角色计数（新增）" '"bind_deferred": 7' "$out"
assert_contains "上下文计数" '"ctxroot_parent_unsettled": 11' "$out"
assert_contains "上下文计数（新增）" '"pending_depth": 18' "$out"
assert_contains "进程计数" '"pid_reused": 1' "$out"

echo "错误路径"

run "连接失败" 1 "$cli" --socket /tmp/hghost-no-such.sock role list
assert_contains "连接失败文案" "cannot connect to the CLI service" "$err"

run "role show 0" 2 "$cli" --socket "$socket" role show 0
run "role show 不存在" 1 "$cli" --socket "$socket" role show missing
run "role which 0" 2 "$cli" --socket "$socket" role which 0
run "context show 0" 2 "$cli" --socket "$socket" context show 0
run "events --timeout" 2 "$cli" --socket "$socket" events --timeout 1s
run "events 非法类型" 2 "$cli" --socket "$socket" events -t bogus
run "events 非法过滤" 2 "$cli" --socket "$socket" events -i roleID=0

echo "事件流"

run "events -t file" 0 "$cli" --socket "$socket" events -t file --duration 300ms
assert_contains "文件事件" "file" "$out"
assert_not_contains "只收到文件事件" "syscall" "$out"
assert_contains "流结束统计" "events:" "$err"
sleep 0.2

run "events -t syscall" 0 "$cli" --socket "$socket" events -t syscall --duration 300ms
assert_contains "系统调用事件" "syscall" "$out"
assert_not_contains "只收到系统调用事件" "file" "$out"
sleep 0.2

run "events -i role=e2e" 0 "$cli" --socket "$socket" events -i role=e2e --duration 200ms
assert_contains "角色标签过滤" "e2e" "$out"
sleep 0.2

run "events -i pid 无匹配" 0 "$cli" --socket "$socket" events -i pid=999999 --duration 100ms
assert_eq "无匹配 stdout" "" "$out"
assert_contains "无匹配统计" "events: 0 received" "$err"
sleep 0.2

run "events -t network" 0 "$cli" --socket "$socket" events -t network --duration 100ms
assert_eq "空流 stdout" "" "$out"
sleep 0.2

run "events -o json" 0 "$cli" --socket "$socket" events -t file -o json --duration 300ms
assert_contains "JSON 事件行" '"kind":"event"' "$out"
assert_contains "JSON 文件事件" '"type":"file"' "$out"
assert_not_contains "JSON 无系统调用事件" '"type":"syscall"' "$out"
sleep 0.2

if bash -o pipefail -c 'exec "$1" --socket "$2" events -o json 2>/dev/null | head -1 >/dev/null' \
    _ "$cli" "$socket"; then
    pass "events | head 以 0 退出"
else
    fail_case "events | head 以 0 退出"
fi
sleep 0.2

"$cli" --socket "$socket" events >/dev/null 2>"$err_file" &
cli_pid=$!
sleep 0.2
kill -INT "$cli_pid" 2>/dev/null || true
set +e
wait "$cli_pid"
code=$?
set -e
assert_eq "events SIGINT 退出码" 0 "$code"
assert_contains "events SIGINT 统计" "events:" "$(cat "$err_file")"

echo "停机"

kill -TERM "$server_pid"
set +e
wait "$server_pid"
code=$?
set -e
assert_eq "服务端 SIGTERM 退出码" 0 "$code"
server_pid=

if [ "$fail" -ne 0 ]; then
    echo "FAILED"
    exit 1
fi
echo "ALL PASS"
