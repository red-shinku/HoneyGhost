#!/bin/sh
# 由仓库内所有 go module 生成 go.work。
#
# go.work 不进版本控制（见 .gitignore）：它记录的是本机工作区的模块位置，
# 各 module 的依赖版本仍由各自的 go.mod / go.sum 决定。增删 module 后重新运行本脚本。
#
# 模块列表取自 `git ls-files --cached --others --exclude-standard`，尊重 .gitignore，
# 故构建产物与生成物目录（build-agent/、bin/、html/、latex/）自动排除，无需维护排除表。
#
# go 指令取各 go.mod 中 go 版本的最大值，避免低于任一 module 的要求。
# 输出按路径排序且幂等：内容无变化时不改写文件。

set -eu

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
cd "$root"

out=$root/go.work

mods=$(git ls-files --cached --others --exclude-standard \
       | grep -E '(^|/)go\.mod$' \
       | sed -e 's|^go\.mod$|.|' -e 's|/go\.mod$||' \
       | sort)

if [ -z "$mods" ]; then
    echo "未找到任何 go.mod，不生成 go.work" >&2
    exit 1
fi

gover=$(printf '%s\n' "$mods" \
        | while IFS= read -r d; do awk '$1 == "go" { print $2; exit }' "$d/go.mod"; done \
        | sort -V | tail -n 1)
if [ -z "$gover" ]; then
    gover=$(go env GOVERSION | sed 's/^go//')
fi

tmp=$out.tmp
{
    printf '// 由 scripts/gen-go-work.sh 生成，请勿手工编辑。\n'
    printf '// go.work 不进版本控制；增删 go module 后重新运行该脚本。\n'
    printf '\n'
    printf 'go %s\n' "$gover"
    printf '\n'
    printf 'use (\n'
    printf '%s\n' "$mods" | while IFS= read -r d; do
        if [ "$d" = "." ]; then
            printf '\t.\n'
        else
            printf '\t./%s\n' "$d"
        fi
    done
    printf ')\n'
} > "$tmp"

if [ -f "$out" ] && cmp -s "$tmp" "$out"; then
    rm -f "$tmp"
    echo "go.work 无变化（模块数 $(printf '%s\n' "$mods" | wc -l)）"
else
    mv "$tmp" "$out"
    echo "已生成 go.work："
    sed 's/^/  /' "$out"
fi
