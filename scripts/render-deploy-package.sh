#!/bin/sh
# 由 deploy/docker 的清单生成发布用部署包：镜像引用换成仓库地址 + digest，
# 并去掉 build 段（发布包不提供源码构建）。
#
#   scripts/render-deploy-package.sh <版本> <agent 引用> <bridge 引用> <输出目录>
#
# 例：scripts/render-deploy-package.sh 0.1.0 \
#       fifseason/honeyghost-agent@sha256:... \
#       fifseason/honeyghost-containerd-bridge@sha256:... dist
#
# 两个镜像引用必须是 digest 形式；替换次数不符、残留 hng/ 引用或 build 段时
# 直接失败，不产出部署包。产物：<输出目录>/honeyghost-deploy_<版本>.tar.gz

set -eu

version=${1:?usage: render-deploy-package.sh VERSION AGENT_REF BRIDGE_REF OUT_DIR}
agent_ref=${2:?}
bridge_ref=${3:?}
out_dir=${4:?}

[ -n "$version" ] || { echo "版本号不能为空" >&2; exit 1; }
case "$agent_ref" in
    *@sha256:*) ;;
    *) echo "agent 引用必须按 digest 固定：$agent_ref" >&2; exit 1 ;;
esac
case "$bridge_ref" in
    *@sha256:*) ;;
    *) echo "bridge 引用必须按 digest 固定：$bridge_ref" >&2; exit 1 ;;
esac

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
stage="$out_dir/honeyghost-deploy_$version"
trap 'rm -rf "$stage"' EXIT

rm -rf "$stage"
mkdir -p "$stage/config"

# 替换按 image 行的取值匹配，保留该行原有缩进；build 段按缩进判定整段删除，
# 因此清单改缩进或改顺序都不影响结果。替换次数与残留引用在下面逐项校验。
{
    cat <<'HEADER'
# ============================================================
# HoneyGhost 发布部署包
#
# 镜像按 digest 固定，不提供源码构建。首次部署：
#   sudo mkdir -p /run/honeyghost
#   docker compose up -d
#
# 宿主 Docker 用传统镜像存储（overlay2）时追加：
#   docker compose -f docker-compose.yaml \
#                  -f docker-compose.docker-api.yaml up -d
# ============================================================
HEADER
    awk -v agent_ref="$agent_ref" -v bridge_ref="$bridge_ref" '
        function lead(s) { match(s, /^[[:space:]]*/); return RLENGTH }
        function fail(msg) {
            print "render-deploy-package: " msg > "/dev/stderr"
            exit 1
        }
        BEGIN { body = 0; skip = 0; n_agent = 0; n_bridge = 0 }
        {
            # 原文件开头的构建说明不适用于发布包，逐行丢弃，不依赖某个键的位置
            if (!body) {
                if ($0 ~ /^[[:space:]]*(#|$)/) next
                body = 1
            }
            if (skip) {
                if ($0 ~ /^[[:space:]]*$/ || lead($0) > skip_indent) next
                skip = 0
            }
            if ($0 ~ /^[[:space:]]*image:[[:space:]]*hng\/agent(:[^[:space:]]*)?[[:space:]]*$/) {
                printf "%simage: %s\n", substr($0, 1, lead($0)), agent_ref
                ++n_agent
                next
            }
            if ($0 ~ /^[[:space:]]*image:[[:space:]]*hng\/containerd-bridge(:[^[:space:]]*)?[[:space:]]*$/) {
                printf "%simage: %s\n", substr($0, 1, lead($0)), bridge_ref
                ++n_bridge
                next
            }
            if ($0 ~ /^[[:space:]]*build:[[:space:]]*$/) {
                skip_indent = lead($0)
                skip = 1
                next
            }
            print
        }
        END {
            if (n_agent != 1) fail("agent 镜像行替换 " n_agent " 次（期望 1）")
            if (n_bridge != 1) fail("bridge 镜像行替换 " n_bridge " 次（期望 1）")
        }
    ' "$root/deploy/docker/docker-compose.yaml"
} > "$stage/docker-compose.yaml"

if grep -nE 'hng/|^[[:space:]]*build:' "$stage/docker-compose.yaml"; then
    echo "部署清单仍含开发用引用或 build 段：$stage/docker-compose.yaml" >&2
    exit 1
fi

cp "$root/deploy/docker/docker-compose.docker-api.yaml" "$stage/"

# sidecar 片段给的是镜像名，替换为同一 digest 的引用；替换次数同样要校验
sidecar_src="$root/agent/role_discovery/containerd_bridge/deploy/containerd-bridge-sidecar.yaml"
sidecar_dst="$stage/containerd-bridge-sidecar.yaml"
sed -e "s|image: hng/containerd-bridge:latest|image: $bridge_ref|" \
    "$sidecar_src" > "$sidecar_dst"
if grep -q 'hng/containerd-bridge' "$sidecar_dst"; then
    echo "sidecar 片段未替换镜像引用：$sidecar_dst" >&2
    exit 1
fi

cp "$root"/deploy/docker/config/*.conf "$stage/config/"

tar -C "$out_dir" -czf "$out_dir/honeyghost-deploy_$version.tar.gz" \
    "honeyghost-deploy_$version"

echo "$out_dir/honeyghost-deploy_$version.tar.gz"
