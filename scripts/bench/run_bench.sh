#!/usr/bin/env bash
# syscalls 探针吞吐压测的编排脚本。
#
# 逐 profile 调用 bench_syscalls，把每行的 TSV 结果追加到 --out，最后打印汇总表。
# 需要 root 与 BPF 权限；构建产物在 <build-dir>/test/bench_syscalls（默认
# build-bench）。
#
# 用法：
#   sudo scripts/bench/run_bench.sh [选项]
#   sudo scripts/bench/run_bench.sh --build --seconds 5 --profiles file,exec
#   sudo scripts/bench/run_bench.sh --profiles file --dump /tmp/file.trace

set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "$script_dir/../.." && pwd)

usage() {
    cat <<'EOF'
用法: sudo scripts/bench/run_bench.sh [选项]
  --obj PATH        传给 bench_syscalls
  --seconds N       每个 profile 的压测时长（默认 10）
  --workers N       并发 worker 数（默认 nproc/2）
  --profiles LIST   逗号分隔，默认 file,process,exec,memory,network,mixed
  --out FILE        结果写到该文件（默认 docs/plan/bench_syscalls_<UTC 日期>.tsv）
  --build-dir DIR   构建目录（默认 build-bench，相对仓库根）
  --build           先配置（缺 CMakeCache.txt 时）并构建 bench_syscalls
  --dump PATH       语料路径；单 profile 原样使用，多 profile 在扩展名前插入 profile 名
  --skip-missing    允许缺失的 tracepoint 被跳过（默认总是允许，保留参数只为兼容）
EOF
}

die() {
    echo "错误：$*" >&2
    exit 2
}

fail() {
    echo "错误：$*" >&2
    exit 1
}

cpu_count=$(nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)
workers=$((cpu_count / 2))
if [ "$workers" -lt 1 ]; then
    workers=1
fi

obj="$repo_root/kernel/build/syscalls.bpf.o"
seconds=10
profiles=file,process,exec,memory,network,mixed
out=""
build_dir="$repo_root/build-bench"
dump=""
build=0

while [ "$#" -gt 0 ]; do
    case "$1" in
        --obj)
            if [ "$#" -lt 2 ]; then
                echo "错误：--obj 缺少路径" >&2
                exit 3
            fi
            obj=$2
            shift 2
            ;;
        --obj=*)
            obj=${1#*=}
            shift
            ;;
        --seconds)
            if [ "$#" -lt 2 ]; then
                echo "错误：--seconds 缺少取值" >&2
                exit 3
            fi
            seconds=$2
            shift 2
            ;;
        --seconds=*)
            seconds=${1#*=}
            shift
            ;;
        --workers)
            if [ "$#" -lt 2 ]; then
                echo "错误：--workers 缺少取值" >&2
                exit 3
            fi
            workers=$2
            shift 2
            ;;
        --workers=*)
            workers=${1#*=}
            shift
            ;;
        --profiles)
            if [ "$#" -lt 2 ]; then
                echo "错误：--profiles 缺少列表" >&2
                exit 3
            fi
            profiles=$2
            shift 2
            ;;
        --profiles=*)
            profiles=${1#*=}
            shift
            ;;
        --out)
            if [ "$#" -lt 2 ]; then
                echo "错误：--out 缺少路径" >&2
                exit 3
            fi
            out=$2
            shift 2
            ;;
        --out=*)
            out=${1#*=}
            shift
            ;;
        --build-dir)
            if [ "$#" -lt 2 ]; then
                echo "错误：--build-dir 缺少目录" >&2
                exit 3
            fi
            build_dir=$2
            shift 2
            ;;
        --build-dir=*)
            build_dir=${1#*=}
            shift
            ;;
        --dump)
            if [ "$#" -lt 2 ]; then
                echo "错误：--dump 缺少路径" >&2
                exit 3
            fi
            dump=$2
            shift 2
            ;;
        --dump=*)
            dump=${1#*=}
            shift
            ;;
        --build)
            build=1
            shift
            ;;
        --skip-missing)
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "错误：未知选项 $1" >&2
            usage >&2
            exit 3
            ;;
    esac
done

if [ -z "$build_dir" ]; then
    echo "错误：--build-dir 不能为空" >&2
    exit 3
fi
case "$build_dir" in
    /*) ;;
    *) build_dir="$repo_root/$build_dir" ;;
esac

if ! [[ "$seconds" =~ ^[1-9][0-9]*$ ]]; then
    echo "错误：--seconds 需为正整数" >&2
    exit 3
fi
if ! [[ "$workers" =~ ^[1-9][0-9]*$ ]]; then
    echo "错误：--workers 需为正整数" >&2
    exit 3
fi
if [ -z "$profiles" ]; then
    echo "错误：--profiles 不能为空" >&2
    exit 3
fi
if [ -z "$out" ]; then
    out="$repo_root/docs/plan/bench_syscalls_$(date -u +%Y%m%d).tsv"
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "错误：需要 root 与 BPF 权限" >&2
    if command -v sudo >/dev/null 2>&1; then
        echo "请用：sudo $0 [选项]" >&2
    else
        echo "未找到 sudo，无法提权：请以 root 身份直接运行" >&2
    fi
    exit 2
fi

if [ "$build" -eq 1 ]; then
    echo "== 构建 bench_syscalls（$build_dir）=="
    if [ ! -f "$build_dir/CMakeCache.txt" ]; then
        (cd "$repo_root" && cmake -S . -B "$build_dir" \
            -DCMAKE_BUILD_TYPE=RelWithDebInfo \
            -DCMAKE_CXX_FLAGS_RELWITHDEBINFO="-O2 -g -DNDEBUG -fno-omit-frame-pointer")
    fi
    (cd "$repo_root" && cmake --build "$build_dir" --target bench_syscalls \
        --parallel)
fi

bin="$build_dir/test/bench_syscalls"
if [ ! -x "$bin" ]; then
    die "找不到可执行文件 $bin；先构建：
  cmake --build $build_dir --target bench_syscalls
或在脚本中加 --build"
fi
if [ ! -r "$obj" ]; then
    die "找不到 BPF 对象 $obj；先执行 make ebpf"
fi

out_dir=$(dirname -- "$out")
mkdir -p "$out_dir"

echo "== 机器指纹 =="
printf 'kernel   : %s\n' "$(uname -r)"
printf 'cpus     : %s\n' "$cpu_count"
model=$(lscpu 2>/dev/null | sed -n 's/^Model name:[[:space:]]*//p' | head -n 1 || true)
if [ -z "$model" ]; then
    model=$(awk -F': ' '/^model name/{print $2; exit}' /proc/cpuinfo)
fi
printf 'cpu model: %s\n' "${model:-未知}"
printf 'memory   : %s\n' "$(awk '/^MemTotal:/{printf "%.1f GiB", $2 / 1048576}' /proc/meminfo)"
echo "object   : $obj"
echo "profiles : $profiles"
echo "seconds  : $seconds  workers: $workers"
echo "out      : $out"

work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT

IFS=',' read -r -a profile_list <<< "$profiles"
profile_count=${#profile_list[@]}
summary=()
index=0

for profile in "${profile_list[@]}"; do
    if [ -z "$profile" ]; then
        die "--profiles 含空项"
    fi
    index=$((index + 1))
    log="$work_dir/$index.log"
    echo
    echo "== profile=$profile =="

    profile_dump=$dump
    if [ -n "$dump" ] && [ "$profile_count" -gt 1 ]; then
        profile_dump_dir=$(dirname -- "$dump")
        if [ "$profile_dump_dir" = "." ]; then
            profile_dump_dir=""
        else
            profile_dump_dir="$profile_dump_dir/"
        fi
        profile_dump_base=$(basename -- "$dump")
        case "$profile_dump_base" in
            ?*.*)
                profile_dump="$profile_dump_dir${profile_dump_base%.*}.$profile"
                profile_dump="$profile_dump.${profile_dump_base##*.}"
                ;;
            *)
                profile_dump="$profile_dump_dir$profile_dump_base.$profile"
                ;;
        esac
    fi

    bench_args=(--obj "$obj" --profile "$profile" --seconds "$seconds"
        --workers "$workers")
    if [ -n "$profile_dump" ]; then
        bench_args+=(--dump "$profile_dump")
    fi
    if ! "$bin" "${bench_args[@]}" >"$log" 2>&1; then
        cat "$log" >&2
        fail "profile=$profile 压测失败"
    fi
    cat "$log"
    if ! grep -q '^TSV' "$log"; then
        fail "profile=$profile 未输出 TSV 行"
    fi
    if [ ! -s "$out" ]; then
        printf '#\tprofile\tworkers\tseconds\trecords\tbytes\trec_per_s\tmib_per_s\tus_per_event\treserve_failures\tpending_lost\n' >> "$out"
    fi
    grep '^TSV' "$log" >> "$out"
    summary+=("$(grep '^TSV' "$log" | head -n 1)")
done

echo
echo "== 汇总 =="
printf '%-10s %14s %10s %18s %14s\n' \
    profile rec/s MiB/s reserve_failures pending_lost
for line in "${summary[@]}"; do
    IFS=$'\t' read -r _ profile _ _ _ _ rec_per_s mib_per_s _ reserve pending <<< "$line"
    printf '%-10s %14s %10s %18s %14s\n' \
        "$profile" "$rec_per_s" "$mib_per_s" "$reserve" "$pending"
done
echo "结果已追加到 $out"
