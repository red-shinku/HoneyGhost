## 事件流压测

`test/bench` 下的用户态事件流水线压测：分段（semantic / engine / cli）与全链（chain，replay）。
容量口径统一为「0 丢的最高限速」，并用饱和读数作参考；丢弃一律以流水线自带计数器为准。

## 语料文件

语料是真实 ringbuf 记录的原始字节，供不加载 BPF 的压测复用。

生成语料文件（需 root 与 BPF 权限，只导出统计窗口内的记录）：  
```bash
# 两种方式等价
bench_syscalls --dump PATH
scripts/bench/run_bench.sh --dump PATH
```
不同事件类型分为不同 profile。
多个 profile 时在扩展名前插入 profile 名（`t.trace` → `t.file.trace`）。

格式（`test/bench/bench_trace.hpp`，是本机字节序、需同机使用）：

| 部分 | 内容 |
|---|---|
| 文件头 | 8 字节 magic `HNGTRACE` + uint32 version=1 + uint32 保留 0 |
| 记录 | uint32 size（1..65535）+ size 字节负载 |
| 结束 | EOF；无尾记录 |

负载就是 ringbuf 记录原文：`syscall_event_head`（80 字节）+ 该 subtype 的定长载荷；

## chain 压测架构

chain 为 agent 用户态的完整事件流处理。

chain 需从语料回放事件：要指定 `--trace`，按 `--rate`（输入侧collector，事件每秒）回放。

```
feeder ──► raw EventChannel<syscall_event> ──► SemanticComponent
   ──► semantic EventChannel<syscall_semantic_data> ──► RuntimeEngineComponent
   ──► CLIStream（真实队列/唤醒） ──► userver gRPC ──► 客户端
```

- 采集段是 **等价解析**：生产侧同一张 `SyscallRecordSize` 校验 + head/载荷两段 memcpy，
  输出里标注 `collector=replay feeder（等价解析）`，不是 collector 代码本身。
- 两个后端：`--backend sink`（无 userver，链路到引擎为止，计数订阅）与
  `--backend cli`（子进程跑完整链 + 真实 `RunCliServer`，父进程只做客户端）。
  有 userver 构建默认 cli，无则默认 sink；`--backend cli` 在无 userver 构建下报错。
- 窗口对齐用 go 文件握手：父进程等服务端就绪且所有订阅流登记完成后写 go；
  子进程收到 go 才取 T0、启动 feeder，写 T0、按 T0 在窗口两端快照并写侧车。
  父进程用同一 T0 采客户端计数与 `cli-tp` 的 CPU。`--warmup` 从 T0 起算。
- 通道都是满即丢（非阻塞），因此容量为所有接缝 0 丢的最高输入速率。
- 每段成本按线程窗口 CPU 记账：feeder / semantic / engine 由子进程自测（侧车），
  `cli-tp` 由父进程按 comm 采集，客户端 CPU 只用于判断压测器是否成为瓶颈。

输出：一次运行写五行 TSV，并打印汇总：

```
TSV chain            合并行：dispatched、端到端 µs/输入事件、接缝丢弃合计
TSV chain/collector  已消费记录数、feeder CPU、raw 通道峰值
TSV chain/semantic   语义已处理数、语义线程 CPU、raw 接缝丢弃
TSV chain/engine     分发数、引擎线程 CPU、语义通道接缝丢弃
TSV chain/cli        客户端交付数、cli-tp CPU、CLI 接缝丢弃
```

汇总同时给 input / dispatched / delivered 三个速率与 fan-out 比值
（8 条流时每个输入事件分发到 8 条流，input 容量约为 delivered 的 1/8 再打折）。
瓶颈判定用两条独立证据：接缝丢弃落在哪（raw 丢→语义慢、语义通道丢→引擎慢、
CLI 丢→cli-tp/客户端慢）与该段 CPU 利用率；两者冲突时标「未定」。

已知边界：

- chain 目前只 L1 控制面（`--fidelity l2` 未接入）。
- 生命周期事件的回放会复活已退出的进程身份，触发墓碑路径；稳态容量用
  `--events syscall`，其余类别只用于看该类事件的单位成本。
- CLI 后端看不到每流队列占用（`chain/cli` 的 peak_queue 恒 0）；
  低速率下 `us/event` 偏高是每事件唤醒成本，不是组件变慢。

几个典型用法：

```sh
# 至引擎（无 userver 也可用），找 0 丢容量
build-bench/test/bench_event_pipeline --stage chain --trace /tmp/p1.mixed.trace \
  --backend sink --events syscall --queue 32768 --rate 1000000

# 全链到 CLI：8 条流、每条 2000/s 输入
build-bench/test/bench_event_pipeline --stage chain --trace /tmp/p1.mixed.trace \
  --streams 8 --batch 64 --rate 16000 --queue 32768 --seconds 10 --out chain.tsv
```

## 构建编译

在 devcontainer 内构建（userver/libbpf 等依赖在容器里）。压测用独立的构建输出目录
`build-bench`：RelWithDebInfo 与发布档一致，并带 frame pointer 以便 perf 取调用栈。

```sh
cmake -S . -B build-bench \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_CXX_FLAGS_RELWITHDEBINFO="-O2 -g -DNDEBUG -fno-omit-frame-pointer"
cmake --build build-bench --target bench_event_pipeline bench_syscalls --parallel
```

- `-DHNG_ENABLE_CLI_SERVER=OFF`：不构建 CLI 段与 userver 依赖；chain 默认 `--backend sink`。
- 采集吞吐工具需要 root 与 BPF（`make ebpf` 产出 `kernel/build/syscalls.bpf.o`）
- 构建目录是 devcontainer 配置的，在 WSL 宿主直接 `cmake --build` 会因源码路径不一致失败；
  换环境时重新跑 configure。