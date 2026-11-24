## Event Stream Benchmarking

There are two groups of benchmarks in `test/bench`:

- **Segmented benchmarks**: benchmark the semantic, runtime engine (engine), and CLI delivery (cli) stages separately;
- **Full-chain benchmark (chain)**: run "collection/parsing → semantic → engine → CLI delivery" chained together in one process.

Capacity always means "**the highest input rate without dropping events**"; saturated throughput is for reference only and is not treated as a capability upper limit.
All drops are based on the program's own counters, not estimated.

## Corpus Files

The corpus is **recorded real events**, so benchmarks can reproduce the same batch of events without loading BPF.

Requires root and BPF permissions; only exports records within the statistical window:

    bench_syscalls --dump PATH
    scripts/bench/run_bench.sh --dump PATH

Different event types are distinguished by profile; with multiple profiles, insert the profile name before the extension
(t.trace → t.file.trace).

Format (`test/bench/bench_trace.hpp`; saved in native byte order, usable only on the same machine):

| Part | Content |
|---|---|
| File header | 8-byte marker HNGTRACE + version number 1 + 4 reserved bytes |
| Each record | 4-byte length + raw record of that length |
| End | End of file; no end marker |

The raw record is exactly one entry from the kernel ringbuf: an 80-byte event header + the fixed-length payload for that type.
Each record's length is determined by the same length table on the production side (`hng::detail::SyscallRecordSize`);
chain replay uses it to validate record by record, and length mismatches are marked malformed and skipped.

## Full-Chain Benchmark

chain is **replay-based**: `--trace` must be provided, and records are replayed according to `--rate` (records fed into collection/parsing per second).

    replay thread ──► raw event queue ──► semantic component
       ──► semantic event queue ──► runtime engine
       ──► per-subscription-stream queue ──► CLI server (gRPC) ──► client

- The collector stage is an **equivalent implementation**: it validates using the same length table as the production side, then copies the header and payload into userspace structures in the same way; it is not collector code, so the output marks `collector=replay feeder` (equivalent parsing).
- Two run modes:
  - `--backend sink`: only runs to the engine, with a counting subscription after the engine (no userver needed);
  - `--backend cli`: runs fully to CLI. The CLI server runs in a child process, and the parent process acts only as a client.
  Builds with userver default to cli; otherwise they default to sink.
- **Startup alignment**: CLI server startup takes several seconds. If timing starts as soon as replay begins, the measurement window will include stream establishment time. Therefore, the parent process writes a temporary marker file to notify the child process after "the server is ready and all subscriptions are established"; the child process starts replay and records the start time only after seeing the marker, and both parent and child use this start point to align the same measurement window (the parent uses it to calculate the client side, and the child uses it to calculate per-stage CPU and counters).
  `--warmup` starts from this start point.
- Queues **drop when full** and do not block, so "capacity" = the highest input rate when no stage drops.
- CPU is recorded per thread: the replay/semantic/engine three threads are sampled by the child process by thread ID; CLI server worker threads are sampled by the parent process by thread name; the two control plane (L2) threads are sampled by their own thread IDs and listed separately as the control stage; the "control plane CPU" item in the results (field name `cp cpu`) is the elapsed time of these two threads.
  Control-plane threads are not mixed with CLI server framework threads.
- `--fidelity l1` (default) uses an in-memory stand-in for the control plane; `--fidelity l2` uses real components for the control plane, while the role dimension still uses a stand-in. L2 cost appears in two places: synchronous queries/enqueues occur **in the engine thread** (counted in the engine per-event cost), and the CPU of the other two control-plane threads is listed separately as control.
- The internal control-plane queue depth has no external statistics, so whether there is a backlog can only be inferred indirectly from CPU and its counters.

### How to Read the Output

One run writes five tab-separated result rows (TSV), and prints a summary:

    chain            merged row: engine dispatch count, end-to-end CPU per input event, total drops across all stages
    chain/collector  parsed record count, replay thread CPU, raw event queue peak occupancy
    chain/semantic   semantic processed count, semantic thread CPU, raw event queue drops
    chain/engine     engine dispatch count, engine thread CPU, semantic event queue drops
    chain/cli        client delivered count, CLI worker thread CPU, per-stream queue drops

- Distinguish three rates: **input** (replay records/s), **dispatch** (processed by engine/s), **delivery** (received by client/s). At CLI, one input is copied to each subscription stream, so with 8 streams the delivery count is about 8 times the input count and then discounted; mentioning only one of them is misleading.
- Result fields correspond to the terms above: `events` is the number of events processed by that stage, `events_per_s` is events per second, `us_per_event` is CPU per event, `drops` is drops at that stage, and `peak_queue` is queue peak occupancy.
- Bottleneck determination looks at two things: where drops occur (raw queue drops → semantic slow; semantic queue drops → engine slow; per-stream queue drops → CLI server or client slow), and the CPU utilization of that stage. When the two conflict, mark "undetermined".
- L2 additionally prints an initialization report (how many processes/contexts were loaded, whether executable paths come from the corpus or are synthetic, whether contexts are derived or attached) and control-plane window counters (`stale_add`, `late_register`, `tombstone_depth`, etc.). When drops occur, it warns: half of the control-plane cost is still in the engine thread, so you cannot look only at control-plane thread CPU.

## 2026/11/24 Benchmark Results

The following numbers come from a 16 vCPU dev container (shared host), window 3–10 s, with queue capacity explicitly specified.

**Segmented (single process)**

| Stage | Event composition | Highest rate without drops | CPU per event |
|---|---|---|---|
| Semantic | syscall-type | ~1.0M/s | 1.0–1.2 µs |
| Semantic | all (including exec/lifecycle) | ~0.75M/s | 1.3–1.5 µs |
| Semantic | lifecycle | ~0.66M/s | 1.3–1.5 µs |
| Engine L1 | syscall-type | ~1.4–1.6M/s | 0.6–0.9 µs |
| Engine L1 | all / lifecycle | ~1.1M/s | 0.8–1.1 µs |
| Engine L2 | syscall-type | ~1.5M/s | 0.6–0.9 µs (control plane idle) |
| Engine L2 | lifecycle | ~0.3M/s | engine ~3–5 µs + control plane ~2–3 µs |
| CLI delivery (8 streams) | any | — | delivery ~1.0M/s |
| CLI delivery (1 stream, batch 64) | any | — | delivery ~0.28–0.3M/s |
| CLI delivery (1 stream, batch 1) | any | — | delivery ~8k/s (limited by message count) |

Note: the single-stage semantic numbers are a lower bound for "zero downstream backlog"—its drain thread immediately drains the output queue, requiring one wakeup per event; the downstream (engine) in production usually has a backlog, so the same component is cheaper in the full chain.

**Full chain**

| Configuration | Highest input rate without drops | Client delivery |
|---|---|---|
| Engine only, syscall-type (L1/L2) | ~1.2–1.4M/s | — |
| Engine only, all (L1) | ~1.05–1.1M/s | — |
| Engine only, lifecycle (L1) | ~0.95–1.0M/s | — |
| To CLI, 1 subscription | ~200k/s | ~200k/s |
| To CLI, 8 subscriptions | ~64k/s (96k is borderline) | ~512k–768k/s |
| Total delivery to CLI | — | hard ceiling around 770k/s |

At CLI, the real upper limit is often **total delivery volume** (gRPC serialization + client packet reception, two worker threads), not the control plane or engine; input capacity decreases with the number of subscription streams, and with 8 streams each input event is copied eight times.

A few usage notes:

- Queue capacity must be specified explicitly (e.g. `--queue 32768`). The default 8192 may drop early under host jitter; the tool warns "queue is default size, re-check capacity conclusions with larger --queue".
- Always use `--events syscall` for steady-state capability; lifecycle event replay revives identities of exited processes, and the numbers include the tombstone handling path, so they are only suitable for viewing the unit cost of that class.
- 8 subscriptions and 96k/s input is borderline with the default per-stream queue of 8192; increasing `--cli-queue` or setting `--batch` to 256 can stabilize zero drops.

## Build and Compile

Build inside the devcontainer (userver, libbpf, and other dependencies are all in the container). Benchmarks use a separate `build-bench`: the optimization level matches the release build, and frame pointers are retained for easy perf call stack capture.

    cmake -S . -B build-bench \
      -DCMAKE_BUILD_TYPE=RelWithDebInfo \
      -DCMAKE_CXX_FLAGS_RELWITHDEBINFO="-O2 -g -DNDEBUG -fno-omit-frame-pointer"
    cmake --build build-bench --target bench_event_pipeline bench_syscalls --parallel

- `-DHNG_ENABLE_CLI_SERVER=OFF`: do not build the CLI stage and userver dependencies; the full chain defaults to engine only.
- The collection throughput tool requires root and BPF (`make ebpf` produces `kernel/build/syscalls.bpf.o`); full-chain replay does not require root.
- The build directory is configured inside the devcontainer; switching to the WSL host and running `cmake --build` directly will fail due to inconsistent source paths, and reconfiguration is required.

## Known Limitations

- The full chain currently uses replay and does not load kernel probes; the real collection path is still covered by `hng_agent` and e2e scripts.
- Per-stream queue occupancy in CLI is unobservable (`chain/cli` queue peak is always 0).
- There are no statistics for internal control-plane queue depth; whether L2 has a backlog can only be inferred indirectly from CPU and counters.
- Higher per-event CPU at low rates is the cost of "waking once per event", not the component slowing down; compare costs at similar rates.