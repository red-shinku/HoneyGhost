# HoneyGhost

![C++17](https://img.shields.io/badge/C%2B%2B-17-00599C?logo=cplusplus&logoColor=white)
![C++20](https://img.shields.io/badge/C%2B%2B-20-00599C?logo=cplusplus&logoColor=white)
![Go 1.26](https://img.shields.io/badge/-Go%201.26-00ADD8?logo=go&logoColor=white)
![eBPF](https://img.shields.io/badge/-eBPF-00AEEF?logo=ebpf&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-blue)

**English** | [简体中文](README.cn.md)

HoneyGhost is an eBPF-based runtime monitoring agent for Linux. It collects
system-call and file events from the kernel, maintains a live view of processes,
roles (systemd services and containerd containers) and contexts, and exposes
that view — together with a filtered event stream — through a local Unix socket
to the `hghost` command-line client.

> **Project status:** Currently, only the basic architecture has been completed. Advanced features are still in planning/development and are expected to include security policies, intrusion detection, etc. Configuration, CLI output, and protocol formats may change across versions. For currently available capabilities, see [Project status](#project-status)
> for what works today.

> I hope it can be a sweet-honey-softly ghost on your server... in the future. There is a far way to go, and for me, still many things to know.

## Features

- **Kernel-side collection** — eBPF probes for syscalls, file access and
  outbound network connections. A shared event header carries parent-process
  identity for attribution.
- **Role-aware filtering** — a user-space role filter supplies the process
  allow/deny list to the kernel, so only selected workloads generate events.
  The default is deny: without a whitelist, ordinary events are not collected.
- **Semantic normalization** — raw kernel records are converted into a stable,
  typed event model before they reach consumers.
- **Control plane** — a process tree with virtual roots for orphaned processes,
  role discovery backed by systemd and containerd, and context derivation from
  exec and environment information.
- **Streaming query plane** — a gRPC server embedded in the agent (optional at
  build time), per-stream queues and a global concurrent-stream quota, and
  filters by role, context, PID and event type.
- **Local CLI** — `hghost` queries roles, contexts, processes and counters, or
  streams events as a table or as JSON Lines.

## Architecture

```
kernel probes ──► Collector ──► Semantic ──► RuntimeEngine ──► CLI streams ──► hghost
                                                  │
                                                  ▼
                                   Control plane (Process / Context / Role)
                                                  ▲
                                                  │
                              Role discovery (systemd / containerd)
```

The kernel side produces raw records; user-space collectors feed them through
the semantic layer into the runtime engine, which updates the control plane and
fans events out to registered CLI streams. Role discovery runs beside this
path and feeds the role manager.

Roughly, a *role* identifies a workload by its systemd unit or container image,
while a *context* groups processes that belong together according to exec and
environment rules.

| Path | Responsibility |
| --- | --- |
| `kernel/` | eBPF probes and shared kernel headers |
| `agent/collector/` | ring-buffer consumption and raw event queues |
| `agent/semantic/` | normalization into typed semantic events |
| `agent/control_plane/` | process, context and role managers and their stores |
| `agent/context_maintainer/` | context derivation rules |
| `agent/role_discovery/` | systemd and containerd role discovery, plus the containerd bridge |
| `agent/role_filter/` | allow/deny rules and the kernel process filter map |
| `agent/runtime_engine/` | event dispatch, runtime information and subscription fan-out |
| `agent/cli_server/` | gRPC query and streaming services |
| `agent/assembly/` | component graph, initialization barrier, threads and shutdown |
| `agent/config/` | configuration document and schema |
| `cli/` | Go `hghost` client |
| `proto/` | event and CLI protocol definitions |
| `test/`, `scripts/`, `deploy/` | tests, helper scripts and deployment assets |

## Requirements

- Linux on x86_64, kernel 5.8 or newer, with BTF
  (`/sys/kernel/btf/vmlinux`) and tracefs mounted. The probes use ring buffer
  maps (5.8+); older kernels are rejected at startup with the unmet requirement
  in the log.
- Root, or at least `CAP_BPF` and `CAP_PERFMON`; loading probes and reading some
  kernel state requires elevated privileges.
- For C++ builds: CMake ≥ 3.16, a C++17 compiler (C++20 for the CLI server),
  `clang` and `bpftool`, libbpf, protobuf, libsystemd (optional), fmt 11 and
  spdlog. userver 3.x is required when the CLI server is enabled.
- For the Go programs: Go ≥ 1.26.3. Regenerating protocol code additionally
  needs `protoc` with `protoc-gen-go` and `protoc-gen-go-grpc`.

The dev container in `.devcontainer/` provides this toolchain; see
[`.devcontainer/README.md`](.devcontainer/README.md) for setup details.

## Build

The `Makefile` at the repository root is the single build entry point.

```sh
make agent   # C++ agent and eBPF probes/skeletons
make ebpf    # eBPF only (a subset of agent)
make go      # Go containerd bridge and hghost CLI, output in bin/
make all     # agent + go
make test    # C++ unit tests (ctest)
make test-go # Go unit tests
```

A first build inside the dev container:

```sh
make ebpf                  # generate vmlinux.h and *.skel.h
scripts/install-userver.sh # install userver into the container volume
make agent
make go
```

`vmlinux.h` is generated from the build host's BTF, so artifacts built on
different kernels are not byte-identical.

The CLI server is enabled by default, which makes `make agent` require userver.
Point CMake at an existing install with `-Duserver_ROOT=<prefix>`, or disable
the CLI server and build the rest:

```sh
cmake -S . -B build-agent -DHNG_ENABLE_CLI_SERVER=OFF
cmake --build build-agent --parallel
```

With that option, set `[cli] enabled = false` in `agent.conf`; otherwise
`hng_agent` refuses to start.

## Run

```sh
sudo mkdir -p /run/honeyghost
sudo ./build-agent/hng_agent --config config/agent.conf
```

`hng_agent` accepts only `--config PATH` and `-h/--help`. If `--config` is
omitted, it reads `$HNG_CONFIG`, then `/etc/honeyghost/agent.conf`. Paths
inside the main configuration file (role filter and CLI server configs) are
resolved relative to that file's directory.

In another terminal:

```sh
bin/hghost status
bin/hghost role list
bin/hghost events -t syscall,file
```

The agent creates the CLI socket at `/run/honeyghost/cli.sock` by default.
Adjust `[cli] socket_path` or `[cli_server] socket_path` if needed; the socket
file's permissions are the only access control. Because the agent runs as root
in this example, the socket is root-owned; run `hghost` with sufficient
privileges or adjust the socket permissions.

The sample configuration enables both discovery sources. The systemd source
works on a normal host; container roles additionally require the containerd
bridge (`agent/role_discovery/containerd_bridge/`). If the bridge is not
running, startup continues after the role-source timeout, but container roles
are missing. Disable discovery sources the host does not provide: set
`[role_discovery] containerd = false`, or `systemd = false` on a host without
systemd.

## Configuration

Sample files live in `config/`:

| File | Purpose |
| --- | --- |
| `agent.conf` | collection switches, discovery sources, paths to the role filter and CLI server configs, CLI on/off and socket override |
| `role_filter.conf` | exact/regex whitelist and blacklist of role labels; blacklist wins; **ordinary events are denied by default** |
| `cli_server.conf` | concurrent stream limit, queue capacity, drain timeout and CLI socket path |

`agent.conf`:

```ini
[collector]
enabled = true

[role_discovery]
systemd = true
containerd = true
containerd_socket_path = /run/honeyghost/containerd-bridge.sock

[role_filter]
path = role_filter.conf

[cli]
# Must be false when the CLI server was not compiled in.
enabled = true
# Empty means: keep the socket path from the CLI server config.
socket_path =
config = cli_server.conf
```

`role_filter.conf`:

```ini
[whitelist]
exact: nginx.service
regex: registry/example/honeypot:v1\..*

[blacklist]
exact: registry/example/honeypot:v1.debug
```

- A role label comes from the discovery source: a systemd unit name or a
  container image label.
- `exact` matches the full role label; `regex` is a case-sensitive
  ECMAScript full-string match.
- Blacklist entries override whitelist entries. With an empty whitelist, no
  ordinary events are collected. Edit the file to match the workloads you want
  to observe; with the sample rules, only `nginx.service` and labels matching
  the container regex are collected.
- Precedence is built-in defaults < configuration file < environment variables.
  Every key can be overridden with `HNG_<SECTION>_<KEY>` in upper case (for
  example `HNG_COLLECTOR_ENABLED=false`); `HNG_CONFIG` selects the main
  configuration file.
- Unknown sections and keys are rejected at startup.

## CLI

```
hghost [global flags] <resource> <action> [arguments] [flags]
hghost [global flags] <standalone command> [arguments] [flags]
```

| Global flag | Default | Meaning |
| --- | --- | --- |
| `--socket` | `$HGHOST_SOCKET`, otherwise `/run/honeyghost/cli.sock` | Unix socket path |
| `--timeout` | `5s` | deadline for unary commands; `0` disables it |
| `-o, --output` | `table` | `table` or `json` |
| `--no-headers` | `false` | omit the table header |

Examples:

```sh
hghost status
hghost role list -a
hghost role show nginx:1.25
hghost role which 1234
hghost context list -k excep,extra
hghost process stats
hghost events -i role=nginx:1.25 -i pid=1234
hghost events --duration 30s -o json | jq 'select(.kind == "event")'
```

See [`cli/README.md`](cli/README.md) for the full command reference, output
formats and exit codes.

## Deployment

A single-machine Docker Compose example is available at [`deploy/docker`](deploy/docker/README.md). It builds the agent image and the containerd translation process image, then mounts the host's `/run/honeyghost`, D-Bus socket, and tracefs into the agent container.

```sh
sudo mkdir -p /run/honeyghost
docker compose up
bin/hghost --socket /run/honeyghost/cli.sock status
```

### Obtaining Images

```sh
docker pull fifseason/honeyghost-agent:latest  
docker pull fifseason/honeyghost-containerd-bridge:latest
```

### Local Build

From the project root directory:
```sh
make image
```

The agent container currently needs `privileged: true`; the minimum capability
set is still being validated. The Docker README lists host prerequisites and
known limitations.

## Testing

```sh
make test                 # C++ unit tests
make test-go              # Go unit tests, with -race
scripts/test-cli-e2e.sh   # end-to-end test against the C++ CLIServer
```

Some checks must run on the host with root privileges because they load probes
or connect to real system services: `verify_starttime`, `verify_role_systemd`
and `verify_role_containerd`.

## Project status

- Syscall and file events are wired end to end. A network probe exists in the
  kernel, but network and IPC events are not semanticized yet, so they do not
  appear in `hghost events` today.
- The anomaly detector (`agent/detector/`) is not wired into the runtime yet;
  only its `Score` structure is used by the context maintainer.
- The agent is Linux-only and currently x86_64-only; the eBPF probes are
  compiled with `-D__TARGET_ARCH_x86`.
- The CLI server has no authentication or TLS. It listens on a local Unix
  socket, and socket file permissions are the access control.
- The CLI event stream ends when the connection drops; it does not silently
  resume.

## Documentation

- [CLI reference](cli/README.md)
- [Docker deployment](deploy/docker/README.md)
- [Development container](.devcontainer/README.md)

## Credits and License

[LINUX DO](https://linux.do/) ; [MIT](LICENSE)
