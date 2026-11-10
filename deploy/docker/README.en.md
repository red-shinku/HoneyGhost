# HoneyGhost Agent Docker Deployment

**English** | [简体中文](README.md)

## Build

```sh
# Both images together
docker compose -f deploy/docker/docker-compose.yaml build

# Build only the agent
docker build -f deploy/docker/agent.Dockerfile -t hng/agent:dev .

# Build only the translation process
docker build -t hng/containerd-bridge:dev agent/role_discovery/containerd_bridge
```
The agent image only compiles this repository's sources: the toolchain, fmt/spdlog and userver come from
`ghcr.io/fifseason/honeyghost-builder:latest` (both Release and Debug variants); the first build is dominated by pulling that image.
Use `--build-arg BUILDER_IMAGE=<image>` to switch build environments; rebuild the builder image from
`deploy/ci/builder.Dockerfile`. `make image` builds both images as well.

## Run

```sh
sudo mkdir -p /run/honeyghost
# AppArmor hosts only: load the agent's profile, see "Permissions"
sudo apparmor_parser -r deploy/docker/apparmor/hng-agent
docker compose -f deploy/docker/docker-compose.yaml up -d

# Host-side client (make go produces bin/hghost)
bin/hghost --socket /run/honeyghost/cli.sock <subcommand>
```

## Host Prerequisites

| Prerequisite | Purpose | When Missing |
| --- | --- | --- |
| Host kernel ≥ 5.8 | ring buffer maps and other probe features | Startup preflight fails and reports the version |
| `/sys/kernel/btf/vmlinux` | CO-RE relocation | Agent fails at startup |
| tracefs (`/sys/kernel/tracing`) | tracepoint IDs | Probe attach fails |
| `/run/containerd/containerd.sock` | containerd role discovery | Bridge process exits |
| `/run/dbus/system_bus_socket` | systemd role discovery | Agent cannot connect to the bus, discovery source times out |
| AppArmor host with the `hng-agent` profile loaded | allows system bus calls and reading exe in the snapshot | container does not start when the profile is missing; with `docker-default` bus calls and exe reads are denied |

For nodes without containerd or systemd: disable the corresponding discovery source in the configuration, and remove the unneeded services and mounts from compose.

### Image reference

A container role's label is its image reference. When the host Docker uses the legacy image store (`docker info` shows `Storage Driver: overlay2`), the reference is not recorded in containerd and the bridge has to look it up through the Docker API:

```sh
docker compose -f deploy/docker/docker-compose.yaml \
               -f deploy/docker/docker-compose.docker-api.yaml up -d
```

That override mounts `/var/run/docker.sock` read-only into the bridge container and enables `-docker-socket`. Hosts using the containerd image store (`driver-type: io.containerd.snapshotter.v1`) do not need it; without the Docker socket mount the bridge never talks to Docker.

## Configuration

The three files in `deploy/docker/config/` are mounted into the container at `/etc/honeyghost`:

- `agent.conf`: collection switches, discovery source switches, bridge socket path, role filtering, and references to the CLI configuration;
- `role_filter.conf`: allow/deny lists, deny ordinary events by default;
- `cli_server.conf`: concurrent streams, queue capacity, drain timeout, CLI socket path.

Relative paths are based on the directory containing `agent.conf`, so references inside the container can simply use filenames in the same directory.

## Permissions

The agent container starts from `cap_drop: ALL` and adds four capabilities:

| Capability | Purpose |
| --- | --- |
| `CAP_BPF` | creating maps and loading probes |
| `CAP_PERFMON` | loading tracing programs and `perf_event_open` attach |
| `CAP_SYS_PTRACE` | reading `/proc/<pid>/exe` for the startup snapshot; processes owned by another uid also need AppArmor to allow ptrace, see below |
| `CAP_SETPCAP` | clearing the bounding set so capabilities cannot come back through `execve` |

Once initialization finishes — probes attached and snapshot read — the process will drops every capability.

### AppArmor

`docker-default` denies two things the agent relies on: calls to the system bus (`Hello`, `AddMatch`, `Subscribe`, `ListUnits`, `Properties.GetAll`), and the `ptrace` needed to read `/proc/<pid>/exe` of host processes.

`deploy/docker/apparmor/hng-agent` takes `docker-default` as its baseline and allows only those two groups, in two stages:

| Profile | Used for | Extra over the other |
| --- | --- | --- |
| `hng-agent` | entry; the one compose refers to via `security_opt` | `ptrace (read)` for the snapshot (any peer), and `change_profile -> hng-agent-steady` |
| `hng-agent-steady` | entered by the process once initialization finishes (A failed switch is only logged) | — |

Load it on the host first (see "Run"); profiles are per thread:

```sh
sudo apparmor_parser -r deploy/docker/apparmor/hng-agent
```

A few `ptrace` denials may still show up after initialization (`requested_mask="read"`, peer `unconfined`): libsystemd reads `/proc/<pid>/exe` while collecting bus peer credentials, and sd-bus degrades gracefully when it cannot.

### SELinux

On SELinux hosts Docker puts the container under `container_t` by default, and the agent does not run there either: sending system bus messages, reading `exe` of host processes, and writing the bind-mounted `/run/honeyghost` (unless that directory is relabeled) are all denied by type enforcement — the symptom is `avc: denied` in `audit.log`, not an AppArmor record in `dmesg`.

On those hosts the agent container needs SELinux labeling turned off (add this to the agent service):

```yaml
security_opt:
  - label=disable
```

The cost is the same as `apparmor=unconfined`: the container is no longer confined by that LSM. A custom minimal policy is not provided yet — it has to be built against the distribution's container-selinux, and SELinux has no read-only tier for `ptrace`: the permission is granted per target domain as a whole, coarser than AppArmor.

The translation process only reads and writes host sockets and its own socket, hence `cap_drop: ALL`.

Other container security settings remain at their defaults: the agent needs to write sockets under `/run/honeyghost`, and the translation process needs to read the host socket; neither is suitable for a read-only root filesystem. The container runs as root without `CAP_DAC_OVERRIDE`, so `/run/honeyghost` must exist and be owned by root — `sudo mkdir -p` already does that, while changing the owner makes the agent fail to bind the CLI socket with `Permission denied`.

## Known Limitations

- **x86_64 only**: the probes in `kernel/CMakeLists.txt` hardcode `-D__TARGET_ARCH_x86`.
- **Image is tied to the build machine's kernel**: `vmlinux.h` is generated from the build machine's BTF, so artifacts are not byte-identical across builds; probes relocate against the target host's BTF, so one image runs on any kernel 5.8 or newer.
- **CLI socket is owned by root**: the socket is created by root inside the container, so non-root host users need `sudo` to connect.
- **Stale sockets**: after the container is force-killed, socket files remain under `/run/honeyghost`; before restarting,
  `sudo rm -f /run/honeyghost/*.sock`.