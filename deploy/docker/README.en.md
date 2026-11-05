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

`privileged: true` is the currently known-working configuration. To tighten it, at least `CAP_BPF`, `CAP_PERFMON`
(loading probes and `perf_event_open`), `CAP_SYS_ADMIN` (some mount paths), and `CAP_SYS_RESOURCE`
(memlock) are required; replace after actual testing.

Other container security settings remain at their defaults: the agent needs to write sockets under `/run/honeyghost`, and the translation process needs to read the host socket; neither is suitable for a read-only root filesystem.

## Known Limitations

- **x86_64 only**: the probes in `kernel/CMakeLists.txt` hardcode `-D__TARGET_ARCH_x86`.
- **Image is tied to the build machine's kernel**: `vmlinux.h` is generated from the build machine's BTF, so artifacts are not byte-identical across builds; probes relocate against the target host's BTF, so one image runs on any kernel 5.8 or newer.
- **CLI socket is owned by root**: the socket is created by root inside the container, so non-root host users need `sudo` to connect.
- **Stale sockets**: after the container is force-killed, socket files remain under `/run/honeyghost`; before restarting,
  `sudo rm -f /run/honeyghost/*.sock`.