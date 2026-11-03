# containerd Translation Process (containerd_bridge)

The containerd monitoring point of the role discovery module. It subscribes to containerd events, queries container metadata, enumerates snapshots, translates them into this repository's own protocol, and hands them to the C++ `ContainerdRoleDiscoverer` over a Unix socket.

**Why is it a separate Go process instead of a direct C++ connection?** containerd's `.proto` files use gogoproto extensions and do not provide C++ generated artifacts. A direct C++ connection would mean that every containerd upgrade requires fetching the `.proto` files again, re-trimming the gogo options, and re-validating field alignment and `Any.type_url`. With the official Go client, this cost becomes one-time: an upgrade degrades to bumping a dependency in `go.mod` once. The cost is one extra process and one IPC hop.

## Responsibility Boundaries

| | This process | C++ `ContainerdRoleDiscoverer` |
| --- | --- | --- |
| containerd event subscription | ✅ | ❌ |
| Metadata lookup (retrieve labels and image references) | ✅ | ❌ |
| Snapshot enumeration | ✅ | ❌ |
| Translate into own structure | ✅ | ❌ |
| Determine join/exit and maintain liveness state | ❌ | ✅ (state table) |
| cgroup member completion | ❌ | ✅ |
| Filtering (including excluding the agent's own container) | ❌ | ✅ |
| Type key extraction | ❌ | ✅ |

Metadata lookup must be on the Go side: otherwise C++ would still need to connect directly to containerd to get labels, defeating the purpose of the design. Filtering is on the C++ side: self-exclusion and the namespace allowlist are both there; this process translates everything.

## Image Reference

The label for a container role is taken from the image reference. This process fills it in the following order and takes the first non-empty value:

1. The `Image` field of the containerd container object: filled by `ctr` and by Docker with the containerd image store enabled;
2. CRI annotations in the OCI spec: for regular containers, use `io.kubernetes.cri.image-name`; for sandboxes, use `io.kubernetes.cri.podsandbox.image-name` — CRI does not write the image into the container object;
3. Docker API's `Config.Image`: queried only when `-docker-socket` is configured and the container's namespace is within `-docker-namespaces`.

Item 3 is needed only for Docker using the traditional image store (overlay2 graphdriver): such Docker neither fills the container object's `Image` nor provides CRI annotations; without it, the role label degrades to the container ID. Lookup results are cached by container ID, with a maximum of 4096 entries; if not found, it is treated as unknown and does not affect the container metadata itself.

Kubernetes nodes do not need item 3; for Docker hosts that need it, see `deploy/docker/docker-compose.docker-api.yaml`.

## Build and Run

```sh
# Build (standalone Go module, not integrated with CMake)
go build ./cmd/containerd-bridge

# Run (requires root: /run/containerd/containerd.sock has permissions srw-rw----)
sudo ./containerd-bridge -socket /run/honeyghost/containerd-bridge.sock
```

| Parameter | Default | Meaning |
| --- | --- | --- |
| `-containerd` | `/run/containerd/containerd.sock` | containerd socket path |
| `-socket` | `/run/honeyghost/containerd-bridge.sock` | Path to listen on for the C++ discoverer |
| `-namespaces` | `default,k8s.io,moby` | Namespaces to track, comma-separated |
| `-docker-socket` | empty | Docker API socket path; empty means do not query Docker |
| `-docker-namespaces` | `moby` | containerd namespaces managed by Docker, comma-separated; empty means no restriction |
| `-namespace-poll` | `30s` | Period for rechecking namespace existence |
| `-backoff-base` / `-backoff-max` | `200ms` / `30s` | Starting value and upper bound for reconnect backoff |
| `-log-level` | `info` | `debug` / `info` / `warn` / `error` |
| `-version` | — | Print version and exit |

## Protocol

`proto/role_containerd_bridge.proto`, length-prefixed framing over a Unix socket (4-byte big-endian). A connection carries only a sequence of frames:

```
SnapshotBegin { source, backend_version, namespaces[] }
Observation   { kind: UPSERT | REMOVE, in_snapshot, ... }   × N
SnapshotEnd   { count }
```

Two invariants, both asserted by the C++ side:

- **Snapshot segment marker pairs may appear repeatedly within a single connection**. When containerd restarts, this process reconnects itself and runs the snapshot segment again, rather than disconnecting from C++; C++ reconciles at **every** `SnapshotEnd`.
- **If any step of enumeration fails, the entire segment is invalidated**: no `SnapshotEnd` is sent, and the `SnapshotBegin` already sent at the segment start is left dangling; C++ counts receiving an opening while an unsettled segment already exists as one invalidation. Continuous invalidation means reconciliation is not happening; both sides have counters and logs, otherwise it would silently degrade into "feeding without settling".

In-stream events arriving during a segment are not consumed and remain queued in the merge channel; they are released only after the entire segment has finished (`in_snapshot=false`). Therefore, the C++ side will not see "in-stream items mixed into a segment" — that is a frame-order violation and will be recorded.

## Regenerating Protocol Code

The C++ side is generated by CMake at build time; the Go-side artifacts are checked into the repository (`internal/protocol/*.pb.go`), so the target machine does not need protoc installed:

```sh
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
./gen.sh
```

## Testing

```sh
go test ./...          # protocol framing, translation layer, session (including in-segment buffering, invalidation, namespace retirement, reconnect)
go test -race ./...
```

## Deployment

See `deploy/containerd-bridge-sidecar.yaml`: it runs as a sidecar container in the agent Pod, shares the socket directory with the C++ container via `emptyDir`, and hostPath-mounts the host's `/run/containerd/containerd.sock`. Strict startup order is not required — if the C++ side cannot connect, it backs off and retries; starting either before or after is correct.