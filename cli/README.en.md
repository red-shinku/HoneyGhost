# hghost

**English** | [简体中文](README.md)

The local command-line client for HoneyGhost. It queries roles, contexts, and system counts through a local Unix socket, and streams runtime events.

## Notes

* Only connects to a local Unix socket; no cross-network access, authentication, or TLS for now; the permissions of the socket file are the access control.
* The event stream ends when disconnected and does not silently resume; re-run when needed.
* `--timeout` only applies to unary commands; `events` uses `--duration`, and explicitly passing `--timeout` is a usage error.
* Only `--socket` reads the environment variable `HGHOST_SOCKET`; the other options have no implicit sources.
* When a downstream consumer closes the pipe early (e.g. `| head`), output stops and the command exits with `0`.

## Build

Requires Go >= 1.26.3, as well as protoc and the Go plugins (`protoc-gen-go` 1.36.x,
`protoc-gen-go-grpc` 1.6.x):

```sh
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.12
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.6.2

# Build at the repository root, output bin/hghost
make go-cli
```

You can also run `go -C cli build ./cmd/hghost` directly, but you need to generate the protocol code first (run `cli/gen.sh`).

## Usage

```
hghost [global flags] <resource> <action> [arguments] [flags]
hghost [global flags] <standalone command> [arguments] [flags]
```

| Global flag | Default | Meaning |
| --- | --- | --- |
| `--socket` | `$HGHOST_SOCKET`, otherwise `/run/honeyghost/cli.sock` | Filesystem path of the server's Unix socket |
| `--timeout` | `5s` | Total time limit for unary commands; `0` means unlimited |
| `-o, --output` | `table` | `table` / `json` |
| `--no-headers` | `false` | Do not print table headers; ignored in JSON mode |

`--socket` must be an absolute path; passing `unix:` or `unix://` forms is rejected as a usage error.

### Version information and shell completion

```sh
hghost version
hghost --version
hghost completion bash    # also supports zsh / fish / powershell
```

`completion` outputs the completion script to stdout; save or source it according to your shell's conventions.

### role

```sh
hghost role list                 # roles supervised by the system
hghost role list -a              # all roles discovered on the node
hghost role show 7               # query by roleID
hghost role show nginx:1.25      # query by label
hghost role show --label 12345   # arguments are always treated as labels
hghost role stats                # role manager counts
hghost role which 1234           # role a process belongs to
```

`role show` treats all-numeric arguments as `roleID` by default (must not be 0), and treats everything else as an exact label match; purely numeric labels must use `--label`. Exits `1` if the target does not exist or the label matches multiple roles. The process and context parts of role details are independent: parts that fail to query are not output (JSON is `null`), the remaining parts are output as usual, and the whole command exits `1`.

### context

```sh
hghost context list                 # exceptional contexts (default)
hghost context list -k extra        # extra contexts
hghost context list -k excep,extra  # both kinds
hghost context show 3               # process set of a context
hghost context stats
hghost context which 1234
```

`-k` can be repeated or comma-separated, with values `excep` / `extra` / `all`. When querying both kinds, a failure of one kind does not affect the other: the successful kind is output as usual, the failure reason is written to stderr, and the whole command exits `1`; if both kinds fail, no data is output.

### process

```sh
hghost process stats               # process manager counts
```

### status

```sh
hghost status
hghost status -o json
```

Summarizes the number of supervised roles, exceptional/extra context counts, and the counts of the role, context, and process managers. Each section is independent: a failed section is not output in table mode and is `null` in JSON, the remaining sections are output as usual, and the whole command exits `1`.

### events

```sh
hghost events                                  # all types, until Ctrl-C
hghost events -t syscall,file                  # only system call and file events
hghost events -i role=nginx:1.25 -i pid=1234   # filter by runtime information
hghost events -i roleID=7,8 -i contextID=3
hghost events -i 'role=nginx\,1.25'            # commas inside labels are written as \,
hghost events --duration 30s                   # stop automatically when time is up
hghost events -o json | jq 'select(.kind == "event")'
```

* `-t` can be repeated or comma-separated, case-insensitive, with values `syscall` / `file` / `network` / `ipc`; omitting it means all.
* The keys of `-i` are `roleID` / `role` / `contextID` / `pid`, with the syntax `key=value[,value...]`. Multiple values for the same key are unioned, different keys are intersected; role labels are passed to the server as-is.
* `--duration` of `0` means until interrupted. Ctrl-C, SIGTERM, `--duration` expiry, and the server ending the stream normally all exit with `0`; RPC errors exit `1`.
* Table columns: `TYPE` `PID` `PPID` `ROLE` `CTX` `DETAIL`. `ROLE` prefers the label; when the label is empty but `roleID` is non-zero, it shows `#<id>`; `CTX` shows `-` when 0.
* `DETAIL` is a human-readable summary, not a stable contract; scripts should parse JSON.
* Events have no time column: the proto does not provide event occurrence time.

`-o json` is JSON Lines, one object per line:

```json
{"kind":"event","head":{"role_label":"nginx:1.25","role_id":7,"context_id":3,"pid":1234,"pid_start_time":123456789,"ppid":1,"ppid_start_time":123400000,"type":"syscall"},"payload":{"kind":"exec","fields":{"semantic_filename":"/usr/sbin/nginx","argv0":"nginx","argv1":"","flags":0,"syscall_name":"execve"}}}
{"kind":"stats","dropped_events":12}
```

`payload.kind` values are `process` / `exec` / `credential` / `namespace` /
`file_syscall` / `memory` / `network_syscall` / `kernel` / `file`, and `fields` holds the corresponding fields.
When the server reports dropped counts, table mode writes to stderr when the count changes, and JSON mode writes a `stats` object; at the end of the stream, table mode outputs `events: N received, M dropped` to stderr.

## Output and exit codes

stdout carries only data; errors, hints, and dropped statistics are written to stderr. JSON uses snake_case field names; empty collections are `[]` in JSON. `which` still exits `0` when not found, and table mode prints a hint to stderr.

| Exit code | Meaning |
| --- | --- |
| `0` | Success, including empty lists, `which` not found, and event stream interrupted or expired |
| `1` | Runtime failure: connection failure, RPC failure, target does not exist, output write failure |
| `2` | Usage error: unknown command/flag, malformed argument, invalid enum value |
| `130` | Interrupted by SIGINT/SIGTERM during a unary command |

## Integration and testing

```sh
make test-go              # Go unit tests
scripts/test-cli-e2e.sh   # end-to-end integration with the C++ CLIServer
```

The integration script reuses the test double setup from `test/e2e_cli_server.cc`, and requires `make agent` and `make go-cli` first.

## Known issues

When a `go.work` exists in the workspace, Go workspace mode may report an ambiguous import, causing `make go` to fail. Temporary workaround:

```sh
GOWORK=off go -C cli build ./cmd/hghost
```