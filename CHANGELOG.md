# Changelog

Records user- and deployment-visible changes. The format follows Keep a Changelog, and version numbers follow Semantic Versioning;
0.x does not promise cross-version compatibility.

## [Unreleased]

### Added

- The CLI tool now supports writing the event stream to a file: `hghost events -w/--write <path>`. In this mode, terminal output is disabled by default; use `--tee` to retain it.

### Changed

- Minimize container privileges:
  - Capabilities: initial capability set [BPF, PERFMON, SYS_PTRACE, SETPCAP], which the process voluntarily drops after initialization.
  - MAC: based on `docker-default`, a custom AppArmor security profile (a minimal security policy for D-Bus and /proc/<pid>/exe access; switch to a smaller policy set after initialization). SELinux support is not considered for now.

### Fixed

- The start_time of a thread event is inconsistent with that of the thread group leader, causing subsequent handling of the event to be incorrect.  

## [v0.1.0] - 2026-11-05

### Added

- Core features:
  - Capture of system call events and file access events.
  - Maintenance of Process, Role, and Context. The system maintains a process tree; supports automatic discovery of container services or systemd unit services; the semantics and rules of Context are currently incomplete.
  - Provides a CLI tool to query system status, supporting output of runtime event streams keyed by pid, roleID, contextID, rolelabel, and eventtype.
  - Supports writing role rosters, enabling the system to capture events of the specified roles based on a blacklist/whitelist mechanism.
- Preflights the target kernel at startup: requires ≥ 5.8, BTF, and tracefs; if not satisfied, reports errors item by item and exits.

### Changed

- `agent.Dockerfile` is changed to be based on a builder image and no longer compiles userver within the image.
- Version information is injected via `-DHNG_VERSION`, `-DHNG_COMMIT`, and `-DHNG_BUILD_DATE`; the Makefile automatically passes the parameters.