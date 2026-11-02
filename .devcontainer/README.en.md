# Development Container

**English** | [简体中文](README.md)

`.devcontainer/`. Provides a reproducible Linux environment for "code → build → unit test".

## 1. Purpose and Scope

The container supports `make agent` / `make ebpf` / `make go` / `make test`, and provides clangd language analysis (Doxygen comment rendering).

| Target | Location |
| --- | --- |
| `make agent` / `make ebpf` / `make go` / `make test` | Inside the container |
| `verify_starttime` | Host `sudo` — loads probes, requires BPF privileges |
| `verify_role_systemd` | Host `sudo` — connects to the real system bus |
| `verify_role_containerd` | Host `sudo` — requires the translation process to be started first, connects to the real containerd socket |

## 2. Usage

### 2.1 First Time

The host machine must run a Linux kernel and have `/sys/kernel/btf/vmlinux` present; otherwise the eBPF parts will not build.

Taking VS Code as an example, you need the **Dev Containers** extension (under WSL2 you also need the **WSL** extension):

1. Clone the repository to the Linux native filesystem; note that under WSL2 **do not place it in `/mnt/c/...`**.
2. `Dev Containers: Reopen in Container`. (Under WSL2 you need to `Connect to WSL` first.)
3. The first image build requires network access; if the network is very troublesome, see point 1 of [Notes](#3-notes).
4. In the **container terminal**, at the project root, run:

```sh
# Generate vmlinux.h and *.skel.h
make ebpf
# Install userver dependencies
scripts/install-userver.sh
# If userver already exists on the machine, skip the download and run:
scripts/install-userver.sh --from-seed <path prefix>
```

Without bootstrapping userver, `make agent` will hard-fail; if you only want the other targets, use `cmake -S . -B build-agent -DHNG_ENABLE_CLI_SERVER=OFF`. The `postCreateCommand` at container creation will first report a configuration failure once; it only prints a hint and does not interrupt creation; after bootstrapping is complete, just rerun `make agent`.

Under WSL2, to run `verify_role_systemd`, you need to enable systemd in `/etc/wsl.conf`:

```ini
[boot]
systemd=true
```

### 2.2 JetBrains IDE Users

JetBrains IDEs running on Windows cannot use the development container (connecting via WSL does not recognize `.devcontainer`, and opening with a WSL path causes a path error when building the image). To use JetBrains IDEs on Windows, install the Linux version of the editor inside WSL and use WSLg for the GUI. Running directly under Linux, just open the project.

To make CLion share `build-agent/` with `make`, open **Settings → Build, Execution, Deployment → CMake** (effective per project, not a global setting) and change two fields:

| Field | Change to |
| --- | --- |
| Generator | `Unix Makefiles` |
| Build directory | `build-agent` |

After changing, click **Reload CMake Project**. If CLion refuses on the grounds that the directory is non-empty, first `rm -rf build-agent` and let it configure on its own.

## 3. Notes

1. **Download sources can be overridden at build time via `--build-arg`**:

   | Parameter | Default |
   | --- | --- |
   | `BASE_IMAGE` | `debian:13-slim` |
   | `APT_MIRROR` / `APT_MIRROR_FALLBACK` | `deb.debian.org` / empty |
   | `GO_DOWNLOAD_BASE` / `GO_DOWNLOAD_FALLBACK` | `https://go.dev/dl` / empty |
   | `GO_SHA256_BASE` | `https://dl.google.com/go` |
   | `GO_SHA256` | empty; if a hash is given, do not fetch online; if `none`, skip verification |
   | `GOPROXY` | `https://goproxy.cn,direct` |

   Manual build:

   ```
   docker build -f .devcontainer/Dockerfile \
     --build-arg APT_MIRROR=mirrors.example.org \
     -t hng-buildtest .
   ```

   For IDE automatic builds, add keys of the same name in `devcontainer.json`'s `build.args`.

2. **`kernel/include/vmlinux.h` is generated from the host BTF**; different host kernels produce different content, so build artifacts produced on different hosts cannot be compared byte-for-byte.

3. **fmt and spdlog are provided from source, not distribution packages**: userver's `cmake/SetupFmt.cmake`
   pins fmt 11.1.4, while trixie only has fmt 10, and the system spdlog is compiled against fmt 10; mixing all three
   into the same link will report undefined symbols when linking `hng_agent`. In the image,
   `scripts/install-fmt-spdlog.sh` installs both into `/usr/local`, shared by userver and
   `hng_agent`. After upgrading to this image, existing containers must each do this once (rebuilding the image does not clear volumes):

   ```sh
   scripts/install-userver.sh --force   # userver in the old volume was compiled against fmt 10
   rm -rf build-agent                   # fmt_DIR in CMakeCache already points to a nonexistent path
   ```

## 4. Assembly Values

`Dockerfile` defines the toolchain and dependency versions; `devcontainer.json` defines mounts, language servers, formatting, and CMake integration. Values worth noting:

| Value | Description |
| --- | --- |
| `workspaceMount` hard-coded to `/workspaces/HoneyGhost` | The in-container path does not vary with the locally cloned directory name |
| `updateRemoteUserUID: true` | Turning it off will cause the bind-mounted workspace to have incorrect ownership on the host side |
| `postCreateCommand` only configures, does not build; does not error on failure | Produces `compile_commands.json` for clangd; does not interrupt container creation when the `hng-userver` volume is still empty |
| clangd and CMake Tools point to `build-agent/` + Unix Makefiles | Share the same cache with `make` |
| clangd's Doxygen comment rendering | The switch is `Documentation.CommentFormat: Doxygen`, written in the image's clangd user config `/home/dev/.config/clangd/config.yaml`. Only takes effect for clients using the image's clangd |
| C/C++ save-time formatting | The extension `xaver.clang-format` invokes `clang-format` on PATH (in-container `/usr/local/bin/clang-format` → `clang-format-19`), with layout from the repository's `.clang-format`. On the VS Code side you also need to point `editor.defaultFormatter` at it, otherwise no formatter can be selected on save |

`remoteUser` and the Dockerfile's `ARG USERNAME` are two places for the same value; changing one requires changing the other in sync (mind the uid).

Dependency versions are aligned with Debian 13 (trixie), so apt packages in the Dockerfile do not specify version numbers; during the build all versions are printed once. fmt and spdlog are the only exceptions: installed from source at pinned versions, for the reason in Section 3, point 3.

clangd uses `clangd-22` from trixie main, not the unversioned `clangd` meta-package — the latter still points to 19 in trixie, while Doxygen comment rendering requires ≥ 22.

Two places cannot be relaxed:

- **`g++` rather than libc++**: the project actually links against libstdc++.
- **`protoc` stays at 3.21.x**: generated proto code is tightly bound to the runtime version.