# 开发容器

`.devcontainer/`。提供「编码 → 构建 → 单测」的可复现 Linux 环境。

## 1. 用途与边界

容器内做 `make agent` / `make ebpf` / `make go` / `make test`。

容器内**不做** eBPF 的加载，也不做对 systemd、containerd 的观测：它们需要宿主内核与特权。故容器不申请任何特权，容器内是普通用户 `dev`。

| 目标 | 位置 |
| --- | --- |
| `make agent` / `make ebpf` / `make go` / `make test` | 容器内 |
| `verify_starttime` | 宿主 `sudo` —— 加载探针，需 BPF 权限 |
| `verify_role_systemd` | 宿主 `sudo` —— 连真实 system bus |
| `verify_role_containerd` | 宿主 `sudo` —— 需先起翻译进程，连真实 containerd socket |

三个 `verify_*` 未注册为 ctest 用例，`make test` 不会碰到它们。

## 2. 使用

### 2.1 首次

宿主机需为 Linux 内核且存在 `/sys/kernel/btf/vmlinux`，否则 eBPF 部分不构建。

以 VS Code 为例，需装 **Dev Containers** 扩展（WSL2 下另需 **WSL** 扩展）：

1. 把仓库克隆到 Linux 原生文件系统，WSL2 下**不要放在 `/mnt/c/...`**。
2. `Dev Containers: Reopen in Container`。（WSL2 下需先`连接到WSL`）
3. 首次构建镜像需网络；受限网络的构建参数见[注意事项](#3-注意事项)第 3 点。
4. 在**容器终端**的项目根目录执行：

```sh
# 生成 vmlinux.h 与 *.skel.h
make ebpf
# 安装 userver 依赖
scripts/install-userver.sh
# 如果机器上已有，则执行：
scripts/install-userver.sh --from-seed <路径前缀>
```

不引导 userver 时 `make agent` 会硬失败；只想要其余目标，用 `cmake -S . -B build-agent -DHNG_ENABLE_CLI_SERVER=OFF`。容器创建时的 `postCreateCommand` 会先报一次配置失败，它只打印提示、不中断创建；引导完成后重跑 `make agent` 即可。

WSL2 下若要跑 `verify_role_systemd`，需在 `/etc/wsl.conf` 开启 systemd：

```ini
[boot]
systemd=true
```

### 2.2 日常

容器内与宿主上无差别，都是仓库根 `Makefile` 的目标：

```sh
make agent    # C++ 与 eBPF
make ebpf     # 只重建探针与骨架（改了 kernel/ 下的头时用）
make go       # bridge
make test     # ctest
```

### 2.3 JetBrains IDE 用户

JetBrains IDE 跑在 Windows 下用不了开发容器（经 WSL 连接不识别 `.devcontainer`，用 WSL 路径打开则构建镜像时报路径错误）。要在 Windows 上用 JetBrains 系 IDE，得在 WSL 里装 Linux 版编辑器，GUI 用 WSLg。直接跑在 Linux 下，打开项目即可。

要让 CLion 与 `make` 共用 `build-agent/`，打开 **Settings → Build, Execution, Deployment → CMake**（每项目生效，不是全局设置）改两处：

| 字段 | 改为 |
| --- | --- |
| Generator | `Unix Makefiles` |
| Build directory | `build-agent` |

改完点 **Reload CMake Project**。若 CLion 以目录非空为由拒绝，先 `rm -rf build-agent` 让它自己配置一遍。

## 3. 注意事项

>[!notice] 所有为了本机环境对 devcontainer 和镜像配置作出的修改，不应该提交到仓库。

1. **Go 模块与构建缓存挂在命名卷上**，跨 Rebuild Container 保留。新增这类挂载点须在 Dockerfile 中预建并 `chown` 到 `dev`，否则容器内写不进去。

2. **容器内 `go` 的 `PATH` 由 `/etc/profile.d/go-path.sh` 与 `/usr/local/bin` 下的符号链接双保险，两条都要留**，不要改回去。

3. **下载源可在构建时经 `--build-arg` 覆盖**：

   | 参数 | 默认 |
   | --- | --- |
   | `BASE_IMAGE` | `debian:13-slim` |
   | `APT_MIRROR` / `APT_MIRROR_FALLBACK` | `deb.debian.org` / 空 |
   | `GO_DOWNLOAD_BASE` / `GO_DOWNLOAD_FALLBACK` | `https://go.dev/dl` / 空 |
   | `GO_SHA256_BASE` | `https://dl.google.com/go` |
   | `GO_SHA256` | 空；给期望哈希则不联网取，给 `none` 则跳过校验 |
   | `GOPROXY` | `https://goproxy.cn,direct` |

   手动构建：

   ```
   docker build -f .devcontainer/Dockerfile \
     --build-arg APT_MIRROR=mirrors.example.org \
     -t hng-buildtest .
   ```

   IDE 自动构建则在 `devcontainer.json` 的 `build.args` 里加同名键。

4. **`kernel/include/vmlinux.h` 由宿主 BTF 生成**，宿主内核不同则内容不同，故不同宿主上产出的构建产物不可逐字比对。

## 4. 装配取值

`Dockerfile` 定工具链与依赖版本，`devcontainer.json` 定挂载、语言服务器与 CMake 集成。其中需要注意的取值：

| 取值 | 说明 |
| --- | --- |
| `workspaceMount` 写死为 `/workspaces/HoneyGhost` | 容器内路径不随本地克隆出的目录名变化 |
| `updateRemoteUserUID: true` | 关掉会让绑定挂载的工作区在宿主侧归属错乱 |
| `postCreateCommand` 只 configure 不 build、失败不报错 | 产出 `compile_commands.json` 供 clangd 用；`hng-userver` 卷尚空时不中断容器创建 |
| clangd 与 CMake Tools 指向 `build-agent/` + Unix Makefiles | 与 `make` 共用同一份缓存 |

`remoteUser` 与 Dockerfile 的 `ARG USERNAME` 是同一个值的两处，改其一须同步改另一处。

依赖版本对齐 Debian 13 (trixie)，故 Dockerfile 中的 apt 包不写版本号；构建期会打印一次全部版本。其中两处不可放宽：

- **`g++` 而非 libc++**：项目实际链的是 libstdc++。
- **`protoc` 留在 3.21.x**：proto 生成代码与运行时版本强绑定。
