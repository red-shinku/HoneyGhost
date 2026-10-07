# 开发容器

`.devcontainer/`。提供「编码 → 构建 → 单测」的可复现 Linux 环境。

## 1. 用途与边界

**做**：`make agent` / `make ebpf` / `make go` / `make test`，含 eBPF 探针的编译与骨架生成。

**不做**：eBPF 的**加载**，以及对 systemd、containerd 的**观测**。这两件事依赖宿主内核的 BTF、tracefs、cgroup2 与 `CAP_BPF` / `CAP_PERFMON`，容器共享宿主内核，带不进来。故容器**不申请任何特权**（无 `privileged`、无 `capAdd`），容器内是普通用户 `dev`。

分工的判据是「需不需要真内核与外部的 systemd / containerd」：

| 目标 | 位置 |
| --- | --- |
| `make agent` / `make ebpf` / `make go` / `make test` | 容器内 |
| `verify_starttime` | 宿主 `sudo` —— 加载探针，需 BPF 权限 |
| `verify_role_systemd` | 宿主 `sudo` —— 连真实 system bus |
| `verify_role_containerd` | 宿主 `sudo` —— 需先起翻译进程，连真实 containerd socket |

三个 `verify_*` 未注册为 ctest 用例（见 `test/CMakeLists.txt`），故 `make test` 不会碰到它们，也不会因权限不足而失败。

## 2. 使用

### 2.1 首次

宿主需为 Linux，且 `/sys/kernel/btf/vmlinux` 存在——`kernel/include/vmlinux.h` 由它生成，缺此项 eBPF 部分不构建。

以 VS Code 为例，需装 **Dev Containers** 扩展（WSL2 下另需 **WSL** 扩展）：

1. 把仓库克隆到 Linux 原生文件系统。WSL2 下**不要放在 `/mnt/c/...`**：它经 9p / virtiofs 转发，构建慢数倍，且 inotify 监听不可靠，会让 clangd 索引与 CMake Tools 的自动重配时灵时不灵。
2. `Dev Containers: Reopen in Container`。
3. 首次构建镜像需拉取 apt 包与 Go 压缩包，需要网络。

WSL2 下若要在**宿主**上跑 `verify_role_systemd`，需在 `/etc/wsl.conf` 开启 systemd：

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

改了 `kernel/` 下的探针或共用头不必手动清理：`kernel/CMakeLists.txt` 把全部共用头列进了 `DEPENDS`，会触发重编与骨架重生成。

## 3. 注意事项

1. **clangd 与 CMake Tools 的配置在 `devcontainer.json` 里，不在 `.vscode/`。** 后者被 `.gitignore` 覆盖，克隆出来并不存在，写进去也不会随仓库分发。改配置请改 `devcontainer.json`。

2. **Go 模块与构建缓存挂在命名卷上**，跨 Rebuild Container 保留；否则每次都要重下 containerd v2 等一大批依赖。两个挂载点在 Dockerfile 中预建并归属 `dev`——命名卷首次挂载继承镜像中该路径的归属。新增此类挂载点时同样要预建，否则卷归 root 所有，容器内写入直接失败。

3. **容器内 `go` 不在 `PATH` 上是个已修的坑，不要改回去。** Debian 的 `/etc/profile` 会无条件 `export PATH`，覆盖掉 Docker 的 `ENV PATH`，而 devcontainer 默认走登录 shell。现由 `/etc/profile.d/go-path.sh` 与 `/usr/local/bin` 下的符号链接双保险——两条都留，只留其一会漏掉 `sudo` 的 `secure_path` 等不经 profile 的场景。

4. **`GOPROXY` 默认取 `https://goproxy.cn,direct`**。`proxy.golang.org` 在部分网络下不可达，用默认值 `make go` 会 i/o timeout；网络可直连时用 `--build-arg GOPROXY=...` 覆盖。

5. **`kernel/include/vmlinux.h` 由宿主 BTF 生成**，宿主内核不同则内容不同。项目用的是 CO-RE（`__builtin_preserve_access_index`），字段偏移在**加载时**按目标内核的 BTF 重定位，故跨内核编译、运行是设计内的；但不同宿主上产出的构建产物不可逐字比对。

## 4. 装配取值

`Dockerfile` 定工具链与依赖版本，`devcontainer.json` 定挂载、语言服务器与 CMake 集成。其中偏离默认值的取值及理由：

| 取值 | 理由 |
| --- | --- |
| `workspaceMount` 写死为 `/workspaces/HoneyGhost` | 容器内路径不随本地克隆出的目录名变化 |
| `updateRemoteUserUID: true` | 宿主 uid 非 1000 时由 VS Code 把容器内 `dev` 重映射过去；关掉会让绑定挂载的工作区在宿主侧归属错乱 |
| `postCreateCommand` 只 configure 不 build | clangd 需要的是 `compile_commands.json`，configure 即产出；探针的条目由 `kernel/CMakeLists.txt` 的 `hng_ebpf_cdb` 目标导出，同在 configure 阶段生成 |
| clangd 与 CMake Tools 指向 `build-agent/` + Unix Makefiles | 与 `make` 的取值对齐，避免语言服务器与命令行各用一份缓存 |
| 不推荐 `ms-vscode.cpptools` | 与 clangd 同时启用会互相覆盖诊断结果 |

`remoteUser` 与 Dockerfile 的 `ARG USERNAME` 是同一个值的两处，改其一须同步改另一处。

依赖版本对齐 Debian 13 (trixie) 仓库，故 Dockerfile 中的 apt 包不写版本号。**构建期会打印一次全部版本**，那是版本漂移的发现点。其中两处不可随意放宽：

- **`g++` 而非 libc++**：项目实际链的是 libstdc++（`/usr/bin/c++` 默认）。
- **`protoc` 留在 3.21.x**：proto 生成代码与运行时版本强绑定，跨大版本会直接编译不过。
