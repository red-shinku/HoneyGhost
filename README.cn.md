# HoneyGhost

![C++17](https://img.shields.io/badge/C%2B%2B-17-00599C?logo=cplusplus&logoColor=white)
![C++20](https://img.shields.io/badge/C%2B%2B-20-00599C?logo=cplusplus&logoColor=white)
![Go 1.26](https://img.shields.io/badge/-Go%201.26-00ADD8?logo=go&logoColor=white)
![eBPF](https://img.shields.io/badge/-eBPF-00AEEF?logo=ebpf&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-blue)

[English](README.md) | **简体中文**

HoneyGhost 是一个基于 eBPF 的 Linux 运行时监控代理。它从内核采集系统调用与文件事件，
维护进程、角色（systemd 服务与 containerd 容器）和上下文（context）的实时视图，并通过
本地 Unix socket 把这些视图和过滤后的事件流提供给 `hghost` 命令行客户端。

> **项目状态**：目前仅完成了基础架构，进阶功能仍在策划 / 开发中，预计会加入安全策略、入侵检测等。配置、CLI 输出与协议格式可能随版本变化。当前可用能力见
> [项目状态](#项目状态)。

> 希望这可以成为一个 sweet-honey-softly 的 ghost on 你的 server...（在未来）。还有很长的路要走，对我来说还有很多东西要去慢慢了解。

## 功能

- **内核态采集**：系统调用、文件访问与出站网络连接的 eBPF 探针；共享事件头携带父进程
  身份，用于归属。
- **按角色过滤**：用户态角色过滤器把进程允许/拒绝名单下发给内核，只为选定的工作负载
  生成事件。默认拒绝——未配置白名单时不采集普通事件。
- **语义化**：原始内核记录在到达消费者之前被转换为稳定、带类型的事件模型。
- **控制平面**：带虚拟根进程的进程树、由 systemd 与 containerd 支撑的角色发现，以及
  基于 exec 与环境信息的上下文派生。
- **流式查询面**：内嵌于代理的 gRPC 服务端（构建时可关闭）、每流队列与全局并发流配额，以及按
  角色、上下文、PID 和事件类型的过滤。
- **本地 CLI**：`hghost` 查询角色、上下文、进程与计数，或以表格 / JSON Lines 输出事件流。

## 架构

```
kernel probes ──► Collector ──► Semantic ──► RuntimeEngine ──► CLI streams ──► hghost
                                                  │
                                                  ▼
                                   Control plane (Process / Context / Role)
                                                  ▲
                                                  │
                              Role discovery (systemd / containerd)
```

内核侧产生原始记录；用户态采集器把它们经语义层送入运行时引擎，由引擎更新控制平面，
并把事件分发给已注册的 CLI 流。角色发现与这条路径并行运行，向角色管理器提供输入。

粗略地说，*角色*按 systemd unit 或容器镜像标识一个工作负载；*上下文*则按 exec 与环境
规则把属于同一组的进程归在一起。

| 路径 | 职责 |
| --- | --- |
| `kernel/` | eBPF 探针与共享内核头 |
| `agent/collector/` | ring buffer 消费与原始事件队列 |
| `agent/semantic/` | 归一化为带类型的语义事件 |
| `agent/control_plane/` | 进程、上下文与角色管理器及其存储层 |
| `agent/context_maintainer/` | 上下文派生规则 |
| `agent/role_discovery/` | systemd 与 containerd 角色发现，以及 containerd 翻译进程 |
| `agent/role_filter/` | 允许/拒绝规则与内核进程过滤表 |
| `agent/runtime_engine/` | 事件分派、运行时信息与订阅分发 |
| `agent/cli_server/` | gRPC 查询与流式服务 |
| `agent/assembly/` | 组件装配、初始化屏障、线程与停机 |
| `agent/config/` | 配置文档与 schema |
| `cli/` | Go `hghost` 客户端 |
| `proto/` | 事件与 CLI 协议定义 |
| `test/`、`scripts/`、`deploy/` | 测试、辅助脚本与部署资产 |

## 环境要求

- x86_64 Linux，内核 ≥ 5.8，提供 BTF（`/sys/kernel/btf/vmlinux`）且已挂载 tracefs。
  探针使用 ring buffer map（5.8 起提供），更低的内核会在启动预检时被拒绝，日志逐项
  给出未满足项。
- 启动时需 root，或 Docker README 列出的那组权能；加载探针、读其它用户的 `/proc/<pid>/exe`
  需要更高权限。初始化完成后会清空全部权能。
- C++ 构建：CMake ≥ 3.16、支持 C++17 的编译器（CLI 服务端需要 C++20）、`clang` 与
  `bpftool`、libbpf、protobuf、libsystemd（可选）、fmt 11 与 spdlog；启用 CLI 服务端时
  还需要 userver 3.x。
- Go 程序：Go ≥ 1.26.3；重新生成协议代码时还需要 `protoc` 及 `protoc-gen-go`、
  `protoc-gen-go-grpc`。

`.devcontainer/` 提供完整工具链，搭建方式见
[`.devcontainer/README.md`](.devcontainer/README.md)。

## 构建

仓库根目录的 `Makefile` 是唯一构建入口。

```sh
make agent   # C++ 代理与 eBPF 探针/骨架
make ebpf    # 只构建 eBPF（agent 的子集）
make go      # Go containerd 翻译进程与 hghost，产物在 bin/
make all     # agent + go
make test    # C++ 单测（ctest）
make test-go # Go 单测
```

在开发容器内首次构建：

```sh
make ebpf                  # 生成 vmlinux.h 与 *.skel.h
scripts/install-userver.sh # 把 userver 装进容器卷
make agent
make go
```

`vmlinux.h` 由构建机的 BTF 生成，不同内核上产出的构建产物不会逐字一致。

CLI 服务端默认启用，因此 `make agent` 需要 userver。可以用 `-Duserver_ROOT=<prefix>`
指向已有安装，或关闭 CLI 服务端并构建其余部分：

```sh
cmake -S . -B build-agent -DHNG_ENABLE_CLI_SERVER=OFF
cmake --build build-agent --parallel
```

使用该选项时，须在 `agent.conf` 中设 `[cli] enabled = false`，否则 `hng_agent`
会拒绝启动。

## 运行

```sh
sudo mkdir -p /run/honeyghost
sudo ./build-agent/hng_agent --config config/agent.conf
```

`hng_agent` 只接受 `--config PATH` 与 `-h/--help`。省略 `--config` 时，依次读取
`$HNG_CONFIG`、`/etc/honeyghost/agent.conf`。主配置文件内的路径（角色过滤与 CLI
服务端配置）以该文件所在目录为基准解析。

另开终端：

```sh
bin/hghost status
bin/hghost role list
bin/hghost events -t syscall,file
```

代理默认在 `/run/honeyghost/cli.sock` 创建 CLI socket。如需修改，调整
`[cli] socket_path` 或 `[cli_server] socket_path`；socket 文件权限就是唯一的访问控制。
本示例以 root 运行代理，socket 因此归 root 所有；请以足够权限运行 `hghost`，或调整
socket 权限。

示例配置同时启用了两个发现源。systemd 源在普通主机上即可工作；容器角色还需要
containerd 翻译进程（`agent/role_discovery/containerd_bridge/`）。翻译进程未运行时，
启动会在角色源超时后继续，但容器角色缺失。请关闭主机没有提供的发现源：设
`[role_discovery] containerd = false`，没有 systemd 时再设 `systemd = false`。

## 配置

示例文件在 `config/`：

| 文件 | 用途 |
| --- | --- |
| `agent.conf` | 采集开关、发现源、角色过滤与 CLI 服务端配置的路径、CLI 开关与 socket 覆盖 |
| `role_filter.conf` | 角色标签的 exact/regex 白名单与黑名单；黑名单优先；**默认拒绝普通事件** |
| `cli_server.conf` | 并发流上限、队列容量、drain 超时与 CLI socket 路径 |

`agent.conf`：

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
# 未编入 CLI 服务端时必须为 false。
enabled = true
# 留空表示沿用 CLI 服务端配置里的 socket 路径。
socket_path =
config = cli_server.conf
```

`role_filter.conf`：

```ini
[whitelist]
exact: nginx.service
regex: registry/example/honeypot:v1\..*

[blacklist]
exact: registry/example/honeypot:v1.debug
```

- 角色标签来自发现源：systemd unit 名或容器镜像标签。
- `exact` 匹配完整角色标签；`regex` 是区分大小写的 ECMAScript 整串匹配。
- 黑名单优先于白名单。白名单为空时不采集普通事件。请按要观察的工作负载修改该文件；
  使用示例规则时，只采集 `nginx.service` 与匹配容器正则的标签。
- 来源优先级：内建默认值 < 配置文件 < 环境变量。每个键都可用大写的
  `HNG_<SECTION>_<KEY>` 覆盖（例如 `HNG_COLLECTOR_ENABLED=false`）；`HNG_CONFIG`
  用于指定主配置文件。
- 启动时会拒绝未知的节与键。

## CLI

```
hghost [全局标志] <资源> <动作> [参数] [标志]
hghost [全局标志] <独立命令> [参数] [标志]
```

| 全局标志 | 默认值 | 含义 |
| --- | --- | --- |
| `--socket` | `$HGHOST_SOCKET`，否则 `/run/honeyghost/cli.sock` | Unix socket 路径 |
| `--timeout` | `5s` | 一元命令的总时长上限；`0` 表示不限 |
| `-o, --output` | `table` | `table` 或 `json` |
| `--no-headers` | `false` | 不输出表头 |

示例：

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

完整命令参考、输出格式与退出码见 [`cli/README.md`](cli/README.md)。

## 部署

单机 Docker Compose 示例见 [`deploy/docker`](deploy/docker/README.md)。它会构建代理
镜像与 containerd 翻译进程镜像，然后把宿主机的 `/run/honeyghost`、D-Bus socket 与
tracefs 挂载进代理容器。

可在 releases 中获取部署包，其中包含 `docker-compose.yaml`、项目配置文件、自定义安全策略配置等。

### 获取镜像

```sh
docker pull fifseason/honeyghost-agent:latest  
docker pull fifseason/honeyghost-containerd-bridge:latest
```

### 本地构建

项目根目录：
```sh
make image
```

## 测试

```sh
make test                 # C++ 单测
make test-go              # Go 单测，带 -race
scripts/test-cli-e2e.sh   # 与 C++ CLIServer 的端到端测试
```

部分检查必须在宿主机以 root 运行，因为它们要加载探针或连接真实系统服务：
`verify_starttime`、`verify_role_systemd`、`verify_role_containerd`。

## 项目状态

- 系统调用与文件事件已端到端打通。内核侧已有网络探针，但网络与 IPC 事件尚未语义化，
  因此目前不会出现在 `hghost events` 中。
- 异常检测器（`agent/detector/`）尚未接入运行时；只有其 `Score` 结构被上下文维护
  模块使用。
- 仅支持 Linux，目前仅支持 x86_64；eBPF 探针以 `-D__TARGET_ARCH_x86` 编译。
- CLI 服务端没有鉴权或 TLS。它只监听本地 Unix socket，访问控制依赖 socket 文件权限。
- CLI 事件流在连接断开时结束，不会静默续订。

## 文档

- [CLI 参考](cli/README.md)
- [Docker 部署](deploy/docker/README.md)
- [开发容器](.devcontainer/README.md)

## 致谢与许可

[LINUX DO](https://linux.do/) ; [MIT](LICENSE)
