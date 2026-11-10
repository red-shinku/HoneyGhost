# HoneyGhost agent Docker 部署

[English](README.en.md) | **简体中文**

## 构建

```sh
# 两个镜像一起
docker compose -f deploy/docker/docker-compose.yaml build

# 只构建代理
docker build -f deploy/docker/agent.Dockerfile -t hng/agent:dev .

# 只构建翻译进程
docker build -t hng/containerd-bridge:dev agent/role_discovery/containerd_bridge
```
代理镜像只编译本仓库源码：工具链、fmt/spdlog 与 userver 来自
`ghcr.io/fifseason/honeyghost-builder:latest`（含 Release/Debug 两变体），首次构建耗时主要是拉取该镜像。
需要换构建环境时加 `--build-arg BUILDER_IMAGE=<镜像>`；重建 builder 镜像见
`deploy/ci/builder.Dockerfile`。也可以直接用 `make image` 构建两个镜像。

## 运行

```sh
sudo mkdir -p /run/honeyghost
# 仅启用 AppArmor 的宿主需要：载入代理容器的配置，见「权限」
sudo apparmor_parser -r deploy/docker/apparmor/hng-agent
docker compose -f deploy/docker/docker-compose.yaml up -d

# 宿主侧客户端（make go 产出 bin/hghost）
bin/hghost --socket /run/honeyghost/cli.sock <子命令>
```

## 宿主前提

| 前提 | 用途 | 缺失时 |
| --- | --- | --- |
| 宿主内核 ≥ 5.8 | ring buffer map 等探针依赖 | 启动预检失败并报告版本 |
| `/sys/kernel/btf/vmlinux` | CO-RE 重定位 | 代理启动即失败 |
| tracefs（`/sys/kernel/tracing`） | tracepoint 的 id | 探针挂载失败 |
| `/run/containerd/containerd.sock` | containerd 角色发现 | 桥接进程退出 |
| `/run/dbus/system_bus_socket` | systemd 角色发现 | 代理连不上总线，发现源超时 |
| AppArmor 宿主已载入 `hng-agent` 配置 | 放行 system bus 调用与快照读 exe | 未载入时容器起不来；用 `docker-default` 时总线调用与 exe 读取被拒 |

没有 containerd 或 systemd 的节点：在配置里关掉对应发现源，并从 compose 中删掉不需要的服务与挂载。

### 镜像引用

容器角色的标签取镜像引用。宿主 Docker 用传统镜像存储（`docker info` 显示
`Storage Driver: overlay2`）时，镜像引用不在 containerd 里，桥接进程需要经
Docker API 回查：

```sh
docker compose -f deploy/docker/docker-compose.yaml \
               -f deploy/docker/docker-compose.docker-api.yaml up -d
```

该覆盖文件给桥接容器挂上只读的 `/var/run/docker.sock` 并开启 `-docker-socket`。
使用 containerd 镜像存储的宿主（`driver-type: io.containerd.snapshotter.v1`）
不需要它；不挂 Docker socket 时桥接进程不会访问 Docker。

## 配置

`deploy/docker/config/` 三个文件挂到容器内 `/etc/honeyghost`：

- `agent.conf`：采集开关、发现源开关、桥接 socket 路径、角色过滤与 CLI 配置的引用；
- `role_filter.conf`：白/黑名单，默认拒绝普通事件；
- `cli_server.conf`：并发流、队列容量、drain 超时、CLI socket 路径。

相对路径以 `agent.conf` 所在目录为基准，因此容器内引用写成同目录文件名即可。

## 权限

代理容器从 `cap_drop: ALL` 起步，只加四项：

| 权能 | 用途 |
| --- | --- |
| `CAP_BPF` | 创建 map、加载探针 |
| `CAP_PERFMON` | 加载 tracing 类程序、`perf_event_open` 挂载 |
| `CAP_SYS_PTRACE` | 初始化快照读 `/proc/<pid>/exe`；非本进程 uid 的进程还须 AppArmor 放行 ptrace，见下 |
| `CAP_SETPCAP` | 清空 bounding set，使权能无法经 execve 带回 |

初始化结束、探针挂载与快照都完成之后，进程会主动清空全部权能。

翻译进程只读写宿主 socket 与自建 socket，故 `cap_drop: ALL`。

### AppArmor

`docker-default` 拒掉代理依赖的两件事：向 system bus 的调用（`Hello`、`AddMatch`、
`Subscribe`、`ListUnits`、`Properties.GetAll`），以及读宿主进程
`/proc/<pid>/exe` 的 `ptrace`。

`deploy/docker/apparmor/hng-agent` 以 `docker-default` 为基线，只额外放行这两组，分两段：

| profile | 用在哪 | 比另一份多什么 |
| --- | --- | --- |
| `hng-agent` | 入口；compose 的 `security_opt` 引用它 | `ptrace (read)`（快照读 exe，不限对端）与 `change_profile -> hng-agent-steady` |
| `hng-agent-steady` | 初始化完成后由进程自行切入（切换失败只记日志） | — |

宿主须先载入（见「运行」）；profile 属线程私有，逐线程生效：

```sh
sudo apparmor_parser -r deploy/docker/apparmor/hng-agent
```

初始化完成后仍可能出现少量 `ptrace` 拒绝（`requested_mask="read"`、peer 为
`unconfined`）：那是 libsystemd 取总线对端凭据时读 `/proc/<pid>/exe`，读不到时
sd-bus 自行降级，不影响功能。

### SELinux

SELinux 宿主上 Docker 默认把容器放在 `container_t` 下，本代理在它下面同样跑不起来：
向 systemd 发总线消息、读宿主进程的 `exe`、以及写 bind mount 进来的
`/run/honeyghost`（除非该目录被重新打标签）都会触发类型强制拒绝，症状是
`audit.log` 里的 `avc: denied` 而非 `dmesg` 里的 AppArmor 记录。

这类宿主上要额外给代理容器关掉 SELinux 标记（在 compose 的 agent 服务里补一条）：

```yaml
security_opt:
  - label=disable
```

代价与该容器用 `apparmor=unconfined` 相同：不再受该 LSM 约束。自定义最小策略尚未
提供——它要随发行版的 container-selinux 一起编译，且 SELinux 的 `ptrace` 权限没有
「只读」这一档，只能按目标域整体放行，粒度比 AppArmor 粗。

---

其余容器安全项保持默认：代理要写 `/run/honeyghost` 下的 socket，翻译进程要读宿主
socket，两者都不适合只读根文件系统。容器以 root 运行且不再带 `CAP_DAC_OVERRIDE`，
`/run/honeyghost` 须存在且属 root——`sudo mkdir -p` 即如此，手工改成其它属主会让
代理绑定 CLI socket 时报 `Permission denied`。

## 已知限制

- **只支持 x86_64**：`kernel/CMakeLists.txt` 的探针固定 `-D__TARGET_ARCH_x86`。
- **镜像与构建机内核相关**：`vmlinux.h` 由构建机的 BTF 生成，字节产物不保证逐次一致；
  探针在目标机上按 BTF 做 CO-RE 重定位，同一镜像可运行于 5.8+ 内核。
- **CLI socket 属 root**：socket 由容器内 root 创建，宿主非 root 用户需 `sudo` 才能连接。
- **残留 socket**：容器被强杀后 `/run/honeyghost` 下会留下 socket 文件，重启前
  `sudo rm -f /run/honeyghost/*.sock`。
