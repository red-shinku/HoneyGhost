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
代理镜像构建的主要耗时是编译 userver（Release 变体，默认并行度 4），首次数十分钟；源码改动不会让该层失效。内存不足时用
`--build-arg USERVER_BUILD_PARALLEL=2` 降低并行度。

## 运行

```sh
sudo mkdir -p /run/honeyghost
docker compose -f deploy/docker/docker-compose.yaml up -d

# 宿主侧客户端（make go 产出 bin/hghost）
bin/hghost --socket /run/honeyghost/cli.sock <子命令>
```

## 宿主前提

| 前提 | 用途 | 缺失时 |
| --- | --- | --- |
| `/sys/kernel/btf/vmlinux` | CO-RE 重定位 | 代理启动即失败 |
| tracefs（`/sys/kernel/tracing`） | tracepoint 的 id | 探针挂载失败 |
| `/run/containerd/containerd.sock` | containerd 角色发现 | 桥接进程退出 |
| `/run/dbus/system_bus_socket` | systemd 角色发现 | 代理连不上总线，发现源超时 |

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

`privileged: true` 是当前确定可用的配置。要收紧，至少需要 `CAP_BPF`、`CAP_PERFMON`
（加载探针与 `perf_event_open`）、`CAP_SYS_ADMIN`（部分挂载路径）、`CAP_SYS_RESOURCE`
（memlock），待实测后替换。

其余容器安全项保持默认：代理要写 `/run/honeyghost` 下的 socket，翻译进程要读宿主
socket，两者都不适合只读根文件系统。

## 已知限制

- **只支持 x86_64**：`kernel/CMakeLists.txt` 的探针固定 `-D__TARGET_ARCH_x86`。
- **镜像与构建机内核相关**：`vmlinux.h` 由构建机的 BTF 生成。
- **CLI socket 属 root**：socket 由容器内 root 创建，宿主非 root 用户需 `sudo` 才能连接。
- **残留 socket**：容器被强杀后 `/run/honeyghost` 下会留下 socket 文件，重启前
  `sudo rm -f /run/honeyghost/*.sock`。
