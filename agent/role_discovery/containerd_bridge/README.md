# containerd 翻译进程（containerd_bridge）

角色发现模块的 containerd 监测点。它订阅 containerd 的事件、回查容器元数据、枚举
快照，翻译成本仓库自有协议经 Unix socket 交给 C++ 的 `ContainerdRoleDiscoverer`。

**为什么是一个独立的 Go 进程而不是 C++ 直连**：containerd 的 `.proto` 用 gogoproto
扩展且不提供 C++ 生成物，C++ 直连意味着每次 containerd 升级都要重新取 `.proto`、
重新裁剪 gogo 选项、重新验证字段对齐与 `Any.type_url`。用官方 Go 客户端后这个成本
变成一次性的：升级退化成升一次 `go.mod` 依赖。代价是多一个进程与一跳 IPC。

## 职责边界

| | 本进程 | C++ `ContainerdRoleDiscoverer` |
| --- | --- | --- |
| containerd 事件订阅 | ✅ | ❌ |
| 元数据回查（取标签） | ✅ | ❌ |
| 快照枚举 | ✅ | ❌ |
| 翻译成自有结构 | ✅ | ❌ |
| 判断加入/退出、维护存活状态 | ❌ | ✅（状态表） |
| cgroup 成员补齐 | ❌ | ✅ |
| 过滤（含排除 agent 自身容器） | ❌ | ✅ |
| 类型键提取 | ❌ | ✅ |

元数据回查必须在 Go 侧：否则 C++ 还要直连 containerd 拿标签，方案就白费了。
过滤在 C++ 侧：self-exclusion 与 namespace 白名单都在那里，本进程全量翻译。

## 构建与运行

```sh
# 构建（独立 go module，不接 CMake）
go build ./cmd/containerd-bridge

# 运行（需 root：/run/containerd/containerd.sock 权限为 srw-rw----）
sudo ./containerd-bridge -socket /run/honeyghost/containerd-bridge.sock
```

| 参数 | 默认值 | 含义 |
| --- | --- | --- |
| `-containerd` | `/run/containerd/containerd.sock` | containerd 的 socket 路径 |
| `-socket` | `/run/honeyghost/containerd-bridge.sock` | 监听给 C++ 发现器的路径 |
| `-namespaces` | `default,k8s.io,moby` | 跟踪的 namespace，逗号分隔 |
| `-namespace-poll` | `30s` | 重新核对 namespace 存在性的周期 |
| `-backoff-base` / `-backoff-max` | `200ms` / `30s` | 重连退避的起始值与上限 |
| `-log-level` | `info` | `debug` / `info` / `warn` / `error` |
| `-version` | — | 打印版本后退出 |

## 协议

`proto/role_containerd_bridge.proto`，Unix socket 上的长度前缀分帧（4 字节大端）。
一条连接上只有帧序列：

```
SnapshotBegin { source, backend_version, namespaces[] }
Observation   { kind: UPSERT | REMOVE, in_snapshot, ... }   × N
SnapshotEnd   { count }
```

两条不变量，都由 C++ 侧断言：

- **快照段标记对可以在一条连接内重复出现**。containerd 重启时本进程自己重连、重走
  一次快照段，而不是断开与 C++ 的连接；C++ 在**每个** `SnapshotEnd` 处对账。
- **枚举的任一步失败即整段作废**：不发 `SnapshotEnd`，段起点已发的 `SnapshotBegin`
  就此悬空，C++ 把「已有未结算段时又收到开场」计为一次作废。持续作废意味着对账
  没在发生，两侧都有计数与日志，否则会静默退化成「只喂不结算」。

段内到达的流内事件不消费、滞留在合并通道里，段全部收场后才放行（`in_snapshot=false`），
故 C++ 侧不会看到「段内混入流内项」——它是帧序违约，会被记下。

## 重新生成协议代码

C++ 侧由 CMake 在构建时生成；Go 侧产物入库（`internal/protocol/*.pb.go`），
目标机不必装 protoc：

```sh
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
./gen.sh
```

## 测试

```sh
go test ./...          # 协议分帧、翻译层、会话（含段内缓冲、作废、namespace 退休、重连）
go test -race ./...
```

## 部署

见 `deploy/containerd-bridge-sidecar.yaml`：作为 agent Pod 的 sidecar 容器，与 C++ 容器
经 `emptyDir` 共享 socket 目录，并 hostPath 挂载宿主的 `/run/containerd/containerd.sock`。
不需要严格的启动顺序——C++ 侧连不上就退避重试，先起后起都正确。
