# hghost

HoneyGhost 的本地命令行客户端。它通过本地 Unix socket 上的 gRPC 查询运行时状态，
并以流式方式输出运行时事件。

## 边界

* 只连接本地 Unix socket；不跨网络、不做鉴权、不启用 TLS。socket 文件的权限就是访问控制。
* 不重试、不自动重连、不缓存、不读写配置文件。
* 一次调用只执行一条命令。
* 只有 `--socket` 读取环境变量；其余选项没有隐式来源。

## 构建

依赖：

| 工具 | 版本 |
| --- | --- |
| Go | >= 1.26.3 |
| protoc | >= 3.21 |
| protoc-gen-go | 1.36.x |
| protoc-gen-go-grpc | 与 grpc-go 配套（当前 1.6.x） |

```sh
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.12
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.6.2

# 在仓库根目录：生成协议代码并构建到 bin/hghost
make go-cli

# 只构建本 module（需已生成 internal/gen）
go -C cli build ./cmd/hghost
```

协议代码生成到 `cli/internal/gen/`，不入库。proto 变更后重跑 `cli/gen.sh` 并检查
`internal/client/convert.go`。

版本、commit 与构建时间由 `-ldflags -X` 注入，默认值分别为 `dev` / `none` / `unknown`。

## 使用

```
hghost [全局标志] <资源> <动作> [参数] [标志]
hghost [全局标志] <独立命令> [参数] [标志]
```

| 全局标志 | 默认值 | 含义 |
| --- | --- | --- |
| `--socket` | `$HGHOST_SOCKET`，否则 `/run/honeyghost/cli.sock` | 服务端 Unix socket 的文件系统路径 |
| `--timeout` | `5s` | 一元命令的总时长上限；`0` 表示不限 |
| `-o, --output` | `table` | `table` / `json` |
| `--no-headers` | `false` | 表格不输出表头；JSON 模式忽略 |

```sh
hghost version
hghost --version
hghost --help
hghost completion bash
```

`--socket` 必须是绝对路径；传 `unix:` 或 `unix://` 形式会按用法错误拒绝。

## 输出约定

* stdout 只承载数据；错误、警告与提示写 stderr，避免污染管道。
* 表格不截断、不分页、不加颜色；终端折行交给终端。
* JSON 查询输出单个文档（2 空格缩进），字段名固定为 snake_case，不依赖 protojson。
* 下游提前关闭管道（`EPIPE`）不算错误，停止输出并以 `0` 退出。

退出码：

| 码 | 含义 |
| --- | --- |
| `0` | 成功，包括空列表、`which` 未找到、事件流被中断或到期 |
| `1` | 运行期失败：连接失败、RPC 失败、目标不存在、写输出失败 |
| `2` | 用法错误：未知命令/标志、参数个数或格式不对、枚举值非法 |
| `130` | 一元命令执行期间被 SIGINT/SIGTERM 中断 |

## 测试

```sh
go -C cli test -race ./...
```

## 已知问题

工作区存在 `go.work` 时，`google.golang.org/genproto` 与拆分包可能触发 ambiguous
import，使 `make go` 失败（见 `docs/累积注意事项.md`）。临时兜底：

```sh
GOWORK=off go -C cli build ./cmd/hghost
```
