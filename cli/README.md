# hghost

[English](README.en.md) | **简体中文**

HoneyGhost 的本地命令行客户端。它通过本地 Unix socket 查询角色、上下文与系统计数，
并以流式方式输出运行时事件。

## 注意事项

* 只连接本地 Unix socket，暂时不做跨网络访问、没有鉴权或 TLS；socket 文件的权限就是访问控制。
* 事件流断开即结束，不会静默续订；需要时请重新运行。
* `--timeout` 只适用于一元命令；`events` 使用 `--duration`，显式传 `--timeout` 是用法错误。
* 只有 `--socket` 读取环境变量 `HGHOST_SOCKET`，其余选项没有隐式来源。
* 下游提前关闭管道（如 `| head`）时停止输出，并以 `0` 退出。

## 构建

需要 Go >= 1.26.3，以及 protoc 与 Go 插件（`protoc-gen-go` 1.36.x、
`protoc-gen-go-grpc` 1.6.x）：

```sh
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.12
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.6.2

# 在仓库根目录构建，产物 bin/hghost
make go-cli
```

也可以直接 `go -C cli build ./cmd/hghost`，需要先生成协议代码（运行 `cli/gen.sh`）。

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

`--socket` 必须是绝对路径；传 `unix:` 或 `unix://` 形式会按用法错误拒绝。

### 版本信息与智能补全

```sh
hghost version
hghost --version
hghost completion bash    # 也支持 zsh / fish / powershell
```

`completion` 输出补全脚本到 stdout，按所使用 shell 的约定保存或 source 即可。

### role（角色）

```sh
hghost role list                 # 系统监管的角色
hghost role list -a              # 节点上发现的全部角色
hghost role show 7               # 按 roleID 查询
hghost role show nginx:1.25      # 按标签查询
hghost role show --label 12345   # 参数一律按标签处理
hghost role stats                # 角色管理器计数
hghost role which 1234           # 进程所属角色
```

`role show` 默认把全数字参数当作 `roleID`（不得为 0），其余按标签精确匹配；
纯数字标签必须用 `--label`。目标不存在或标签匹配到多个角色时退出 `1`。
角色详情中的进程与上下文相互独立：查询失败的部分不输出（JSON 为 `null`），
其余部分照常输出，整条命令退出 `1`。

### context（上下文）

```sh
hghost context list                 # 异常上下文（默认）
hghost context list -k extra        # 附属上下文
hghost context list -k excep,extra  # 两类都要
hghost context show 3               # 上下文的进程集合
hghost context stats
hghost context which 1234
```

`-k` 可重复或逗号分隔，取值为 `excep` / `extra` / `all`。同时查询两类时，
一类失败不影响另一类：成功类照常输出，失败原因写 stderr，整条命令退出 `1`；
两类都失败时不输出数据。

### process（进程）

```sh
hghost process stats               # 进程管理器计数
```

### status（系统总览）

```sh
hghost status
hghost status -o json
```

汇总监管角色数、异常/附属上下文数，以及角色、上下文、进程三个管理器的计数。各段独立：
失败的段在 table 模式不输出、JSON 为 `null`，其余段照常输出，整条命令退出 `1`。

### events（事件流）

```sh
hghost events                                  # 全部类型，直到 Ctrl-C
hghost events -t syscall,file                  # 只看系统调用与文件事件
hghost events -i role=nginx:1.25 -i pid=1234   # 按运行时信息过滤
hghost events -i roleID=7,8 -i contextID=3
hghost events -i 'role=nginx\,1.25'            # 标签内的逗号写作 \,
hghost events --duration 30s                   # 到时间自动停止
hghost events -o json | jq 'select(.kind == "event")'
hghost events -w capture.jsonl -o json        # 只写文件，stdout 静默
hghost events -w capture.jsonl --tee -o json  # 同时写文件与 stdout
```

* `-t` 可重复或逗号分隔，大小写不敏感，取值 `syscall` / `file` / `network` / `ipc`；
  省略表示全部。
* `-i` 的 key 为 `roleID` / `role` / `contextID` / `pid`，语法为 `key=value[,value...]`。
  同一 key 的多个值取并集，不同 key 之间取交集；角色标签原样交给服务端。
* `--duration` 为 `0` 表示直到中断。Ctrl-C、SIGTERM、`--duration` 到期和服务端正常
  结束流都以 `0` 退出；RPC 错误退出 `1`。
* `-w, --write <path>` 把事件数据流写入文件，默认不再写 stdout；相对路径按当前工作
  目录解析，`-` 不是特殊值。文件在拨号成功后、订阅前创建或截断；父目录不创建；
  新建文件权限为 `0600`，已存在的文件保留原权限。`-w` 的值为空是用法错误。
* `--tee` 必须与 `-w` 同用，保留 stdout 输出；单独使用是用法错误。
* 文件格式跟随 `-o`，`--no-headers` 同样作用于文件。JSON 的 `stats` 属于数据流，
  会写入文件；table 的丢弃提示与结束汇总只写 stderr。
* 使用 `--tee` 时，stdout 的 EPIPE（如 `| head`）只停止 stdout 输出，文件继续写；
  未使用 `--tee` 时 stdout 不是数据目标。
* table 列：`TYPE` `PID` `PPID` `ROLE` `CTX` `DETAIL`。`ROLE` 优先显示标签，
  标签为空但 `roleID` 非 0 时显示 `#<id>`；`CTX` 为 0 时显示 `-`。
* `DETAIL` 是人读摘要，不是稳定契约；脚本应解析 JSON。
* 事件没有时间列：proto 不提供事件发生时间。

`-o json` 为 JSON Lines，每行一个对象：

```json
{"kind":"event","head":{"role_label":"nginx:1.25","role_id":7,"context_id":3,"pid":1234,"pid_start_time":123456789,"ppid":1,"ppid_start_time":123400000,"type":"syscall"},"payload":{"kind":"exec","fields":{"semantic_filename":"/usr/sbin/nginx","argv0":"nginx","argv1":"","flags":0,"syscall_name":"execve"}}}
{"kind":"stats","dropped_events":12}
```

`payload.kind` 取值为 `process` / `exec` / `credential` / `namespace` /
`file_syscall` / `memory` / `network_syscall` / `kernel` / `file`，`fields` 为对应字段。
服务端上报丢弃计数时，table 模式在计数变化时写 stderr，JSON 模式写 `stats` 对象；
流结束时 table 模式在 stderr 输出 `events: N received, M dropped`。这些 stderr
诊断不写入 `-w` 文件。

## 输出与退出码

stdout 只承载数据；错误、提示与丢弃统计写 stderr。JSON 使用 snake_case 字段名；
空集合在 JSON 中为 `[]`。`which` 未找到时退出码仍为 `0`，table 模式在 stderr 提示。
使用 `events -w` 时，文件只承载事件数据流；错误、提示与 table 诊断仍写 stderr。

| 退出码 | 含义 |
| --- | --- |
| `0` | 成功，包括空列表、`which` 未找到、事件流被中断或到期 |
| `1` | 运行期失败：连接失败、RPC 失败、目标不存在、写输出失败、事件文件打开/写入/关闭失败 |
| `2` | 用法错误：未知命令/标志、参数格式不对、枚举值非法 |
| `130` | 一元命令执行期间被 SIGINT/SIGTERM 中断 |

## 联调与测试

```sh
make test-go              # Go 单测
scripts/test-cli-e2e.sh   # 与 C++ CLIServer 的端到端联调
```

联调脚本复用 `test/e2e_cli_server.cc` 的替身装配，需要先 `make agent` 与 `make go-cli`。

## 已知问题

工作区存在 `go.work` 时，Go workspace 模式可能报 ambiguous import，使 `make go` 失败。临时兜底：

```sh
GOWORK=off go -C cli build ./cmd/hghost
```
