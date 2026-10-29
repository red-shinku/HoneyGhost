# 目录结构说明

```
  HoneyGhost/
  ├── Makefile              # 顶层唯一构建入口：agent / ebpf / go / test / image / package
  ├── CMakeLists.txt        # C++ 目标定义
  ├── go.work               # 不进版本控制，由 scripts/gen-go-work.sh 生成
  ├── scripts/              # 仓库级脚本（生成 go.work 等）
  ├── config/               # 默认配置样例：agent.conf、role_filter.conf、cli_server.conf
  ├── proto/
  │   ├── internal/         # 待建：file_event, syscall_event —— 仅 C++，不过 wire
  │   ├── agent_bridge/     # 待建：现 role_containerd_bridge.proto
  │   ├── agent_central/    # 待建：跨节点契约
  │   └── cli/              # 待建
  ├── agent/                # 节点代理：一个 DaemonSet Pod / 一份 systemd unit = 一次部署
  │   ├── main.cc
  │   ├── config/ control_plane/ collector/ detector/ semantic/ context_maintainer/ event_data/ util/
  │   │   ├── include/      # 对外头：别的模块可以 include
  │   │   └── src/          # 私有头与源文件；子模块再嵌一层（如 context_maintainer/src/rule/）
  │   └── role_discovery/   # 与 control_plane 同级；内含 Go module containerd_bridge/
  ├── central/              # 待建：Go module
  ├── cli/                  # 待建：Go module
  ├── gen/go/               # 待建：Go module（共享）—— proto 的 Go 产物需被多个 module 共享时放这里
  ├── kernel/               # eBPF：探针、共用头与 CMakeLists.txt
  ├── test/
  └── deploy/
      ├── k8s/              # 待建：daemonset-agent.yaml（含 bridge sidecar）, central.yaml
      ├── baremetal/        # 待建：systemd unit, install.sh
      └── docker/           # 待建
```
