// Command containerd-bridge 是角色发现模块的 containerd 翻译进程。
//
// 它订阅 containerd 的事件、回查容器元数据、枚举快照，翻译成自有协议经
// Unix socket 交给 C++ 发现器。判断加入/退出、过滤、cgroup 成员补齐、
// 类型键提取全部在 C++ 侧。
//
// 部署形态：agent Pod 的 sidecar 容器，与 C++ 容器经 emptyDir 共享 socket
// 目录，并挂载宿主的 /run/containerd/containerd.sock。
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"honeyghost/containerd_bridge/internal/bridge"
)

// 构建信息由 -ldflags 注入；未注入时给出可读的占位值。
var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	cfg := bridge.DefaultConfig()
	flag.StringVar(&cfg.Address, "containerd", cfg.Address,
		"containerd 的 socket 路径")
	socket := flag.String("socket", "/run/honeyghost/containerd-bridge.sock",
		"监听给 C++ 发现器的 Unix socket 路径")
	namespaces := flag.String("namespaces", strings.Join(cfg.Namespaces, ","),
		"跟踪的 containerd namespace，逗号分隔")
	flag.DurationVar(&cfg.NamespacePollInterval, "namespace-poll",
		cfg.NamespacePollInterval, "重新核对 namespace 存在性的周期")
	flag.DurationVar(&cfg.SnapshotInterval, "snapshot-interval",
		cfg.SnapshotInterval, "周期快照间隔；0 表示关闭")
	flag.DurationVar(&cfg.BackoffBase, "backoff-base", cfg.BackoffBase,
		"重连退避的起始时长")
	flag.DurationVar(&cfg.BackoffMax, "backoff-max", cfg.BackoffMax,
		"重连退避的上限")
	flag.StringVar(&cfg.DockerSocket, "docker-socket", cfg.DockerSocket,
		"Docker API 的 socket 路径；空表示不查询 Docker（仅传统镜像存储的 Docker 需要）")
	dockerNamespaces := flag.String("docker-namespaces",
		strings.Join(cfg.DockerNamespaces, ","),
		"Docker 管理的 containerd namespace，逗号分隔；空表示不限定")
	logLevel := flag.String("log-level", "info",
		"日志级别：debug / info / warn / error")
	showVersion := flag.Bool("version", false, "打印版本后退出")
	flag.Parse()

	if *showVersion {
		fmt.Printf("containerd-bridge %s (%s, %s)\n", version, commit, date)
		return
	}

	cfg.Namespaces = splitList(*namespaces)
	cfg.DockerNamespaces = splitList(*dockerNamespaces)
	cfg.Log = newLogger(*logLevel)
	slog.SetDefault(cfg.Log)

	if cfg.SnapshotInterval < 0 {
		cfg.Log.Warn("negative snapshot interval; disabling periodic snapshots",
			"value", cfg.SnapshotInterval)
		cfg.SnapshotInterval = 0
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	started := []any{
		"version", version, "containerd", cfg.Address, "socket", *socket,
		"namespaces", cfg.Namespaces, "snapshot_interval", cfg.SnapshotInterval,
	}
	if cfg.DockerSocket != "" {
		started = append(started, "docker", cfg.DockerSocket,
			"docker_namespaces", cfg.DockerNamespaces)
	}
	cfg.Log.Info("containerd bridge started", started...)

	server := &bridge.Server{Socket: *socket, Config: cfg, Log: cfg.Log}
	if err := server.Serve(ctx); err != nil {
		cfg.Log.Error("server exited", "err", err)
		os.Exit(1)
	}
}

// splitList 切分逗号分隔的列表，去掉空项与空白。
func splitList(list string) []string {
	var items []string
	for _, item := range strings.Split(list, ",") {
		if trimmed := strings.TrimSpace(item); trimmed != "" {
			items = append(items, trimmed)
		}
	}
	return items
}

func newLogger(level string) *slog.Logger {
	var parsed slog.Level
	if err := parsed.UnmarshalText([]byte(level)); err != nil {
		parsed = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr,
		&slog.HandlerOptions{Level: parsed}))
}
