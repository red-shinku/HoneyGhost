// Command hghost 是 HoneyGhost 的本地 CLI 客户端。
//
// 它通过本地 Unix socket 上的 gRPC 查询运行时状态并订阅事件。
// 可执行文件只负责装配、信号与退出码；命令逻辑在 internal/cmd。
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"honeyghost/cli/internal/api"
	"honeyghost/cli/internal/client"
	"honeyghost/cli/internal/cmd"
)

// 以下变量由 -ldflags -X 注入。
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	os.Exit(run())
}

func run() int {
	// 让 stdout 的 EPIPE 以错误形式返回，由输出路径识别后正常退出。
	signal.Ignore(syscall.SIGPIPE)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	app := cmd.NewApp(dial)
	app.SetSignalStop(stop)
	defer app.Close()

	root := cmd.NewRootCommand(app, cmd.BuildInfo{
		Version: version,
		Commit:  commit,
		Date:    date,
	})
	err := root.ExecuteContext(ctx)
	if err == nil {
		return 0
	}

	fmt.Fprintf(os.Stderr, "hghost: %s\n", err)
	return cmd.ExitCode(err, ctx.Err() != nil)
}

func dial(ctx context.Context, socket string) (api.Services, io.Closer, error) {
	c, err := client.Dial(ctx, socket, client.Options{UserAgent: "hghost/" + version})
	if err != nil {
		return api.Services{}, nil, err
	}
	return c.Services(), c, nil
}
