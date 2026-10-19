package cmd

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"honeyghost/cli/internal/api"
	"honeyghost/cli/internal/render"
)

// DefaultSocket 是 --socket 与服务端约定的默认路径。
const DefaultSocket = "/run/honeyghost/cli.sock"

// DialFunc 是命令层与传输层之间唯一的接缝，由 main 注入。
type DialFunc func(ctx context.Context, socket string) (api.Services, io.Closer, error)

// Options 是解析后的全局 flag。
type Options struct {
	Socket    string
	Timeout   time.Duration
	Format    render.Format
	NoHeaders bool
}

// App 持有全局选项与惰性建立的连接。
type App struct {
	opts   Options
	output string
	dial   DialFunc

	svcs   api.Services
	closer io.Closer
	dialed bool
}

// NewApp 创建命令上下文；--socket 的默认值取环境变量 HGHOST_SOCKET。
func NewApp(dial DialFunc) *App {
	socket := os.Getenv("HGHOST_SOCKET")
	if socket == "" {
		socket = DefaultSocket
	}
	return &App{
		opts: Options{
			Socket:  socket,
			Timeout: 5 * time.Second,
			Format:  render.FormatTable,
		},
		output: "table",
		dial:   dial,
	}
}

// Services 首次调用时拨号；失败不缓存，同一条命令内的多个 RPC 复用同一连接。
func (a *App) Services(ctx context.Context) (api.Services, error) {
	if a.dialed {
		return a.svcs, nil
	}
	svcs, closer, err := a.dial(ctx, a.opts.Socket)
	if err != nil {
		return api.Services{}, err
	}
	a.svcs = svcs
	a.closer = closer
	a.dialed = true
	return svcs, nil
}

// QueryContext 应用 --timeout；0 表示不设截止时间。
func (a *App) QueryContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if a.opts.Timeout <= 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, a.opts.Timeout)
}

// Close 关闭已建立的连接。
func (a *App) Close() error {
	if a.closer == nil {
		return nil
	}
	return a.closer.Close()
}

// validateFlags 在 PersistentPreRunE 中解析并校验全局 flag。
func (a *App) validateFlags() error {
	if strings.HasPrefix(a.opts.Socket, "unix:") {
		return usageErrorf("--socket takes a filesystem path, not a gRPC target: %q", a.opts.Socket)
	}
	if !filepath.IsAbs(a.opts.Socket) {
		return usageErrorf("--socket must be an absolute path: %q", a.opts.Socket)
	}
	if a.opts.Timeout < 0 {
		return usageErrorf("--timeout must not be negative: %s", a.opts.Timeout)
	}
	format, err := render.ParseFormat(a.output)
	if err != nil {
		return usageError{err}
	}
	a.opts.Format = format
	return nil
}
