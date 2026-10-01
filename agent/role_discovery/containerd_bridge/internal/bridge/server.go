package bridge

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"honeyghost/containerd_bridge/internal/protocol"
)

// writeTimeout 是写一帧的上限。C++ 侧若不读，写出会一直阻塞，本进程的内存
// 与订阅随之积压；超时即判定该连接不可用。
const writeTimeout = 5 * time.Second

// Server 在 Unix socket 上服务 C++ 发现器。
//
// 单客户端：C++ 侧只有一条连接，新连接顶掉旧连接，旧会话的写出随即失败并
// 退出。这样 C++ 重启后不必等旧会话自然结束。
type Server struct {
	// Socket 是监听路径。
	Socket string
	// Config 是会话参数。
	Config Config
	// Log 是日志出口，为空则用默认出口。
	Log *slog.Logger

	mu     sync.Mutex
	cancel context.CancelFunc
}

// Serve 监听并服务连接，直到 ctx 结束。
func (srv *Server) Serve(ctx context.Context) error {
	if srv.Log == nil {
		srv.Log = slog.Default()
	}
	listener, err := srv.listen(ctx)
	if err != nil {
		return err
	}
	defer listener.Close()

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("接受连接失败: %w", err)
		}
		go srv.serveConn(ctx, conn)
	}
}

// listen 绑定监听路径，先清掉上一轮留下的 socket 文件。
func (srv *Server) listen(ctx context.Context) (net.Listener, error) {
	if err := removeStaleSocket(srv.Socket); err != nil {
		return nil, err
	}
	var lc net.ListenConfig
	listener, err := lc.Listen(ctx, "unix", srv.Socket)
	if err != nil {
		return nil, fmt.Errorf("监听 %s 失败: %w", srv.Socket, err)
	}
	return listener, nil
}

// removeStaleSocket 删除残留的 socket 文件。
//
// 只删 socket：路径上若是别的东西（普通文件、目录），说明配置指错了地方，
// 不能替调用方做决定。
func removeStaleSocket(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("检查 %s 失败: %w", path, err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("%s 已存在且不是 socket，拒绝覆盖", path)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("删除残留 socket %s 失败: %w", path, err)
	}
	return nil
}

// serveConn 服务一条连接，直到其会话结束。
func (srv *Server) serveConn(ctx context.Context, conn net.Conn) {
	sessionCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer conn.Close()

	srv.mu.Lock()
	if srv.cancel != nil {
		srv.cancel() // 顶掉旧连接
	}
	srv.cancel = cancel
	srv.mu.Unlock()

	srv.Log.Info("C++ 发现器已连接", "peer", conn.RemoteAddr().String())
	NewSession(srv.Config, &connWriter{conn: conn}).Run(sessionCtx)
	srv.Log.Info("C++ 发现器连接结束", "peer", conn.RemoteAddr().String())
}

// connWriter 是会话的帧出口。
type connWriter struct {
	mu   sync.Mutex
	conn net.Conn
}

func (w *connWriter) Send(frame *protocol.Frame) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if err := w.conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		return err
	}
	return protocol.WriteFrame(w.conn, frame)
}
