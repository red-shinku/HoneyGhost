// Package api 定义 CLI 的消费者侧服务接口。
//
// 命令层只依赖本包；传输层实现本包，并在测试中以假件替代。
package api

import (
	"context"
	"fmt"

	"honeyghost/cli/internal/model"
)

// SubscribeOptions 是事件订阅的可选参数。
type SubscribeOptions struct {
	// BatchSize 是单条响应最多携带的事件数；0 表示由服务端取默认值。
	BatchSize uint32
}

// Services 汇总四类服务。结构体而非接口，避免为每个服务再造一层包装。
type Services struct {
	Roles    RoleService
	Contexts ContextService
	Process  ProcessService
	Events   EventService
}

// RoleService 是角色管理器的消费者侧视图；每个方法对应一个 RPC。
type RoleService interface {
	List(ctx context.Context, scope model.RoleScope) ([]model.Role, error)
	Processes(ctx context.Context, roleID uint32) (model.ProcessSet, error)
	ContextIDs(ctx context.Context, roleID uint32) ([]uint32, error)
	Stats(ctx context.Context) (model.RoleStats, error)
	Which(ctx context.Context, pid uint32) (roleID uint32, found bool, err error)
}

// ContextService 是上下文管理器的消费者侧视图；每个方法对应一个 RPC。
type ContextService interface {
	ExceptionIDs(ctx context.Context) ([]uint32, error)
	ExtraIDs(ctx context.Context) ([]uint32, error)
	Processes(ctx context.Context, contextID uint32) (model.ProcessSet, error)
	Stats(ctx context.Context) (model.ContextStats, error)
	Which(ctx context.Context, pid uint32) (contextID uint32, found bool, err error)
}

// ProcessService 是进程管理器的消费者侧视图；每个方法对应一个 RPC。
type ProcessService interface {
	Stats(ctx context.Context) (model.ProcessStats, error)
}

// EventService 提供运行时事件订阅。
type EventService interface {
	Subscribe(ctx context.Context, sel model.RuntimeSelector,
		types []model.EventType, opts SubscribeOptions) (EventStream, error)
	Stats(ctx context.Context) (model.PipelineStats, error)
}

// EventStream 是一次订阅的消费端。Recv 在服务端正常结束流时返回 io.EOF。
type EventStream interface {
	Recv() (model.StreamItem, error)
	Close() error
}

// ErrorKind 是 gRPC 状态码的消费者侧投影，使 api 不依赖 gRPC。
type ErrorKind int

const (
	ErrorUnavailable ErrorKind = iota
	ErrorDeadlineExceeded
	ErrorUnimplemented
	ErrorInvalidArgument
	ErrorPermissionDenied
	ErrorResourceExhausted
	ErrorCanceled
	ErrorOther
)

// StatusError 是 RPC 失败的共享契约。
//
// client 填充；cmd 据此组装用户文案与退出码。本类型不打印、不退出。
type StatusError struct {
	Op      string // RPC 名
	Kind    ErrorKind
	Code    string // gRPC 状态码名，ErrorOther 的文案需要
	Message string // 服务端提供的消息
}

func (e *StatusError) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("%s: %s", e.Op, e.Message)
	}
	return fmt.Sprintf("%s (%s): %s", e.Op, e.Code, e.Message)
}
