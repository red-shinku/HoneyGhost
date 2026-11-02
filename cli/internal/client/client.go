// Package client 是 api 接口的 gRPC 实现。
//
// 本包封装拨号、RPC 调用与 proto 到 model 的转换；不打印、不退出，也不依赖 Cobra。
// 生成的协议代码只允许出现在本包，不进入命令层与输出契约。
package client

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"honeyghost/cli/internal/api"
	"honeyghost/cli/internal/gen/hng/clisv"
	"honeyghost/cli/internal/model"
)

// Options 是拨号选项。
type Options struct {
	UserAgent string
}

// Client 持有一条 gRPC 连接与四个服务客户端。
type Client struct {
	conn     *grpc.ClientConn
	roles    clisv.RoleManagerServiceClient
	contexts clisv.ContextManagerServiceClient
	process  clisv.ProcessManagerServiceClient
	events   clisv.RuntimeServiceClient
}

// Dial 建立到 socket 的连接。
//
// socket 必须是文件系统路径；连接惰性建立，第一条 RPC 时才真正拨号。
// 不重试、不等待就绪：连接失败由 RPC 以 Unavailable 暴露。
func Dial(_ context.Context, socket string, opts Options) (*Client, error) {
	conn, err := grpc.NewClient("unix:"+socket,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDisableRetry(),
		grpc.WithUserAgent(opts.UserAgent),
	)
	if err != nil {
		return nil, err
	}
	return &Client{
		conn:     conn,
		roles:    clisv.NewRoleManagerServiceClient(conn),
		contexts: clisv.NewContextManagerServiceClient(conn),
		process:  clisv.NewProcessManagerServiceClient(conn),
		events:   clisv.NewRuntimeServiceClient(conn),
	}, nil
}

// Services 返回共享本连接的 api 服务集合。
func (c *Client) Services() api.Services {
	return api.Services{
		Roles:    roleService{c},
		Contexts: contextService{c},
		Process:  processService{c},
		Events:   eventService{c},
	}
}

// Close 关闭底层连接。
func (c *Client) Close() error {
	return c.conn.Close()
}

type roleService struct {
	c *Client
}

func (s roleService) List(ctx context.Context, scope model.RoleScope) ([]model.Role, error) {
	option := clisv.RM_ShowOption_RM_SHOW_SUPERVISION
	if scope == model.RoleScopeAll {
		option = clisv.RM_ShowOption_RM_SHOW_ALL
	}
	resp, err := s.c.roles.GetRoles(ctx, &clisv.RM_GetRolesRequest{Showoption: option})
	if err != nil {
		return nil, statusError("GetRoles", err)
	}
	return convertRoles(resp.GetR()), nil
}

func (s roleService) Processes(ctx context.Context, roleID uint32) (model.ProcessSet, error) {
	resp, err := s.c.roles.GetProcessSet(ctx, &clisv.RM_GetProcessSetRequest{RoleID: roleID})
	if err != nil {
		return model.ProcessSet{}, statusError("GetProcessSet", err)
	}
	return convertProcessSet(resp.GetRootPid(), resp.GetPids()), nil
}

func (s roleService) ContextIDs(ctx context.Context, roleID uint32) ([]uint32, error) {
	resp, err := s.c.roles.GetContextSet(ctx, &clisv.RM_GetContextSetRequest{RoleID: roleID})
	if err != nil {
		return nil, statusError("GetContextSet", err)
	}
	return convertUint32s(resp.GetContextID()), nil
}

func (s roleService) Stats(ctx context.Context) (model.RoleStats, error) {
	resp, err := s.c.roles.GetStats(ctx, &clisv.RM_GetStatsRequest{})
	if err != nil {
		return model.RoleStats{}, statusError("GetStats", err)
	}
	return convertRoleStats(resp), nil
}

func (s roleService) Which(ctx context.Context, pid uint32) (uint32, bool, error) {
	resp, err := s.c.roles.WhichRole(ctx, &clisv.RM_WhichRoleRequest{Pid: pid})
	if err != nil {
		return 0, false, statusError("WhichRole", err)
	}
	roleID, found := convertWhichRole(resp)
	return roleID, found, nil
}

type contextService struct {
	c *Client
}

func (s contextService) ExceptionIDs(ctx context.Context) ([]uint32, error) {
	resp, err := s.c.contexts.GetExcepCtx(ctx, &clisv.CM_GetExcepCtxRequest{})
	if err != nil {
		return nil, statusError("GetExcepCtx", err)
	}
	return convertUint32s(resp.GetContextID()), nil
}

func (s contextService) ExtraIDs(ctx context.Context) ([]uint32, error) {
	resp, err := s.c.contexts.GetExtraCtx(ctx, &clisv.CM_GetExtraCtxRequest{})
	if err != nil {
		return nil, statusError("GetExtraCtx", err)
	}
	return convertUint32s(resp.GetContextID()), nil
}

func (s contextService) Processes(ctx context.Context, contextID uint32) (model.ProcessSet, error) {
	resp, err := s.c.contexts.GetProcessSet(ctx, &clisv.CM_GetProcessSetRequest{ContextID: contextID})
	if err != nil {
		return model.ProcessSet{}, statusError("GetProcessSet", err)
	}
	return convertProcessSet(resp.GetRootPid(), resp.GetPids()), nil
}

func (s contextService) Stats(ctx context.Context) (model.ContextStats, error) {
	resp, err := s.c.contexts.GetStats(ctx, &clisv.CM_GetStatsRequest{})
	if err != nil {
		return model.ContextStats{}, statusError("GetStats", err)
	}
	return convertContextStats(resp), nil
}

func (s contextService) Which(ctx context.Context, pid uint32) (uint32, bool, error) {
	resp, err := s.c.contexts.WhichContext(ctx, &clisv.CM_WhichContextRequest{Pid: pid})
	if err != nil {
		return 0, false, statusError("WhichContext", err)
	}
	contextID, found := convertWhichContext(resp)
	return contextID, found, nil
}

type processService struct {
	c *Client
}

func (s processService) Stats(ctx context.Context) (model.ProcessStats, error) {
	resp, err := s.c.process.GetStats(ctx, &clisv.PM_GetStatsRequest{})
	if err != nil {
		return model.ProcessStats{}, statusError("GetStats", err)
	}
	return convertProcessStats(resp), nil
}

type eventService struct {
	c *Client
}

func (s eventService) Subscribe(ctx context.Context, sel model.RuntimeSelector,
	types []model.EventType) (api.EventStream, error) {
	request := &clisv.ReceiveEventRequest{}
	for _, eventType := range types {
		converted, err := toProtoEventType(eventType)
		if err != nil {
			return nil, err
		}
		request.Etype = append(request.Etype, converted)
	}
	if !sel.IsZero() {
		request.Info = &clisv.Runtimeinfo{
			RoleID:    append([]uint32(nil), sel.RoleIDs...),
			RoleLabel: append([]string(nil), sel.RoleLabels...),
			ContextID: append([]uint32(nil), sel.ContextIDs...),
			Pid:       append([]uint32(nil), sel.PIDs...),
		}
	}

	stream, err := s.c.events.ReceiveEvent(ctx, request)
	if err != nil {
		return nil, statusError("ReceiveEvent", err)
	}
	return &eventStream{stream: stream}, nil
}
