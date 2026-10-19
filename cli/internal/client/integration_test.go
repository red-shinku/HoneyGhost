package client

import (
	"context"
	"net"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"google.golang.org/grpc"

	"honeyghost/cli/internal/gen/hng/clisv"
	"honeyghost/cli/internal/model"
)

type fakeRoleServer struct {
	clisv.UnimplementedRoleManagerServiceServer
}

func (fakeRoleServer) GetRoles(_ context.Context, req *clisv.RM_GetRolesRequest) (
	*clisv.RM_GetRolesResponse, error) {
	if req.GetShowoption() == clisv.RM_ShowOption_RM_SHOW_ALL {
		return &clisv.RM_GetRolesResponse{R: []*clisv.Role{
			{RoleID: 7, RoleLabel: "nginx:1.25"},
			{RoleID: 3, RoleLabel: "ssh"},
		}}, nil
	}
	return &clisv.RM_GetRolesResponse{R: []*clisv.Role{
		{RoleID: 7, RoleLabel: "nginx:1.25"},
	}}, nil
}

func (fakeRoleServer) GetProcessSet(context.Context, *clisv.RM_GetProcessSetRequest) (
	*clisv.RM_GetProcessSetResponse, error) {
	return &clisv.RM_GetProcessSetResponse{
		RootPid: 1001,
		Pids:    &clisv.PidList{Pid: []uint32{1002, 1001}},
	}, nil
}

func (fakeRoleServer) GetContextSet(context.Context, *clisv.RM_GetContextSetRequest) (
	*clisv.RM_GetContextSetResponse, error) {
	return &clisv.RM_GetContextSetResponse{ContextID: []uint32{4, 3}}, nil
}

func (fakeRoleServer) GetStats(context.Context, *clisv.RM_GetStatsRequest) (
	*clisv.RM_GetStatsResponse, error) {
	one, two := uint64(1), uint64(2)
	return &clisv.RM_GetStatsResponse{Rejected: &one, OwnerConflict: &two}, nil
}

func (fakeRoleServer) WhichRole(_ context.Context, req *clisv.RM_WhichRoleRequest) (
	*clisv.RM_WhichRoleResponse, error) {
	if req.GetPid() == 1001 {
		id := uint32(7)
		return &clisv.RM_WhichRoleResponse{RoleID: &id}, nil
	}
	return &clisv.RM_WhichRoleResponse{}, nil
}

type fakeContextServer struct {
	clisv.UnimplementedContextManagerServiceServer
}

func (fakeContextServer) GetExcepCtx(context.Context, *clisv.CM_GetExcepCtxRequest) (
	*clisv.CM_GetExcepCtxResponse, error) {
	return &clisv.CM_GetExcepCtxResponse{ContextID: []uint32{4, 3}}, nil
}

func (fakeContextServer) GetExtraCtx(context.Context, *clisv.CM_GetExtraCtxRequest) (
	*clisv.CM_GetExtraCtxResponse, error) {
	return &clisv.CM_GetExtraCtxResponse{ContextID: []uint32{9}}, nil
}

func (fakeContextServer) GetProcessSet(context.Context, *clisv.CM_GetProcessSetRequest) (
	*clisv.CM_GetProcessSetResponse, error) {
	return &clisv.CM_GetProcessSetResponse{
		RootPid: 1001,
		Pids:    &clisv.PidList{Pid: []uint32{1001}},
	}, nil
}

func (fakeContextServer) GetStats(context.Context, *clisv.CM_GetStatsRequest) (
	*clisv.CM_GetStatsResponse, error) {
	return &clisv.CM_GetStatsResponse{CtxrootParentUnsettled: 1, UnknownUnregister: 2}, nil
}

func (fakeContextServer) WhichContext(context.Context, *clisv.CM_WhichContextRequest) (
	*clisv.CM_WhichContextResponse, error) {
	id := uint32(3)
	return &clisv.CM_WhichContextResponse{ContextID: &id}, nil
}

func startTestServer(t *testing.T) string {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "cli.sock")
	lis, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := grpc.NewServer()
	clisv.RegisterRoleManagerServiceServer(server, fakeRoleServer{})
	clisv.RegisterContextManagerServiceServer(server, fakeContextServer{})
	go func() {
		_ = server.Serve(lis)
	}()
	t.Cleanup(server.Stop)
	return socket
}

func TestIntegrationQueries(t *testing.T) {
	socket := startTestServer(t)
	c, err := Dial(context.Background(), socket, Options{UserAgent: "hghost/test"})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()
	svcs := c.Services()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	supervised, err := svcs.Roles.List(ctx, model.RoleScopeSupervision)
	if err != nil {
		t.Fatalf("List(supervision): %v", err)
	}
	if want := []model.Role{{ID: 7, Label: "nginx:1.25"}}; !reflect.DeepEqual(supervised, want) {
		t.Errorf("supervised = %+v, want %+v", supervised, want)
	}

	all, err := svcs.Roles.List(ctx, model.RoleScopeAll)
	if err != nil {
		t.Fatalf("List(all): %v", err)
	}
	if want := []model.Role{{ID: 3, Label: "ssh"}, {ID: 7, Label: "nginx:1.25"}}; !reflect.DeepEqual(all, want) {
		t.Errorf("all = %+v, want %+v", all, want)
	}

	processes, err := svcs.Roles.Processes(ctx, 7)
	if err != nil {
		t.Fatalf("Processes: %v", err)
	}
	if want := (model.ProcessSet{RootPID: 1001, PIDs: []uint32{1002, 1001}}); !reflect.DeepEqual(processes, want) {
		t.Errorf("processes = %+v, want %+v", processes, want)
	}

	contextIDs, err := svcs.Roles.ContextIDs(ctx, 7)
	if err != nil {
		t.Fatalf("ContextIDs: %v", err)
	}
	if want := []uint32{3, 4}; !reflect.DeepEqual(contextIDs, want) {
		t.Errorf("contextIDs = %v, want %v", contextIDs, want)
	}

	roleID, found, err := svcs.Roles.Which(ctx, 1001)
	if err != nil || !found || roleID != 7 {
		t.Errorf("Which(1001) = (%d, %v, %v), want (7, true, nil)", roleID, found, err)
	}
	if _, found, err := svcs.Roles.Which(ctx, 9999); err != nil || found {
		t.Errorf("Which(9999) found = %v, err = %v, want (false, nil)", found, err)
	}

	roleStats, err := svcs.Roles.Stats(ctx)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if roleStats.Rejected == nil || *roleStats.Rejected != 1 {
		t.Errorf("Rejected = %v, want 1", roleStats.Rejected)
	}
	if roleStats.UnknownInstance != nil {
		t.Errorf("UnknownInstance = %v, want nil", roleStats.UnknownInstance)
	}

	excep, err := svcs.Contexts.ExceptionIDs(ctx)
	if err != nil {
		t.Fatalf("ExceptionIDs: %v", err)
	}
	if want := []uint32{3, 4}; !reflect.DeepEqual(excep, want) {
		t.Errorf("excep = %v, want %v", excep, want)
	}

	extra, err := svcs.Contexts.ExtraIDs(ctx)
	if err != nil {
		t.Fatalf("ExtraIDs: %v", err)
	}
	if want := []uint32{9}; !reflect.DeepEqual(extra, want) {
		t.Errorf("extra = %v, want %v", extra, want)
	}

	contextProcesses, err := svcs.Contexts.Processes(ctx, 3)
	if err != nil {
		t.Fatalf("context Processes: %v", err)
	}
	if want := (model.ProcessSet{RootPID: 1001, PIDs: []uint32{1001}}); !reflect.DeepEqual(contextProcesses, want) {
		t.Errorf("context processes = %+v, want %+v", contextProcesses, want)
	}

	contextStats, err := svcs.Contexts.Stats(ctx)
	if err != nil {
		t.Fatalf("context Stats: %v", err)
	}
	if contextStats.CtxrootParentUnsettled == nil || *contextStats.CtxrootParentUnsettled != 1 ||
		contextStats.UnknownUnregister == nil || *contextStats.UnknownUnregister != 2 {
		t.Errorf("context stats = %+v, want 1/2", contextStats)
	}

	contextID, found, err := svcs.Contexts.Which(ctx, 1001)
	if err != nil || !found || contextID != 3 {
		t.Errorf("WhichContext = (%d, %v, %v), want (3, true, nil)", contextID, found, err)
	}
}
