package client

import (
	"context"
	"errors"
	"io"
	"net"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"google.golang.org/grpc"

	"honeyghost/cli/internal/api"
	"honeyghost/cli/internal/gen/hng"
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
	one, two, seven := uint64(1), uint64(2), uint64(7)
	return &clisv.RM_GetStatsResponse{
		Rejected:           &one,
		OwnerConflict:      &two,
		BindDeferred:       &seven,
		TombstoneDepth:     &seven,
		DeadMemberRejected: &seven,
	}, nil
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
	return &clisv.CM_GetStatsResponse{
		CtxrootParentUnsettled: 1,
		UnknownUnregister:      2,
		PendingDepth:           3,
		TombstoneDepth:         4,
	}, nil
}

func (fakeContextServer) WhichContext(context.Context, *clisv.CM_WhichContextRequest) (
	*clisv.CM_WhichContextResponse, error) {
	id := uint32(3)
	return &clisv.CM_WhichContextResponse{ContextID: &id}, nil
}

type fakeProcessServer struct {
	clisv.UnimplementedProcessManagerServiceServer
}

func (fakeProcessServer) GetStats(context.Context, *clisv.PM_GetStatsRequest) (
	*clisv.PM_GetStatsResponse, error) {
	one, four := uint64(1), uint64(4)
	return &clisv.PM_GetStatsResponse{
		PidReused:      &one,
		TombstoneDepth: &four,
	}, nil
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
	clisv.RegisterProcessManagerServiceServer(server, fakeProcessServer{})
	go func() {
		_ = server.Serve(lis)
	}()
	t.Cleanup(server.Stop)
	return socket
}

func startEventServer(t *testing.T, runtime clisv.RuntimeServiceServer) string {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "cli.sock")
	lis, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := grpc.NewServer()
	clisv.RegisterRuntimeServiceServer(server, runtime)
	go func() {
		_ = server.Serve(lis)
	}()
	t.Cleanup(server.Stop)
	return socket
}

type streamingRuntimeServer struct {
	clisv.UnimplementedRuntimeServiceServer
	requests chan *clisv.ReceiveEventRequest
}

func (s *streamingRuntimeServer) ReceiveEvent(req *clisv.ReceiveEventRequest,
	stream grpc.ServerStreamingServer[clisv.ReceiveEventResponse]) error {
	s.requests <- req
	if err := stream.Send(&clisv.ReceiveEventResponse{
		Payload: &clisv.ReceiveEventResponse_Batch{Batch: &clisv.ReceiveEventBatch{
			Records: []*clisv.Eventrecord{{
				Head: testHead(),
				Event: &clisv.Eventrecord_SyscallEv{SyscallEv: &clisv.SyscallEventData{
					SData: &clisv.SyscallEventData_ExecData{ExecData: &hng.ExecSemanticData{
						SemanticFilename: "/usr/sbin/nginx",
						SyscallName:      "execve",
					}},
				}},
			}},
		}},
	}); err != nil {
		return err
	}
	return stream.Send(&clisv.ReceiveEventResponse{
		Payload: &clisv.ReceiveEventResponse_Stats{Stats: &clisv.Streamstats{DroppedEvents: 3}},
	})
}

func TestIntegrationEventStream(t *testing.T) {
	server := &streamingRuntimeServer{requests: make(chan *clisv.ReceiveEventRequest, 1)}
	socket := startEventServer(t, server)

	c, err := Dial(context.Background(), socket, Options{UserAgent: "hghost/test"})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	selector := model.RuntimeSelector{
		RoleIDs:    []uint32{7, 8},
		RoleLabels: []string{"nginx"},
		ContextIDs: []uint32{3},
		PIDs:       []uint32{1234},
	}
	stream, err := c.Services().Events.Subscribe(ctx, selector,
		[]model.EventType{model.EventTypeFile, model.EventTypeSyscall},
		api.SubscribeOptions{BatchSize: 7})
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer stream.Close()

	req := <-server.requests
	wantTypes := []clisv.EventType{
		clisv.EventType_EVENT_TYPE_FILE,
		clisv.EventType_EVENT_TYPE_SYSCALL,
	}
	if !reflect.DeepEqual(req.Etype, wantTypes) {
		t.Errorf("Etype = %v, want %v", req.Etype, wantTypes)
	}
	if req.BatchSize != 7 {
		t.Errorf("BatchSize = %d, want 7", req.BatchSize)
	}
	if req.Info == nil {
		t.Fatal("Info = nil, want selector")
	}
	if !reflect.DeepEqual(req.Info.RoleID, []uint32{7, 8}) ||
		!reflect.DeepEqual(req.Info.RoleLabel, []string{"nginx"}) ||
		!reflect.DeepEqual(req.Info.ContextID, []uint32{3}) ||
		!reflect.DeepEqual(req.Info.Pid, []uint32{1234}) {
		t.Errorf("Info = %+v, want the parsed selector", req.Info)
	}

	item, err := stream.Recv()
	if err != nil {
		t.Fatalf("Recv event: %v", err)
	}
	if item.Event == nil || item.Event.Payload.Kind != model.PayloadExec {
		t.Fatalf("event = %+v, want exec payload", item.Event)
	}
	if item.Event.Head.PID != 1234 || item.Event.Head.Type != model.EventTypeSyscall {
		t.Errorf("head = %+v, want test head", item.Event.Head)
	}

	item, err = stream.Recv()
	if err != nil {
		t.Fatalf("Recv stats: %v", err)
	}
	if item.Stats == nil || item.Stats.DroppedEvents != 3 {
		t.Fatalf("stats = %+v, want 3 dropped", item.Stats)
	}

	if _, err := stream.Recv(); !errors.Is(err, io.EOF) {
		t.Errorf("final Recv error = %v, want io.EOF", err)
	}
}

type recordingRuntimeServer struct {
	clisv.UnimplementedRuntimeServiceServer
	requests chan *clisv.ReceiveEventRequest
}

func (s *recordingRuntimeServer) ReceiveEvent(req *clisv.ReceiveEventRequest,
	_ grpc.ServerStreamingServer[clisv.ReceiveEventResponse]) error {
	s.requests <- req
	return nil
}

func TestIntegrationEventRequestEmpty(t *testing.T) {
	server := &recordingRuntimeServer{requests: make(chan *clisv.ReceiveEventRequest, 1)}
	socket := startEventServer(t, server)

	c, err := Dial(context.Background(), socket, Options{UserAgent: "hghost/test"})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	stream, err := c.Services().Events.Subscribe(context.Background(),
		model.RuntimeSelector{}, nil, api.SubscribeOptions{})
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer stream.Close()

	req := <-server.requests
	if req.Info != nil {
		t.Errorf("Info = %+v, want nil", req.Info)
	}
	if len(req.Etype) != 0 {
		t.Errorf("Etype = %v, want empty", req.Etype)
	}
	if _, err := stream.Recv(); !errors.Is(err, io.EOF) {
		t.Errorf("Recv error = %v, want io.EOF", err)
	}
}

type blockingRuntimeServer struct {
	clisv.UnimplementedRuntimeServiceServer
}

func (blockingRuntimeServer) ReceiveEvent(_ *clisv.ReceiveEventRequest,
	stream grpc.ServerStreamingServer[clisv.ReceiveEventResponse]) error {
	<-stream.Context().Done()
	return stream.Context().Err()
}

func TestIntegrationEventStreamCanceled(t *testing.T) {
	socket := startEventServer(t, blockingRuntimeServer{})

	c, err := Dial(context.Background(), socket, Options{UserAgent: "hghost/test"})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	ctx, cancel := context.WithCancel(context.Background())
	stream, err := c.Services().Events.Subscribe(ctx, model.RuntimeSelector{}, nil,
		api.SubscribeOptions{})
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer stream.Close()

	timer := time.AfterFunc(50*time.Millisecond, cancel)
	defer timer.Stop()

	_, err = stream.Recv()
	var se *api.StatusError
	if !errors.As(err, &se) {
		t.Fatalf("Recv error = %T (%v), want *api.StatusError", err, err)
	}
	if se.Kind != api.ErrorCanceled {
		t.Errorf("Kind = %v, want ErrorCanceled", se.Kind)
	}
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
	if roleStats.BindDeferred == nil || *roleStats.BindDeferred != 7 {
		t.Errorf("BindDeferred = %v, want 7", roleStats.BindDeferred)
	}
	if roleStats.DeadMemberRejected == nil || *roleStats.DeadMemberRejected != 7 {
		t.Errorf("DeadMemberRejected = %v, want 7", roleStats.DeadMemberRejected)
	}
	if roleStats.DeadAnchorRejected != nil {
		t.Errorf("DeadAnchorRejected = %v, want nil", roleStats.DeadAnchorRejected)
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
	if contextStats.PendingDepth == nil || *contextStats.PendingDepth != 3 {
		t.Errorf("PendingDepth = %v, want 3", contextStats.PendingDepth)
	}
	if contextStats.TombstoneDepth == nil || *contextStats.TombstoneDepth != 4 {
		t.Errorf("TombstoneDepth = %v, want 4", contextStats.TombstoneDepth)
	}

	processStats, err := svcs.Process.Stats(ctx)
	if err != nil {
		t.Fatalf("process Stats: %v", err)
	}
	if processStats.PidReused == nil || *processStats.PidReused != 1 {
		t.Errorf("PidReused = %v, want 1", processStats.PidReused)
	}
	if processStats.TombstoneDepth == nil || *processStats.TombstoneDepth != 4 {
		t.Errorf("TombstoneDepth = %v, want 4", processStats.TombstoneDepth)
	}
	if processStats.StaleAdd != nil {
		t.Errorf("StaleAdd = %v, want nil", processStats.StaleAdd)
	}

	contextID, found, err := svcs.Contexts.Which(ctx, 1001)
	if err != nil || !found || contextID != 3 {
		t.Errorf("WhichContext = (%d, %v, %v), want (3, true, nil)", contextID, found, err)
	}
}
