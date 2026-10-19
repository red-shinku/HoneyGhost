package cmd

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"honeyghost/cli/internal/api"
	"honeyghost/cli/internal/model"
)

type fakeRoleService struct {
	list       func(context.Context, model.RoleScope) ([]model.Role, error)
	processes  func(context.Context, uint32) (model.ProcessSet, error)
	contextIDs func(context.Context, uint32) ([]uint32, error)
	stats      func(context.Context) (model.RoleStats, error)
	which      func(context.Context, uint32) (uint32, bool, error)
}

func (f fakeRoleService) List(ctx context.Context, scope model.RoleScope) ([]model.Role, error) {
	return f.list(ctx, scope)
}

func (f fakeRoleService) Processes(ctx context.Context, id uint32) (model.ProcessSet, error) {
	return f.processes(ctx, id)
}

func (f fakeRoleService) ContextIDs(ctx context.Context, id uint32) ([]uint32, error) {
	return f.contextIDs(ctx, id)
}

func (f fakeRoleService) Stats(ctx context.Context) (model.RoleStats, error) {
	return f.stats(ctx)
}

func (f fakeRoleService) Which(ctx context.Context, pid uint32) (uint32, bool, error) {
	return f.which(ctx, pid)
}

type fakeContextService struct {
	exceptionIDs func(context.Context) ([]uint32, error)
	extraIDs     func(context.Context) ([]uint32, error)
	processes    func(context.Context, uint32) (model.ProcessSet, error)
	stats        func(context.Context) (model.ContextStats, error)
	which        func(context.Context, uint32) (uint32, bool, error)
}

func (f fakeContextService) ExceptionIDs(ctx context.Context) ([]uint32, error) {
	return f.exceptionIDs(ctx)
}

func (f fakeContextService) ExtraIDs(ctx context.Context) ([]uint32, error) {
	return f.extraIDs(ctx)
}

func (f fakeContextService) Processes(ctx context.Context, id uint32) (model.ProcessSet, error) {
	return f.processes(ctx, id)
}

func (f fakeContextService) Stats(ctx context.Context) (model.ContextStats, error) {
	return f.stats(ctx)
}

func (f fakeContextService) Which(ctx context.Context, pid uint32) (uint32, bool, error) {
	return f.which(ctx, pid)
}

type fakeEventService struct{}

func (fakeEventService) Subscribe(context.Context, model.RuntimeSelector,
	[]model.EventType) (api.EventStream, error) {
	panic("unexpected Subscribe")
}

func executeWithServices(t *testing.T, svcs api.Services, args ...string) (string, string, error) {
	t.Helper()
	t.Setenv("HGHOST_SOCKET", "")
	app := NewApp(func(context.Context, string) (api.Services, io.Closer, error) {
		return svcs, io.NopCloser(strings.NewReader("")), nil
	})
	out, errOut := new(bytes.Buffer), new(bytes.Buffer)
	root := NewRootCommand(app, testBuild)
	root.SetOut(out)
	root.SetErr(errOut)
	root.SetArgs(args)
	err := root.ExecuteContext(context.Background())
	return out.String(), errOut.String(), err
}

func executeWithoutDial(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	t.Setenv("HGHOST_SOCKET", "")
	app := NewApp(func(context.Context, string) (api.Services, io.Closer, error) {
		t.Fatalf("dial must not be called for %v", args)
		return api.Services{}, nil, nil
	})
	out, errOut := new(bytes.Buffer), new(bytes.Buffer)
	root := NewRootCommand(app, testBuild)
	root.SetOut(out)
	root.SetErr(errOut)
	root.SetArgs(args)
	err := root.ExecuteContext(context.Background())
	return out.String(), errOut.String(), err
}

func TestRoleListTable(t *testing.T) {
	var gotScope model.RoleScope
	svcs := api.Services{Roles: fakeRoleService{
		list: func(_ context.Context, scope model.RoleScope) ([]model.Role, error) {
			gotScope = scope
			return []model.Role{{ID: 3, Label: "ssh"}}, nil
		},
	}}
	out, errOut, err := executeWithServices(t, svcs, "role", "list")
	if err != nil {
		t.Fatalf("role list: %v", err)
	}
	if gotScope != model.RoleScopeSupervision {
		t.Errorf("scope = %v, want supervision", gotScope)
	}
	want := "ID  LABEL\n3   ssh\n"
	if out != want {
		t.Errorf("stdout = %q, want %q", out, want)
	}
	if errOut != "" {
		t.Errorf("stderr = %q, want empty", errOut)
	}
}

func TestRoleListAllJSON(t *testing.T) {
	var gotScope model.RoleScope
	svcs := api.Services{Roles: fakeRoleService{
		list: func(_ context.Context, scope model.RoleScope) ([]model.Role, error) {
			gotScope = scope
			return []model.Role{{ID: 3, Label: "ssh"}}, nil
		},
	}}
	out, _, err := executeWithServices(t, svcs, "role", "list", "--all", "-o", "json")
	if err != nil {
		t.Fatalf("role list: %v", err)
	}
	if gotScope != model.RoleScopeAll {
		t.Errorf("scope = %v, want all", gotScope)
	}
	want := "[\n  {\n    \"role_id\": 3,\n    \"role_label\": \"ssh\"\n  }\n]\n"
	if out != want {
		t.Errorf("stdout = %q, want %q", out, want)
	}
}

func TestRoleListEmpty(t *testing.T) {
	svcs := api.Services{Roles: fakeRoleService{
		list: func(context.Context, model.RoleScope) ([]model.Role, error) {
			return []model.Role{}, nil
		},
	}}
	out, errOut, err := executeWithServices(t, svcs, "role", "list")
	if err != nil {
		t.Fatalf("role list: %v", err)
	}
	if out != "ID  LABEL\n" {
		t.Errorf("stdout = %q, want header only", out)
	}
	if errOut != "no matching entries\n" {
		t.Errorf("stderr = %q, want no matching entries", errOut)
	}

	out, errOut, err = executeWithServices(t, svcs, "role", "list", "-o", "json")
	if err != nil {
		t.Fatalf("role list json: %v", err)
	}
	if out != "[]\n" {
		t.Errorf("json stdout = %q, want []", out)
	}
	if errOut != "" {
		t.Errorf("json stderr = %q, want empty", errOut)
	}
}

func TestRoleListError(t *testing.T) {
	svcs := api.Services{Roles: fakeRoleService{
		list: func(context.Context, model.RoleScope) ([]model.Role, error) {
			return nil, &api.StatusError{Op: "GetRoles", Kind: api.ErrorUnavailable, Message: "boom"}
		},
	}}
	out, _, err := executeWithServices(t, svcs, "role", "list")
	if err == nil {
		t.Fatal("expected an error")
	}
	if out != "" {
		t.Errorf("stdout = %q, want empty", out)
	}
	if ExitCode(err, false) != 1 {
		t.Errorf("ExitCode = %d, want 1", ExitCode(err, false))
	}
	if !strings.Contains(err.Error(), "cannot connect to the CLI service") {
		t.Errorf("error = %q, want mapped Unavailable message", err.Error())
	}
}

func TestRoleStats(t *testing.T) {
	svcs := api.Services{Roles: fakeRoleService{
		stats: func(context.Context) (model.RoleStats, error) {
			return model.RoleStats{Rejected: uint64Ptr(0), OwnerConflict: uint64Ptr(2)}, nil
		},
	}}
	out, _, err := executeWithServices(t, svcs, "role", "stats")
	if err != nil {
		t.Fatalf("role stats: %v", err)
	}
	for _, line := range []string{
		"COUNTER", "rejected", "0", "unknown_instance", "-", "owner_conflict", "2",
	} {
		if !strings.Contains(out, line) {
			t.Errorf("stdout missing %q:\n%s", line, out)
		}
	}
}

func TestRoleWhich(t *testing.T) {
	svcs := api.Services{Roles: fakeRoleService{
		which: func(_ context.Context, pid uint32) (uint32, bool, error) {
			if pid != 1234 {
				t.Errorf("pid = %d, want 1234", pid)
			}
			return 7, true, nil
		},
	}}
	out, errOut, err := executeWithServices(t, svcs, "role", "which", "1234")
	if err != nil {
		t.Fatalf("role which: %v", err)
	}
	if out != "7\n" {
		t.Errorf("stdout = %q, want 7", out)
	}
	if errOut != "" {
		t.Errorf("stderr = %q, want empty", errOut)
	}

	out, _, err = executeWithServices(t, svcs, "role", "which", "1234", "-o", "json")
	if err != nil {
		t.Fatalf("role which json: %v", err)
	}
	if want := "{\n  \"role_id\": 7\n}\n"; out != want {
		t.Errorf("json stdout = %q, want %q", out, want)
	}
}

func TestRoleWhichNotFound(t *testing.T) {
	svcs := api.Services{Roles: fakeRoleService{
		which: func(context.Context, uint32) (uint32, bool, error) {
			return 0, false, nil
		},
	}}
	out, errOut, err := executeWithServices(t, svcs, "role", "which", "1234")
	if err != nil {
		t.Fatalf("role which: %v", err)
	}
	if out != "" {
		t.Errorf("stdout = %q, want empty", out)
	}
	if errOut != "pid 1234 has no role\n" {
		t.Errorf("stderr = %q, want pid hint", errOut)
	}

	out, errOut, err = executeWithServices(t, svcs, "role", "which", "1234", "-o", "json")
	if err != nil {
		t.Fatalf("role which json: %v", err)
	}
	if want := "{\n  \"role_id\": null\n}\n"; out != want {
		t.Errorf("json stdout = %q, want %q", out, want)
	}
	if errOut != "" {
		t.Errorf("json stderr = %q, want empty", errOut)
	}
}

func TestGroupRejectsUnknownSubcommand(t *testing.T) {
	for _, group := range []string{"role", "context"} {
		t.Run(group, func(t *testing.T) {
			_, _, err := executeWithoutDial(t, group, "bogus")
			if err == nil {
				t.Fatal("expected an error")
			}
			if ExitCode(err, false) != 2 {
				t.Errorf("ExitCode = %d, want 2", ExitCode(err, false))
			}
		})
	}
}

func TestGroupWithoutSubcommandPrintsHelp(t *testing.T) {
	for _, group := range []string{"role", "context"} {
		t.Run(group, func(t *testing.T) {
			out, _, err := executeWithoutDial(t, group)
			if err != nil {
				t.Fatalf("%s: %v", group, err)
			}
			if !strings.Contains(out, "Available Commands:") {
				t.Errorf("%s output does not look like help:\n%s", group, out)
			}
		})
	}
}

func TestInvalidPID(t *testing.T) {
	for _, pid := range []string{"0", "abc", "4294967296"} {
		t.Run(pid, func(t *testing.T) {
			_, _, err := executeWithoutDial(t, "role", "which", pid)
			if err == nil {
				t.Fatal("expected an error")
			}
			if ExitCode(err, false) != 2 {
				t.Errorf("ExitCode = %d, want 2", ExitCode(err, false))
			}
		})
	}
}

func TestContextListDefault(t *testing.T) {
	callExtra := false
	svcs := api.Services{Contexts: fakeContextService{
		exceptionIDs: func(context.Context) ([]uint32, error) { return []uint32{3}, nil },
		extraIDs: func(context.Context) ([]uint32, error) {
			callExtra = true
			return nil, nil
		},
	}}
	out, _, err := executeWithServices(t, svcs, "context", "list")
	if err != nil {
		t.Fatalf("context list: %v", err)
	}
	if callExtra {
		t.Error("extra contexts queried without -k extra")
	}
	want := "KIND   CONTEXT_ID\nexcep  3\n"
	if out != want {
		t.Errorf("stdout = %q, want %q", out, want)
	}
}

func TestContextListKinds(t *testing.T) {
	svcs := api.Services{Contexts: fakeContextService{
		exceptionIDs: func(context.Context) ([]uint32, error) { return []uint32{3}, nil },
		extraIDs:     func(context.Context) ([]uint32, error) { return []uint32{4}, nil },
	}}
	out, _, err := executeWithServices(t, svcs, "context", "list", "-k", "excep,extra")
	if err != nil {
		t.Fatalf("context list: %v", err)
	}
	want := "KIND   CONTEXT_ID\nexcep  3\nextra  4\n"
	if out != want {
		t.Errorf("stdout = %q, want %q", out, want)
	}

	out, _, err = executeWithServices(t, svcs, "context", "list", "-k", "all", "-o", "json")
	if err != nil {
		t.Fatalf("context list json: %v", err)
	}
	wantJSON := "[\n  {\n    \"kind\": \"excep\",\n    \"context_id\": 3\n  },\n" +
		"  {\n    \"kind\": \"extra\",\n    \"context_id\": 4\n  }\n]\n"
	if out != wantJSON {
		t.Errorf("json stdout = %q, want %q", out, wantJSON)
	}
}

func TestContextListKindExtraOnly(t *testing.T) {
	callExcep := false
	svcs := api.Services{Contexts: fakeContextService{
		exceptionIDs: func(context.Context) ([]uint32, error) {
			callExcep = true
			return nil, nil
		},
		extraIDs: func(context.Context) ([]uint32, error) { return []uint32{4}, nil },
	}}
	out, _, err := executeWithServices(t, svcs, "context", "list", "-k", "extra")
	if err != nil {
		t.Fatalf("context list: %v", err)
	}
	if callExcep {
		t.Error("exception contexts queried with -k extra")
	}
	if want := "KIND   CONTEXT_ID\nextra  4\n"; out != want {
		t.Errorf("stdout = %q, want %q", out, want)
	}
}

func TestContextListRepeatedKindFlags(t *testing.T) {
	svcs := api.Services{Contexts: fakeContextService{
		exceptionIDs: func(context.Context) ([]uint32, error) { return []uint32{3}, nil },
		extraIDs:     func(context.Context) ([]uint32, error) { return []uint32{4}, nil },
	}}
	out, _, err := executeWithServices(t, svcs, "context", "list", "-k", "extra", "-k", "excep")
	if err != nil {
		t.Fatalf("context list: %v", err)
	}
	if want := "KIND   CONTEXT_ID\nexcep  3\nextra  4\n"; out != want {
		t.Errorf("stdout = %q, want %q", out, want)
	}
}

func TestContextListAllFail(t *testing.T) {
	failing := func(context.Context) ([]uint32, error) {
		return nil, &api.StatusError{Op: "Get", Kind: api.ErrorUnavailable, Message: "boom"}
	}
	svcs := api.Services{Contexts: fakeContextService{
		exceptionIDs: failing,
		extraIDs:     failing,
	}}
	out, errOut, err := executeWithServices(t, svcs, "context", "list", "-k", "all")
	if err == nil {
		t.Fatal("expected an error")
	}
	if out != "" {
		t.Errorf("stdout = %q, want empty", out)
	}
	if errOut != "" {
		t.Errorf("stderr = %q, want empty", errOut)
	}
	if ExitCode(err, false) != 1 {
		t.Errorf("ExitCode = %d, want 1", ExitCode(err, false))
	}
	if !strings.Contains(err.Error(), "excep contexts:") ||
		!strings.Contains(err.Error(), "extra contexts:") {
		t.Errorf("error = %q, want both failed segments", err.Error())
	}
}

func TestContextListInvalidKind(t *testing.T) {
	_, _, err := executeWithoutDial(t, "context", "list", "-k", "bogus")
	if err == nil {
		t.Fatal("expected an error")
	}
	if ExitCode(err, false) != 2 {
		t.Errorf("ExitCode = %d, want 2", ExitCode(err, false))
	}
}

func TestContextListPartialFailure(t *testing.T) {
	svcs := api.Services{Contexts: fakeContextService{
		exceptionIDs: func(context.Context) ([]uint32, error) {
			return nil, &api.StatusError{
				Op: "GetExcepCtx", Kind: api.ErrorUnimplemented, Message: "nope",
			}
		},
		extraIDs: func(context.Context) ([]uint32, error) { return []uint32{4}, nil },
	}}
	out, errOut, err := executeWithServices(t, svcs, "context", "list", "-k", "all")
	if err == nil {
		t.Fatal("expected an error")
	}
	if want := "KIND   CONTEXT_ID\nextra  4\n"; out != want {
		t.Errorf("stdout = %q, want %q", out, want)
	}
	if errOut != "" {
		t.Errorf("stderr = %q, want empty (hint suppressed on failure)", errOut)
	}
	if ExitCode(err, false) != 1 {
		t.Errorf("ExitCode = %d, want 1", ExitCode(err, false))
	}
	want := "excep contexts: GetExcepCtx is not implemented by the server: nope"
	if err.Error() != want {
		t.Errorf("error = %q, want %q", err.Error(), want)
	}
}

func TestContextListEmpty(t *testing.T) {
	svcs := api.Services{Contexts: fakeContextService{
		exceptionIDs: func(context.Context) ([]uint32, error) { return []uint32{}, nil },
	}}
	out, errOut, err := executeWithServices(t, svcs, "context", "list")
	if err != nil {
		t.Fatalf("context list: %v", err)
	}
	if out != "KIND  CONTEXT_ID\n" {
		t.Errorf("stdout = %q, want header only", out)
	}
	if errOut != "no matching entries\n" {
		t.Errorf("stderr = %q, want hint", errOut)
	}
}

func TestContextStats(t *testing.T) {
	svcs := api.Services{Contexts: fakeContextService{
		stats: func(context.Context) (model.ContextStats, error) {
			return model.ContextStats{
				CtxrootParentUnsettled: uint64Ptr(1),
				UnknownUnregister:      uint64Ptr(2),
			}, nil
		},
	}}
	out, _, err := executeWithServices(t, svcs, "context", "stats")
	if err != nil {
		t.Fatalf("context stats: %v", err)
	}
	for _, line := range []string{"COUNTER", "ctxroot_parent_unsettled", "1", "unknown_unregister", "2"} {
		if !strings.Contains(out, line) {
			t.Errorf("stdout missing %q:\n%s", line, out)
		}
	}
}

func TestContextWhich(t *testing.T) {
	found := true
	svcs := api.Services{Contexts: fakeContextService{
		which: func(_ context.Context, pid uint32) (uint32, bool, error) {
			return 3, found, nil
		},
	}}
	out, _, err := executeWithServices(t, svcs, "context", "which", "1234")
	if err != nil {
		t.Fatalf("context which: %v", err)
	}
	if out != "3\n" {
		t.Errorf("stdout = %q, want 3", out)
	}

	out, errOut, err := executeWithServices(t, svcs, "context", "which", "1234", "-o", "json")
	if err != nil {
		t.Fatalf("context which json: %v", err)
	}
	if want := "{\n  \"context_id\": 3\n}\n"; out != want {
		t.Errorf("json stdout = %q, want %q", out, want)
	}

	found = false
	out, errOut, err = executeWithServices(t, svcs, "context", "which", "1234")
	if err != nil {
		t.Fatalf("context which not found: %v", err)
	}
	if out != "" {
		t.Errorf("stdout = %q, want empty", out)
	}
	if errOut != "pid 1234 has no context\n" {
		t.Errorf("stderr = %q, want hint", errOut)
	}
}

func uint64Ptr(v uint64) *uint64 { return &v }
