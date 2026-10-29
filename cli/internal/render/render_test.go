package render

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"honeyghost/cli/internal/model"
)

var update = flag.Bool("update", false, "update golden files")

func checkGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name+".golden")
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if got != string(want) {
		t.Errorf("%s mismatch:\n--- got ---\n%s--- want ---\n%s", name, got, want)
	}
}

func render(t *testing.T, format Format, opts Options, fn func(Renderer, *bytes.Buffer) error) string {
	t.Helper()
	var buf bytes.Buffer
	if err := fn(New(format, opts), &buf); err != nil {
		t.Fatalf("render: %v", err)
	}
	return buf.String()
}

func uint64Ptr(v uint64) *uint64 { return &v }

func TestGoldenRoles(t *testing.T) {
	roles := []model.Role{
		{ID: 7, Label: "nginx:1.25"},
		{ID: 3, Label: "ssh"},
	}
	checkGolden(t, "roles_table", render(t, FormatTable, Options{},
		func(r Renderer, b *bytes.Buffer) error { return r.Roles(b, roles) }))
	checkGolden(t, "roles_table_no_headers", render(t, FormatTable, Options{NoHeaders: true},
		func(r Renderer, b *bytes.Buffer) error { return r.Roles(b, roles) }))
	checkGolden(t, "roles_table_empty", render(t, FormatTable, Options{},
		func(r Renderer, b *bytes.Buffer) error { return r.Roles(b, nil) }))
	checkGolden(t, "roles_json", render(t, FormatJSON, Options{},
		func(r Renderer, b *bytes.Buffer) error { return r.Roles(b, roles) }))
	checkGolden(t, "roles_json_empty", render(t, FormatJSON, Options{},
		func(r Renderer, b *bytes.Buffer) error { return r.Roles(b, nil) }))
}

func TestGoldenRoleStats(t *testing.T) {
	stats := model.RoleStats{
		Rejected:           uint64Ptr(0),
		UnknownInstance:    nil,
		OwnerConflict:      uint64Ptr(2),
		AnchorsRemoved:     uint64Ptr(0),
		CgroupReadEmpty:    nil,
		QueueRejected:      uint64Ptr(5),
		BindDeferred:       uint64Ptr(3),
		BindResolved:       uint64Ptr(3),
		BindRejected:       nil,
		BindExpired:        nil,
		BindIgnored:        uint64Ptr(0),
		LateAdoptRejected:  uint64Ptr(1),
		TombstoneDepth:     uint64Ptr(4),
		DeadMemberRejected: nil,
		DeadAnchorRejected: uint64Ptr(0),
	}
	checkGolden(t, "role_stats_table", render(t, FormatTable, Options{},
		func(r Renderer, b *bytes.Buffer) error { return r.RoleStats(b, stats) }))
	checkGolden(t, "role_stats_table_no_headers", render(t, FormatTable, Options{NoHeaders: true},
		func(r Renderer, b *bytes.Buffer) error { return r.RoleStats(b, stats) }))
	checkGolden(t, "role_stats_json", render(t, FormatJSON, Options{},
		func(r Renderer, b *bytes.Buffer) error { return r.RoleStats(b, stats) }))
}

func TestGoldenContextStats(t *testing.T) {
	stats := model.ContextStats{
		CtxrootParentUnsettled: uint64Ptr(1),
		UnknownUnregister:      uint64Ptr(2),
		PendingDeferred:        uint64Ptr(3),
		PendingResolved:        uint64Ptr(2),
		PendingRejected:        uint64Ptr(0),
		PendingExpired:         uint64Ptr(1),
		PendingCancelled:       uint64Ptr(0),
		PendingDepth:           uint64Ptr(1),
		BindOrphaned:           uint64Ptr(0),
		ExtraOrphaned:          uint64Ptr(0),
		ParentMissing:          uint64Ptr(2),
		LateRegister:           uint64Ptr(1),
		LateBind:               uint64Ptr(0),
		DuplicateContext:       uint64Ptr(1),
		OwnershipConflict:      uint64Ptr(0),
		TombstoneHits:          uint64Ptr(9),
		TombstoneDepth:         uint64Ptr(1),
	}
	checkGolden(t, "context_stats_table", render(t, FormatTable, Options{},
		func(r Renderer, b *bytes.Buffer) error { return r.ContextStats(b, stats) }))
	checkGolden(t, "context_stats_json", render(t, FormatJSON, Options{},
		func(r Renderer, b *bytes.Buffer) error { return r.ContextStats(b, stats) }))
}

func TestGoldenProcessStats(t *testing.T) {
	stats := model.ProcessStats{
		PidReused:      uint64Ptr(0),
		StaleAdd:       nil,
		ParentMissing:  uint64Ptr(2),
		TombstoneDepth: uint64Ptr(4),
	}
	checkGolden(t, "process_stats_table", render(t, FormatTable, Options{},
		func(r Renderer, b *bytes.Buffer) error { return r.ProcessStats(b, stats) }))
	checkGolden(t, "process_stats_json", render(t, FormatJSON, Options{},
		func(r Renderer, b *bytes.Buffer) error { return r.ProcessStats(b, stats) }))
}

func TestGoldenWhich(t *testing.T) {
	checkGolden(t, "which_role_table_found", render(t, FormatTable, Options{},
		func(r Renderer, b *bytes.Buffer) error { return r.WhichRole(b, 7, true) }))
	checkGolden(t, "which_role_table_not_found", render(t, FormatTable, Options{},
		func(r Renderer, b *bytes.Buffer) error { return r.WhichRole(b, 0, false) }))
	checkGolden(t, "which_role_json_found", render(t, FormatJSON, Options{},
		func(r Renderer, b *bytes.Buffer) error { return r.WhichRole(b, 7, true) }))
	checkGolden(t, "which_role_json_not_found", render(t, FormatJSON, Options{},
		func(r Renderer, b *bytes.Buffer) error { return r.WhichRole(b, 0, false) }))
	checkGolden(t, "which_context_json_not_found", render(t, FormatJSON, Options{},
		func(r Renderer, b *bytes.Buffer) error { return r.WhichContext(b, 0, false) }))
}

func TestGoldenRoleDetail(t *testing.T) {
	label := "nginx:1.25"
	ids := []uint32{3, 4}
	processes := model.ProcessSet{RootPID: 1234, PIDs: []uint32{1234, 1235}}
	full := model.RoleDetail{
		RoleID:     7,
		Label:      &label,
		Processes:  &processes,
		ContextIDs: &ids,
	}

	checkGolden(t, "role_detail_table", render(t, FormatTable, Options{},
		func(r Renderer, b *bytes.Buffer) error { return r.RoleDetail(b, full) }))
	checkGolden(t, "role_detail_table_minimal", render(t, FormatTable, Options{},
		func(r Renderer, b *bytes.Buffer) error {
			return r.RoleDetail(b, model.RoleDetail{RoleID: 7})
		}))

	rootless := model.ProcessSet{PIDs: []uint32{1234}}
	noContexts := []uint32{}
	checkGolden(t, "role_detail_table_rootless", render(t, FormatTable, Options{},
		func(r Renderer, b *bytes.Buffer) error {
			return r.RoleDetail(b, model.RoleDetail{
				RoleID:     7,
				Label:      &label,
				Processes:  &rootless,
				ContextIDs: &noContexts,
			})
		}))

	checkGolden(t, "role_detail_json", render(t, FormatJSON, Options{},
		func(r Renderer, b *bytes.Buffer) error { return r.RoleDetail(b, full) }))
	checkGolden(t, "role_detail_json_minimal", render(t, FormatJSON, Options{},
		func(r Renderer, b *bytes.Buffer) error {
			return r.RoleDetail(b, model.RoleDetail{RoleID: 7})
		}))

	emptyLabel := ""
	emptyProcesses := model.ProcessSet{PIDs: []uint32{}}
	emptyIDs := []uint32{}
	checkGolden(t, "role_detail_json_empty", render(t, FormatJSON, Options{},
		func(r Renderer, b *bytes.Buffer) error {
			return r.RoleDetail(b, model.RoleDetail{
				RoleID:     7,
				Label:      &emptyLabel,
				Processes:  &emptyProcesses,
				ContextIDs: &emptyIDs,
			})
		}))
}

func TestGoldenContextDetail(t *testing.T) {
	processes := model.ProcessSet{RootPID: 1234, PIDs: []uint32{1234, 1235}}
	checkGolden(t, "context_detail_table", render(t, FormatTable, Options{},
		func(r Renderer, b *bytes.Buffer) error { return r.ContextDetail(b, 3, processes) }))
	checkGolden(t, "context_detail_table_rootless", render(t, FormatTable, Options{},
		func(r Renderer, b *bytes.Buffer) error {
			return r.ContextDetail(b, 3, model.ProcessSet{PIDs: []uint32{}})
		}))
	checkGolden(t, "context_detail_json", render(t, FormatJSON, Options{},
		func(r Renderer, b *bytes.Buffer) error { return r.ContextDetail(b, 3, processes) }))
}

func TestGoldenStatus(t *testing.T) {
	supervised, exception, extra := 12, 3, 0
	full := model.Status{
		SupervisedRoleCount:   &supervised,
		ExceptionContextCount: &exception,
		ExtraContextCount:     &extra,
		RoleStats: &model.RoleStats{
			Rejected:           uint64Ptr(0),
			UnknownInstance:    nil,
			OwnerConflict:      uint64Ptr(2),
			AnchorsRemoved:     uint64Ptr(0),
			CgroupReadEmpty:    nil,
			QueueRejected:      uint64Ptr(5),
			BindDeferred:       uint64Ptr(3),
			BindResolved:       uint64Ptr(3),
			BindRejected:       nil,
			BindExpired:        nil,
			BindIgnored:        uint64Ptr(0),
			LateAdoptRejected:  uint64Ptr(1),
			TombstoneDepth:     uint64Ptr(4),
			DeadMemberRejected: nil,
			DeadAnchorRejected: uint64Ptr(0),
		},
		ContextStats: &model.ContextStats{
			CtxrootParentUnsettled: uint64Ptr(1),
			UnknownUnregister:      uint64Ptr(2),
			PendingDeferred:        uint64Ptr(3),
			PendingResolved:        uint64Ptr(2),
			PendingRejected:        uint64Ptr(0),
			PendingExpired:         uint64Ptr(1),
			PendingCancelled:       uint64Ptr(0),
			PendingDepth:           uint64Ptr(1),
			BindOrphaned:           uint64Ptr(0),
			ExtraOrphaned:          uint64Ptr(0),
			ParentMissing:          uint64Ptr(2),
			LateRegister:           uint64Ptr(1),
			LateBind:               uint64Ptr(0),
			DuplicateContext:       uint64Ptr(1),
			OwnershipConflict:      uint64Ptr(0),
			TombstoneHits:          uint64Ptr(9),
			TombstoneDepth:         uint64Ptr(1),
		},
		ProcessStats: &model.ProcessStats{
			PidReused:      uint64Ptr(0),
			StaleAdd:       nil,
			ParentMissing:  uint64Ptr(2),
			TombstoneDepth: uint64Ptr(4),
		},
	}
	checkGolden(t, "status_table", render(t, FormatTable, Options{},
		func(r Renderer, b *bytes.Buffer) error { return r.Status(b, full) }))
	checkGolden(t, "status_json", render(t, FormatJSON, Options{},
		func(r Renderer, b *bytes.Buffer) error { return r.Status(b, full) }))

	partial := model.Status{
		RoleStats: &model.RoleStats{Rejected: uint64Ptr(1)},
	}
	checkGolden(t, "status_table_partial", render(t, FormatTable, Options{},
		func(r Renderer, b *bytes.Buffer) error { return r.Status(b, partial) }))
	checkGolden(t, "status_json_partial", render(t, FormatJSON, Options{},
		func(r Renderer, b *bytes.Buffer) error { return r.Status(b, partial) }))
	checkGolden(t, "status_json_empty", render(t, FormatJSON, Options{},
		func(r Renderer, b *bytes.Buffer) error { return r.Status(b, model.Status{}) }))
	checkGolden(t, "status_table_empty", render(t, FormatTable, Options{},
		func(r Renderer, b *bytes.Buffer) error { return r.Status(b, model.Status{}) }))
}

func renderStream(t *testing.T, format Format, opts Options,
	events []model.Event, stats []model.StreamStats) string {
	t.Helper()
	var buf bytes.Buffer
	r := New(format, opts)
	for _, ev := range events {
		if err := r.Event(&buf, ev); err != nil {
			t.Fatalf("Event: %v", err)
		}
	}
	for _, s := range stats {
		if err := r.StreamStats(&buf, s); err != nil {
			t.Fatalf("StreamStats: %v", err)
		}
	}
	return buf.String()
}

func testEvents() []model.Event {
	return []model.Event{
		{
			Head: model.Head{
				RoleLabel: "nginx:1.25",
				RoleID:    7,
				ContextID: 3,
				PID:       1234,
				PPID:      1,
				Type:      model.EventTypeSyscall,
			},
			Payload: model.Payload{Kind: model.PayloadExec, Fields: map[string]any{
				"semantic_filename": "/usr/sbin/nginx",
				"argv0":             "nginx",
				"argv1":             "",
				"flags":             uint32(0),
				"syscall_name":      "execve",
			}},
		},
		{
			Head: model.Head{
				RoleID: 7,
				PID:    2002,
				PPID:   1,
				Type:   model.EventTypeFile,
			},
			Payload: model.Payload{Kind: model.PayloadFile, Fields: map[string]any{
				"semantic_filename": "/etc/nginx/nginx.conf",
				"flags":             uint32(0),
				"is_innamespace":    false,
				"comm":              "nginx",
			}},
		},
	}
}

func TestGoldenEventsTable(t *testing.T) {
	stats := []model.StreamStats{{DroppedEvents: 12}}
	checkGolden(t, "events_table", renderStream(t, FormatTable, Options{}, testEvents(), stats))
	checkGolden(t, "events_table_no_headers",
		renderStream(t, FormatTable, Options{NoHeaders: true}, testEvents(), stats))
}

func TestGoldenEventsJSON(t *testing.T) {
	stats := []model.StreamStats{{DroppedEvents: 12}}
	checkGolden(t, "events_json", renderStream(t, FormatJSON, Options{}, testEvents(), stats))
}

func TestEventDetail(t *testing.T) {
	tests := []struct {
		name    string
		payload model.Payload
		want    string
	}{
		{
			name: "process",
			payload: model.Payload{Kind: model.PayloadProcess, Fields: map[string]any{
				"exit_code": int32(-9), "syscall_name": "exit_group",
			}},
			want: "exit_group exit=-9",
		},
		{
			name: "exec",
			payload: model.Payload{Kind: model.PayloadExec, Fields: map[string]any{
				"syscall_name": "execve", "semantic_filename": "/usr/sbin/nginx",
			}},
			want: "execve /usr/sbin/nginx",
		},
		{
			name: "setuid",
			payload: model.Payload{Kind: model.PayloadCredential, Fields: map[string]any{
				"syscall_name": "setuid", "setuid_uid": uint32(1000),
			}},
			want: "setuid uid=1000",
		},
		{
			name: "setgid",
			payload: model.Payload{Kind: model.PayloadCredential, Fields: map[string]any{
				"syscall_name": "setgid", "setgid_gid": uint32(1000),
			}},
			want: "setgid gid=1000",
		},
		{
			name: "capset",
			payload: model.Payload{Kind: model.PayloadCredential, Fields: map[string]any{
				"syscall_name": "capset",
				"capset": map[string]any{
					"effective": uint64(1), "permitted": uint64(2), "inheritable": uint64(3),
				},
			}},
			want: "capset eff=1 perm=2 inh=3",
		},
		{
			name: "namespace",
			payload: model.Payload{Kind: model.PayloadNamespace, Fields: map[string]any{
				"syscall_name": "unshare", "ns_type": uint32(1), "flags": uint64(2),
			}},
			want: "unshare ns_type=1 flags=0x2",
		},
		{
			name: "file_syscall",
			payload: model.Payload{Kind: model.PayloadFileSyscall, Fields: map[string]any{
				"syscall_name": "openat", "flags": uint32(3), "mode": uint32(420),
			}},
			want: "openat flags=0x3 mode=0644",
		},
		{
			name: "memory",
			payload: model.Payload{Kind: model.PayloadMemory, Fields: map[string]any{
				"syscall_name": "mmap", "prot": uint64(4), "flags": uint64(5),
			}},
			want: "mmap prot=0x4 flags=0x5",
		},
		{
			name: "network",
			payload: model.Payload{Kind: model.PayloadNetworkSyscall, Fields: map[string]any{
				"syscall_name": "socket", "family": uint32(2), "type": uint32(1),
				"protocol": uint32(6),
			}},
			want: "socket family=2 type=1 protocol=6",
		},
		{
			name: "kernel",
			payload: model.Payload{Kind: model.PayloadKernel, Fields: map[string]any{
				"syscall_name": "ptrace", "command": uint32(7), "arg": uint64(8),
			}},
			want: "ptrace command=7 arg=8",
		},
		{
			name: "file",
			payload: model.Payload{Kind: model.PayloadFile, Fields: map[string]any{
				"semantic_filename": "/etc/nginx/nginx.conf",
			}},
			want: "/etc/nginx/nginx.conf",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := eventDetail(tt.payload); got != tt.want {
				t.Errorf("eventDetail = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGoldenContextList(t *testing.T) {
	refs := []model.ContextRef{
		{Kind: model.ContextKindException, ID: 3},
		{Kind: model.ContextKindExtra, ID: 4},
	}
	checkGolden(t, "context_list_table", render(t, FormatTable, Options{},
		func(r Renderer, b *bytes.Buffer) error { return r.ContextList(b, refs) }))
	checkGolden(t, "context_list_table_no_headers", render(t, FormatTable, Options{NoHeaders: true},
		func(r Renderer, b *bytes.Buffer) error { return r.ContextList(b, refs) }))
	checkGolden(t, "context_list_json", render(t, FormatJSON, Options{},
		func(r Renderer, b *bytes.Buffer) error { return r.ContextList(b, refs) }))
	checkGolden(t, "context_list_json_empty", render(t, FormatJSON, Options{},
		func(r Renderer, b *bytes.Buffer) error { return r.ContextList(b, nil) }))
}
