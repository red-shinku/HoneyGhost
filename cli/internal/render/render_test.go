package render

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
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
				Subtype:   model.SubtypeExec,
				UID:       0,
				EUID:      1000,
				Ret:       0,
				Comm:      "nginx",
				MntNS:     initMntNSInum,
				Exe:       "/tmp/test",
			},
			Payload: model.Payload{Kind: model.SubtypeExec, Fields: map[string]any{
				"semantic_filename": "/tmp/test",
				"argv0":             "test",
				"argv1":             "",
				"argv2":             "",
				"argv3":             "",
				"ld_preload":        "/tmp/inject.so",
				"ld_library_path":   "",
				"flags":             uint32(0),
				"invoked":           "./test",
				"image":             "/tmp/test",
				"syscall_name":      "execve",
			}},
		},
		{
			Head: model.Head{
				RoleID:  7,
				PID:     2004,
				PPID:    1,
				Type:    model.EventTypeSyscall,
				Subtype: model.SubtypeNamespace,
				UID:     1000,
				EUID:    1000,
				Ret:     0,
				Comm:    "bash",
				MntNS:   4026532222,
			},
			// 一次 unshare 新建 MNT 与 USER 两个命名空间：掩码按固定顺序展开
			Payload: model.Payload{Kind: model.SubtypeNamespace, Fields: map[string]any{
				"flags":        uint64(0x10020000),
				"ns_mask":      uint32(0x10020000),
				"fd":           int32(-1),
				"syscall_name": "unshare",
			}},
		},
		{
			Head: model.Head{
				RoleID:  7,
				PID:     2002,
				PPID:    1,
				Type:    model.EventTypeSyscall,
				Subtype: model.SubtypeFile,
				UID:     1000,
				EUID:    0,
				Ret:     0,
				Comm:    "nginx",
				MntNS:   4026532222,
				Exe:     "/usr/sbin/nginx",
			},
			Payload: model.Payload{Kind: model.SubtypeFile, Fields: map[string]any{
				"path1":        "/etc/nginx/nginx.conf",
				"path2":        "",
				"path1_flags":  uint32(0),
				"path2_flags":  uint32(0),
				"dirfd":        int32(-100),
				"dirfd2":       int32(-100),
				"flags":        uint32(0),
				"mode":         uint32(0),
				"syscall_name": "openat",
			}},
		},
		{
			Head: model.Head{
				RoleID:  7,
				PID:     2003,
				PPID:    1,
				Type:    model.EventTypeSyscall,
				Subtype: model.SubtypeFile,
				UID:     1000,
				EUID:    1000,
				Ret:     -2,
				Comm:    "bash",
				MntNS:   initMntNSInum,
			},
			// 内核未能解析为绝对路径：path1 是原始串，渲染时加 ? 前缀
			Payload: model.Payload{Kind: model.SubtypeFile, Fields: map[string]any{
				"path1":        "deploy.sh",
				"path2":        "",
				"path1_flags":  uint32(2),
				"path2_flags":  uint32(0),
				"dirfd":        int32(-100),
				"dirfd2":       int32(-100),
				"flags":        uint32(0),
				"mode":         uint32(0),
				"syscall_name": "openat",
			}},
		},
		{
			Head: model.Head{
				RoleID:  7,
				PID:     2005,
				PPID:    1,
				Type:    model.EventTypeSyscall,
				Subtype: model.SubtypeFile,
				UID:     1000,
				EUID:    1000,
				Ret:     0,
				Comm:    "mv",
				MntNS:   initMntNSInum,
			},
			// rename 的第二路径：path2 非空时按 path2= 追加，两个 dirfd 各自呈现
			Payload: model.Payload{Kind: model.SubtypeFile, Fields: map[string]any{
				"path1":        "/tmp/a",
				"path2":        "/tmp/b",
				"path1_flags":  uint32(0),
				"path2_flags":  uint32(0),
				"dirfd":        int32(3),
				"dirfd2":       int32(4),
				"flags":        uint32(1),
				"mode":         uint32(0),
				"syscall_name": "renameat2",
			}},
		},
		{
			Head: model.Head{
				RoleID:  7,
				PID:     2006,
				PPID:    1,
				Type:    model.EventTypeSyscall,
				Subtype: model.SubtypeMemory,
				UID:     1000,
				EUID:    1000,
				Ret:     0x7f0000000000,
				Comm:    "nginx",
				MntNS:   initMntNSInum,
				Exe:     "/usr/sbin/nginx",
			},
			// 文件映射：源路径与区段起点一并呈现，W|X 追加 wx
			Payload: model.Payload{Kind: model.SubtypeMemory, Fields: map[string]any{
				"prot": uint64(5), "flags": uint64(1), "addr": uint64(0),
				"length": uint64(8192), "offset": uint64(4096), "fd": int32(3),
				"anonymous": false, "wx": true, "path": "/usr/lib/libc.so.6",
				"path_flags": uint32(0), "syscall_name": "mmap",
			}},
		},
		{
			Head: model.Head{
				RoleID:  7,
				PID:     2007,
				PPID:    1,
				Type:    model.EventTypeSyscall,
				Subtype: model.SubtypeNetwork,
				UID:     1000,
				EUID:    1000,
				Ret:     0,
				Comm:    "dbus-daemon",
				MntNS:   4026532222,
			},
			// AF_UNIX：目标按 sun_path 呈现，抽象命名空间以 @ 开头
			Payload: model.Payload{Kind: model.SubtypeNetwork, Fields: map[string]any{
				"family": uint32(1), "type": uint32(1), "protocol": uint32(0),
				"dst_ip": []uint32{0, 0, 0, 0}, "dst_port": uint32(0),
				"src_port": uint32(0), "sockfd": int32(5), "count": uint64(0),
				"unix_path": "@/run/dbus", "syscall_name": "connect",
			}},
		},
		{
			Head: model.Head{
				RoleID:  7,
				PID:     2008,
				PPID:    1,
				Type:    model.EventTypeSyscall,
				Subtype: model.SubtypeSignal,
				UID:     1000,
				EUID:    1000,
				Ret:     0,
				Comm:    "kill",
				MntNS:   initMntNSInum,
			},
			// tgkill：目标线程组与 tid 分别呈现
			Payload: model.Payload{Kind: model.SubtypeSignal, Fields: map[string]any{
				"sig": uint32(9), "target_pid": uint32(1),
				"target_tid": uint32(2), "si_code": int32(0),
				"syscall_name": "tgkill",
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
			payload: model.Payload{Kind: model.SubtypeProcess, Fields: map[string]any{
				"exit_code": int32(-9), "syscall_name": "exit_group",
			}},
			want: "exit_group exit=-9",
		},
		{
			name: "process_fork",
			payload: model.Payload{Kind: model.SubtypeProcess, Fields: map[string]any{
				"exit_code": int32(0), "derived_flags": uint32(3),
				"syscall_name": "fork",
			}},
			// 非退出事件的 exit_code 恒为 0，不呈现
			want: "fork flags=SHARED_MM,PARENT",
		},
		{
			name: "process_rename",
			payload: model.Payload{Kind: model.SubtypeProcess, Fields: map[string]any{
				"exit_code": int32(0), "derived_flags": uint32(0),
				"exit_signal": int32(0), "old_comm": "bash",
				"new_comm": "nginx", "cgroup_path": "/system.slice/nginx.service",
				"syscall_name": "task_rename",
			}},
			want: "task_rename old=bash new=nginx cgroup=/system.slice/nginx.service",
		},
		{
			name: "process_rename_with_target",
			payload: model.Payload{Kind: model.SubtypeProcess, Fields: map[string]any{
				"exit_code": int32(0), "old_comm": "bash", "new_comm": "nginx",
				"target_pid": uint32(4242), "syscall_name": "task_rename",
			}},
			want: "task_rename target=4242 old=bash new=nginx",
		},
		{
			name: "process_exit_signal",
			payload: model.Payload{Kind: model.SubtypeProcess, Fields: map[string]any{
				"exit_code": int32(-9), "exit_signal": int32(9),
				"syscall_name": "exit_group",
			}},
			want: "exit_group exit=-9 signal=9",
		},
		{
			name: "exec",
			payload: model.Payload{Kind: model.SubtypeExec, Fields: map[string]any{
				"syscall_name": "execve", "semantic_filename": "/usr/sbin/nginx",
			}},
			want: "execve /usr/sbin/nginx",
		},
		{
			name: "exec_image",
			payload: model.Payload{Kind: model.SubtypeExec, Fields: map[string]any{
				"syscall_name": "execve", "image": "/tmp/test",
				"invoked": "./test",
			}},
			want: "execve image=/tmp/test invoked=./test",
		},
		{
			name: "exec_image_same_invoked",
			payload: model.Payload{Kind: model.SubtypeExec, Fields: map[string]any{
				"syscall_name": "execve", "image": "/bin/sh",
				"invoked": "/bin/sh",
			}},
			want: "execve image=/bin/sh",
		},
		{
			name: "exec_preload",
			payload: model.Payload{Kind: model.SubtypeExec, Fields: map[string]any{
				"syscall_name": "execve", "image": "/bin/sh",
				"invoked": "/bin/sh", "ld_preload": "/tmp/inject.so",
			}},
			want: "execve image=/bin/sh preload=/tmp/inject.so",
		},
		{
			name: "setuid",
			payload: model.Payload{Kind: model.SubtypeCredential, Fields: map[string]any{
				"syscall_name": "setuid", "kind": uint32(1),
				"requested": []uint32{1000},
			}},
			want: "setuid uid=1000",
		},
		{
			name: "setgid",
			payload: model.Payload{Kind: model.SubtypeCredential, Fields: map[string]any{
				"syscall_name": "setgid", "kind": uint32(2),
				"requested": []uint32{2000},
			}},
			want: "setgid gid=2000",
		},
		{
			name: "setuid_multi",
			payload: model.Payload{Kind: model.SubtypeCredential, Fields: map[string]any{
				"syscall_name": "setuid", "kind": uint32(1),
				"requested": []uint32{1000, 1001, 1002},
			}},
			want: "setuid uids=1000,1001,1002",
		},
		{
			name: "setgid_multi",
			payload: model.Payload{Kind: model.SubtypeCredential, Fields: map[string]any{
				"syscall_name": "setgid", "kind": uint32(2),
				"requested": []uint32{2000, 2001},
			}},
			want: "setgid gids=2000,2001",
		},
		{
			name: "credential_no_requested",
			payload: model.Payload{Kind: model.SubtypeCredential, Fields: map[string]any{
				"syscall_name": "setuid", "kind": uint32(1),
				"requested": []uint32{},
			}},
			want: "setuid",
		},
		{
			name: "capset",
			payload: model.Payload{Kind: model.SubtypeCredential, Fields: map[string]any{
				"syscall_name": "capset", "kind": uint32(3),
				"requested": []uint32{},
				"capset": map[string]any{
					"effective": uint64(0x1), "permitted": uint64(0x2),
					"inheritable": uint64(0x4),
				},
			}},
			want: "capset capset eff=0x1 perm=0x2 inh=0x4",
		},
		{
			name: "namespace_unshare",
			payload: model.Payload{Kind: model.SubtypeNamespace, Fields: map[string]any{
				"syscall_name": "unshare", "flags": uint64(0x10020000),
				"ns_mask": uint32(0x10020000), "fd": int32(-1),
			}},
			want: "unshare ns=MNT,USER flags=0x10020000",
		},
		{
			name: "namespace_setns",
			payload: model.Payload{Kind: model.SubtypeNamespace, Fields: map[string]any{
				"syscall_name": "setns", "flags": uint64(0),
				"ns_mask": uint32(0x40000000), "fd": int32(5),
			}},
			want: "setns ns=NET fd=5",
		},
		{
			name: "namespace_no_mask",
			payload: model.Payload{Kind: model.SubtypeNamespace, Fields: map[string]any{
				"syscall_name": "unshare", "flags": uint64(0x2),
				"ns_mask": uint32(0), "fd": int32(-1),
			}},
			want: "unshare flags=0x2",
		},
		{
			name: "prctl",
			payload: model.Payload{Kind: model.SubtypeCredential, Fields: map[string]any{
				"syscall_name": "prctl", "kind": uint32(4),
				"requested": []uint32{}, "prctl_option": uint32(28),
				"arg2": uint64(63), "securebits": uint32(63),
			}},
			want: "prctl option=28 arg=63",
		},
		{
			name: "namespace_mount",
			payload: model.Payload{Kind: model.SubtypeNamespace, Fields: map[string]any{
				"syscall_name": "mount", "source": "/dev/sda1",
				"target": "/mnt", "source_flags": uint32(0),
				"target_flags": uint32(0), "fstype": "ext4",
				"mount_flags": uint64(1),
			}},
			want: "mount [/dev/sda1 -> /mnt type ext4]",
		},
		{
			name: "namespace_mount_unresolved",
			payload: model.Payload{Kind: model.SubtypeNamespace, Fields: map[string]any{
				"syscall_name": "mount", "source": "dev/sda1",
				"target": "/mnt", "source_flags": uint32(2),
				"target_flags": uint32(0), "fstype": "ext4",
			}},
			want: "mount [?dev/sda1 -> /mnt type ext4]",
		},
		{
			name: "namespace_umount",
			payload: model.Payload{Kind: model.SubtypeNamespace, Fields: map[string]any{
				"syscall_name": "umount2", "target": "/mnt",
				"target_flags": uint32(0), "mount_flags": uint64(2),
			}},
			want: "umount /mnt",
		},
		{
			name: "namespace_pivot_root",
			payload: model.Payload{Kind: model.SubtypeNamespace, Fields: map[string]any{
				"syscall_name": "pivot_root", "source": "/a",
				"target": "/b", "source_flags": uint32(0),
				"target_flags": uint32(0),
			}},
			want: "pivot_root /a => /b",
		},
		{
			name: "namespace_chroot_unresolved",
			payload: model.Payload{Kind: model.SubtypeNamespace, Fields: map[string]any{
				"syscall_name": "chroot", "target": "/newroot",
				"target_flags": uint32(2),
			}},
			want: "chroot ?/newroot",
		},
		{
			name: "file_syscall",
			payload: model.Payload{Kind: model.SubtypeFile, Fields: map[string]any{
				"syscall_name": "openat", "flags": uint32(3), "mode": uint32(420),
				"path1": "/tmp/x", "path2": "",
			}},
			want: "openat path=/tmp/x flags=0x3 mode=0644",
		},
		{
			name: "file_syscall_no_path",
			payload: model.Payload{Kind: model.SubtypeFile, Fields: map[string]any{
				"syscall_name": "unlink", "flags": uint32(0), "mode": uint32(0),
				"path1": "", "path2": "",
			}},
			want: "unlink flags=0x0 mode=00",
		},
		{
			name: "file_syscall_unresolved",
			payload: model.Payload{Kind: model.SubtypeFile, Fields: map[string]any{
				"syscall_name": "openat", "flags": uint32(3), "mode": uint32(420),
				"path1": "deploy.sh", "path1_flags": uint32(2), "path2": "",
			}},
			want: "openat path=?deploy.sh flags=0x3 mode=0644",
		},
		{
			name: "file_syscall_truncated_only",
			payload: model.Payload{Kind: model.SubtypeFile, Fields: map[string]any{
				"syscall_name": "openat", "flags": uint32(3), "mode": uint32(420),
				"path1": "/tmp/x", "path1_flags": uint32(1), "path2": "",
			}},
			want: "openat path=/tmp/x flags=0x3 mode=0644",
		},
		{
			name: "file_syscall_second_path",
			payload: model.Payload{Kind: model.SubtypeFile, Fields: map[string]any{
				"syscall_name": "rename", "flags": uint32(0), "mode": uint32(0),
				"path1": "/tmp/a", "path2": "/tmp/b",
			}},
			want: "rename path=/tmp/a path2=/tmp/b flags=0x0 mode=00",
		},
		{
			name: "file_syscall_second_path_unresolved",
			payload: model.Payload{Kind: model.SubtypeFile, Fields: map[string]any{
				"syscall_name": "link", "flags": uint32(0), "mode": uint32(0),
				"path1": "/tmp/a", "path1_flags": uint32(0),
				"path2": "rel/new", "path2_flags": uint32(2),
			}},
			want: "link path=/tmp/a path2=?rel/new flags=0x0 mode=00",
		},
		{
			name: "file_truncate",
			payload: model.Payload{Kind: model.SubtypeFile, Fields: map[string]any{
				"syscall_name": "truncate", "flags": uint32(0),
				"mode": uint32(0), "path1": "/tmp/f", "path2": "",
				"length": int64(4096),
			}},
			want: "truncate path=/tmp/f flags=0x0 mode=00 length=4096",
		},
		{
			name: "file_mknod_at_flags",
			payload: model.Payload{Kind: model.SubtypeFile, Fields: map[string]any{
				"syscall_name": "fchmodat", "flags": uint32(0),
				"mode": uint32(420), "path1": "/tmp/f", "path2": "",
				"at_flags": uint32(0x100), "dev": uint32(0x1234),
			}},
			want: "fchmodat path=/tmp/f flags=0x0 mode=0644 at_flags=0x100 dev=4660",
		},
		{
			name: "file_handle_fd",
			payload: model.Payload{Kind: model.SubtypeFile, Fields: map[string]any{
				"syscall_name": "open_by_handle_at", "flags": uint32(0),
				"mode": uint32(0), "path1": "", "path2": "",
				"handle": []byte{0xde, 0xad, 0xbe, 0xef}, "fd": int32(3),
			}},
			want: "open_by_handle_at flags=0x0 mode=00 handle=deadbeef fd=3",
		},
		{
			name: "file_memfd_keeps_prefix",
			payload: model.Payload{Kind: model.SubtypeFile, Fields: map[string]any{
				"syscall_name": "memfd_create", "flags": uint32(3),
				"mode": uint32(0), "path1": "memfd:payload", "path2": "",
				"path1_flags": uint32(0),
			}},
			want: "memfd_create path=memfd:payload flags=0x3 mode=00",
		},
		{
			name: "memory_anon",
			payload: model.Payload{Kind: model.SubtypeMemory, Fields: map[string]any{
				"syscall_name": "mmap", "prot": uint64(3), "flags": uint64(0x22),
				"addr": uint64(0), "length": uint64(4096), "offset": uint64(0),
				"fd": int32(-1), "anonymous": true, "wx": false,
				"path": "", "path_flags": uint32(0),
			}},
			want: "mmap addr=0x0 len=4096 prot=0x3 flags=0x22 anon",
		},
		{
			name: "memory_file",
			payload: model.Payload{Kind: model.SubtypeMemory, Fields: map[string]any{
				"syscall_name": "mmap", "prot": uint64(5), "flags": uint64(1),
				"addr": uint64(0), "length": uint64(8192), "offset": uint64(4096),
				"fd": int32(3), "anonymous": false, "wx": true,
				"path": "/usr/lib/libc.so.6", "path_flags": uint32(0),
			}},
			want: "mmap addr=0x0 len=8192 prot=0x5 flags=0x1 path=/usr/lib/libc.so.6 offset=4096 wx",
		},
		{
			name: "memory_mprotect",
			payload: model.Payload{Kind: model.SubtypeMemory, Fields: map[string]any{
				"syscall_name": "mprotect", "prot": uint64(7), "flags": uint64(0),
				"addr": uint64(0x401000), "length": uint64(2048), "offset": uint64(0),
				"fd": int32(-1), "anonymous": false, "wx": true,
				"path": "", "path_flags": uint32(0),
			}},
			want: "mprotect addr=0x401000 len=2048 prot=0x7 flags=0x0 wx",
		},
		{
			name: "network",
			payload: model.Payload{Kind: model.SubtypeNetwork, Fields: map[string]any{
				"syscall_name": "connect", "family": uint32(2), "type": uint32(1),
				"protocol": uint32(6), "dst_ip": []uint32{0x0a01a8c0, 0, 0, 0},
				"dst_port": uint32(443), "src_port": uint32(50000),
			}},
			want: "connect family=2 type=1 protocol=6 dst=192.168.1.10:443 src_port=50000",
		},
		{
			name: "network_no_dst",
			payload: model.Payload{Kind: model.SubtypeNetwork, Fields: map[string]any{
				"syscall_name": "socket", "family": uint32(2), "type": uint32(1),
				"protocol": uint32(6), "dst_ip": []uint32{0, 0, 0, 0},
				"dst_port": uint32(0), "src_port": uint32(0),
			}},
			want: "socket family=2 type=1 protocol=6",
		},
		{
			name: "network_ipv6",
			payload: model.Payload{Kind: model.SubtypeNetwork, Fields: map[string]any{
				"syscall_name": "sendto", "family": uint32(10), "type": uint32(2),
				"protocol": uint32(17),
				"dst_ip":   []uint32{0xb80d0120, 0, 0, 0x01000000},
				"dst_port": uint32(53), "src_port": uint32(40000),
			}},
			want: "sendto family=10 type=2 protocol=17 dst=[2001:db8:0:0:0:0:0:1]:53 src_port=40000",
		},
		{
			name: "network_unix",
			payload: model.Payload{Kind: model.SubtypeNetwork, Fields: map[string]any{
				"syscall_name": "connect", "family": uint32(1), "type": uint32(1),
				"protocol": uint32(0), "dst_ip": []uint32{0, 0, 0, 0},
				"dst_port": uint32(0), "src_port": uint32(0),
				"sockfd": int32(5), "count": uint64(0), "unix_path": "@/run/dbus",
			}},
			want: "connect family=1 type=1 protocol=0 dst=@/run/dbus",
		},
		{
			name: "network_sockfd_count",
			payload: model.Payload{Kind: model.SubtypeNetwork, Fields: map[string]any{
				"syscall_name": "sendto", "family": uint32(2), "type": uint32(2),
				"protocol": uint32(17), "dst_ip": []uint32{0x0a01a8c0, 0, 0, 0},
				"dst_port": uint32(53), "src_port": uint32(40000),
				"sockfd": int32(4), "count": uint64(512), "unix_path": "",
			}},
			want: "sendto family=2 type=2 protocol=17 dst=192.168.1.10:53 src_port=40000 sockfd=4 count=512",
		},
		{
			name: "kernel_module_load",
			payload: model.Payload{Kind: model.SubtypeKernel, Fields: map[string]any{
				"syscall_name": "module_load", "module_name": "nfs",
			}},
			want: "module_load module=nfs",
		},
		{
			name: "kernel_init_module",
			payload: model.Payload{Kind: model.SubtypeKernel, Fields: map[string]any{
				"syscall_name": "init_module", "module_len": uint32(4096),
			}},
			want: "init_module length=4096",
		},
		{
			name: "kernel_kexec_load",
			payload: model.Payload{Kind: model.SubtypeKernel, Fields: map[string]any{
				"syscall_name": "kexec_load", "kexec_entry": uint64(0x1000),
				"kexec_segments": uint32(3),
			}},
			want: "kexec_load entry=0x1000 segments=3",
		},
		{
			name: "kernel_reboot",
			payload: model.Payload{Kind: model.SubtypeKernel, Fields: map[string]any{
				"syscall_name": "reboot", "reboot_cmd": uint32(0x01234567),
			}},
			want: "reboot cmd=19088743",
		},
		{
			name: "kernel_sethostname",
			payload: model.Payload{Kind: model.SubtypeKernel, Fields: map[string]any{
				"syscall_name": "sethostname", "hostname": "evil",
			}},
			want: "sethostname evil",
		},
		{
			name: "signal_kill",
			payload: model.Payload{Kind: model.SubtypeSignal, Fields: map[string]any{
				"syscall_name": "kill", "sig": uint32(9),
				"target_pid": uint32(1234), "target_tid": uint32(0),
				"si_code": int32(0),
			}},
			want: "kill sig=9 pid=1234",
		},
		{
			name: "signal_tgkill",
			payload: model.Payload{Kind: model.SubtypeSignal, Fields: map[string]any{
				"syscall_name": "tgkill", "sig": uint32(9),
				"target_pid": uint32(1), "target_tid": uint32(2),
				"si_code": int32(0),
			}},
			want: "tgkill sig=9 pid=1 tid=2",
		},
		{
			name: "signal_rt_sigqueueinfo",
			payload: model.Payload{Kind: model.SubtypeSignal, Fields: map[string]any{
				"syscall_name": "rt_sigqueueinfo", "sig": uint32(10),
				"target_pid": uint32(77), "target_tid": uint32(0),
				"si_code": int32(-6),
			}},
			want: "rt_sigqueueinfo sig=10 pid=77 si_code=-6",
		},
		{
			name: "memory_mremap",
			payload: model.Payload{Kind: model.SubtypeMemory, Fields: map[string]any{
				"syscall_name": "mremap", "prot": uint64(0), "flags": uint64(1),
				"addr": uint64(0x7f0000000000), "length": uint64(8192),
				"offset": uint64(0), "fd": int32(-1), "anonymous": false,
				"wx": false, "path": "", "path_flags": uint32(0),
			}},
			want: "mremap addr=0x7f0000000000 len=8192 prot=0x0 flags=0x1",
		},
		{
			name: "memory_munmap",
			payload: model.Payload{Kind: model.SubtypeMemory, Fields: map[string]any{
				"syscall_name": "munmap", "prot": uint64(0), "flags": uint64(0),
				"addr": uint64(0x401000), "length": uint64(4096),
				"offset": uint64(0), "fd": int32(-1), "anonymous": false,
				"wx": false, "path": "", "path_flags": uint32(0),
			}},
			want: "munmap addr=0x401000 len=4096 prot=0x0 flags=0x0",
		},
		{
			name: "network_listen",
			payload: model.Payload{Kind: model.SubtypeNetwork, Fields: map[string]any{
				"syscall_name": "listen", "family": uint32(2),
				"type": uint32(1), "protocol": uint32(6),
				"sockfd": int32(5), "backlog": int32(128),
			}},
			want: "listen sockfd=5 backlog=128",
		},
		{
			name: "network_recvfrom",
			payload: model.Payload{Kind: model.SubtypeNetwork, Fields: map[string]any{
				"syscall_name": "recvfrom", "family": uint32(2),
				"src_ip": []uint32{0x0a01a8c0, 0, 0, 0}, "src_port": uint32(443),
				"count": uint64(512), "sockfd": int32(3),
			}},
			want: "recvfrom count=512 src=192.168.1.10:443 sockfd=3",
		},
		{
			name: "network_accept4",
			payload: model.Payload{Kind: model.SubtypeNetwork, Fields: map[string]any{
				"syscall_name": "accept4", "family": uint32(2),
				"type": uint32(0x800), "sockfd": int32(6),
			}},
			want: "accept4 sockfd=6",
		},
		{
			name: "kernel_ptrace",
			payload: model.Payload{Kind: model.SubtypeKernel, Fields: map[string]any{
				"syscall_name": "ptrace", "command": uint32(7),
				"target_pid": uint32(4242), "arg": uint64(8), "bpf_type": uint32(0),
			}},
			want: "ptrace command=7 pid=4242",
		},
		{
			name: "kernel_bpf",
			payload: model.Payload{Kind: model.SubtypeKernel, Fields: map[string]any{
				"syscall_name": "bpf", "command": uint32(8),
				"target_pid": uint32(0), "arg": uint64(0),
				"bpf_attr": []uint32{7, 9, 3, 0}, "bpf_type": uint32(3),
			}},
			want: "bpf command=8 type=3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 事件头字段由 TestEventDetailHeadFields 单独覆盖
			got := strings.TrimSuffix(eventDetail(model.Head{}, tt.payload), " RET=0")
			if got != tt.want {
				t.Errorf("eventDetail = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestEventDetailHeadFields(t *testing.T) {
	payload := model.Payload{Kind: model.SubtypeFile, Fields: map[string]any{
		"syscall_name": "openat", "path1": "/tmp/x", "flags": uint32(3),
		"mode": uint32(420),
	}}
	const detail = "openat path=/tmp/x flags=0x3 mode=0644"

	tests := []struct {
		name string
		head model.Head
		want string
	}{
		{"zero head", model.Head{}, detail + " RET=0"},
		{"comm", model.Head{Comm: "bash"}, detail + " RET=0 COMM=bash"},
		{"ret", model.Head{Ret: 3}, detail + " RET=3"},
		{"exe", model.Head{Exe: "/tmp/test"}, detail + " RET=0 EXE=/tmp/test"},
		{"non-initial mnt_ns", model.Head{MntNS: 4026532222},
			detail + " RET=0 MNTNS=4026532222"},
		{"initial mnt_ns hidden", model.Head{MntNS: initMntNSInum},
			detail + " RET=0"},
		{"unknown mnt_ns hidden", model.Head{MntNS: 0}, detail + " RET=0"},
		{"all", model.Head{Comm: "bash", Ret: -2, Exe: "/tmp/test",
			MntNS: 4026532222},
			detail + " RET=-2 COMM=bash EXE=/tmp/test MNTNS=4026532222"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := eventDetail(tt.head, payload); got != tt.want {
				t.Errorf("eventDetail = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFormatIP(t *testing.T) {
	tests := []struct {
		name   string
		family uint32
		words  []uint32
		want   string
	}{
		{"ipv4", afINET, []uint32{0x0a01a8c0}, "192.168.1.10"},
		{"ipv4 zero", afINET, []uint32{0}, "0.0.0.0"},
		{"ipv4 no words", afINET, nil, ""},
		{"ipv6", afINET6, []uint32{0xb80d0120, 0, 0, 0x01000000},
			"2001:db8:0:0:0:0:0:1"},
		{"ipv6 loopback", afINET6, []uint32{0, 0, 0, 0x01000000},
			"0:0:0:0:0:0:0:1"},
		{"ipv6 short", afINET6, []uint32{0, 0, 0}, ""},
		{"other family", 1, []uint32{0x0a01a8c0}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatIP(tt.family, tt.words); got != tt.want {
				t.Errorf("formatIP(%d, %v) = %q, want %q", tt.family, tt.words, got, tt.want)
			}
		})
	}
}

func TestNetworkDst(t *testing.T) {
	tests := []struct {
		name   string
		fields map[string]any
		want   string
	}{
		{"ipv4", map[string]any{
			"family": uint32(2), "dst_ip": []uint32{0x0a01a8c0, 0, 0, 0},
			"dst_port": uint32(443),
		}, "192.168.1.10:443"},
		{"ipv6", map[string]any{
			"family": uint32(10), "dst_ip": []uint32{0xb80d0120, 0, 0, 0x01000000},
			"dst_port": uint32(53),
		}, "[2001:db8:0:0:0:0:0:1]:53"},
		{"unparsed", map[string]any{
			"family": uint32(2), "dst_ip": []uint32{0, 0, 0, 0},
			"dst_port": uint32(0),
		}, ""},
		{"unix", map[string]any{
			"family": uint32(1), "dst_ip": []uint32{0, 0, 0, 0},
			"dst_port": uint32(0),
		}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := networkDst(tt.fields); got != tt.want {
				t.Errorf("networkDst(%v) = %q, want %q", tt.fields, got, tt.want)
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
