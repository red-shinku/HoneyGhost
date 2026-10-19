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
		Rejected:        uint64Ptr(0),
		UnknownInstance: nil,
		OwnerConflict:   uint64Ptr(2),
		AnchorsRemoved:  uint64Ptr(0),
		CgroupReadEmpty: nil,
		QueueRejected:   uint64Ptr(5),
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
	}
	checkGolden(t, "context_stats_table", render(t, FormatTable, Options{},
		func(r Renderer, b *bytes.Buffer) error { return r.ContextStats(b, stats) }))
	checkGolden(t, "context_stats_json", render(t, FormatJSON, Options{},
		func(r Renderer, b *bytes.Buffer) error { return r.ContextStats(b, stats) }))
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
