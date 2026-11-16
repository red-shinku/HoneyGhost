package selector

import (
	"reflect"
	"strings"
	"testing"

	"honeyghost/cli/internal/model"
)

func TestParseTypes(t *testing.T) {
	tests := []struct {
		name   string
		values []string
		want   []model.EventType
	}{
		{"none", nil, []model.EventType{}},
		{"single", []string{"syscall"}, []model.EventType{model.EventTypeSyscall}},
		{"case and comma", []string{"SYSCALL,File"}, []model.EventType{
			model.EventTypeSyscall, model.EventTypeFile,
		}},
		{"canonical order", []string{"ipc", "network", "file", "syscall"}, []model.EventType{
			model.EventTypeSyscall, model.EventTypeFile,
			model.EventTypeNetwork, model.EventTypeIPC,
		}},
		{"dedupe", []string{"file", "FILE,file"}, []model.EventType{model.EventTypeFile}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseTypes(tt.values)
			if err != nil {
				t.Fatalf("ParseTypes: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseTypes = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseTypesErrors(t *testing.T) {
	for _, value := range [][]string{
		{"bogus"},
		{""},
		{"syscall,"},
	} {
		t.Run(strings.Join(value, "|"), func(t *testing.T) {
			if _, err := ParseTypes(value); err == nil {
				t.Error("expected an error")
			}
		})
	}
}

func TestParseSelector(t *testing.T) {
	tests := []struct {
		name   string
		values []string
		want   model.RuntimeSelector
	}{
		{"none", nil, model.RuntimeSelector{}},
		{
			name:   "ids sorted and deduped",
			values: []string{"roleID=8,7", "roleID=7"},
			want:   model.RuntimeSelector{RoleIDs: []uint32{7, 8}},
		},
		{
			name:   "context and pid",
			values: []string{"contextID=3", "pid=10,2"},
			want: model.RuntimeSelector{
				ContextIDs: []uint32{3},
				PIDs:       []uint32{2, 10},
			},
		},
		{
			name:   "zero role and context id",
			values: []string{"roleID=0", "contextID=0", "contextID=3", "roleID=7"},
			want: model.RuntimeSelector{
				RoleIDs:    []uint32{0, 7},
				ContextIDs: []uint32{0, 3},
			},
		},
		{
			name:   "labels sorted",
			values: []string{"role=nginx,ssh", "role=nginx"},
			want:   model.RuntimeSelector{RoleLabels: []string{"nginx", "ssh"}},
		},
		{
			name:   "escaped comma",
			values: []string{`role=nginx\,1.25`},
			want:   model.RuntimeSelector{RoleLabels: []string{"nginx,1.25"}},
		},
		{
			name:   "escaped and plain list",
			values: []string{`role=a\,b,c`},
			want:   model.RuntimeSelector{RoleLabels: []string{"a,b", "c"}},
		},
		{
			name:   "value with equals sign",
			values: []string{"role=a=b"},
			want:   model.RuntimeSelector{RoleLabels: []string{"a=b"}},
		},
		{
			name:   "all dimensions",
			values: []string{"roleID=7", "role=nginx", "contextID=3", "pid=4"},
			want: model.RuntimeSelector{
				RoleIDs:    []uint32{7},
				RoleLabels: []string{"nginx"},
				ContextIDs: []uint32{3},
				PIDs:       []uint32{4},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseSelector(tt.values)
			if err != nil {
				t.Fatalf("ParseSelector: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseSelector = %+v, want %+v", got, tt.want)
			}
			if tt.name == "none" && !got.IsZero() {
				t.Error("empty selector should be zero")
			}
		})
	}
}

func TestParseSelectorErrors(t *testing.T) {
	tests := []struct {
		name   string
		values []string
	}{
		{"missing equals", []string{"roleID"}},
		{"empty key", []string{"=1"}},
		{"empty value", []string{"role="}},
		{"empty list item", []string{"role=a,,b"}},
		{"unknown key", []string{"bogus=1"}},
		{"not a number", []string{"roleID=abc"}},
		{"zero pid", []string{"pid=0"}},
		{"overflow", []string{"pid=4294967296"}},
		{"number with space", []string{"pid= 1"}},
		{"negative", []string{"pid=-1"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseSelector(tt.values); err == nil {
				t.Error("expected an error")
			}
		})
	}
}

func TestParseSelectorErrorMentionsToken(t *testing.T) {
	_, err := ParseSelector([]string{"roleID=nope"})
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), `roleID=nope`) {
		t.Errorf("error does not contain the original token: %v", err)
	}
}
