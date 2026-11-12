package client

import (
	"reflect"
	"testing"

	"honeyghost/cli/internal/gen/hng"
	"honeyghost/cli/internal/gen/hng/clisv"
	"honeyghost/cli/internal/model"
)

func testHead() *clisv.Eventhead {
	return &clisv.Eventhead{
		RoleLabel:     "nginx:1.25",
		RoleID:        7,
		ContextID:     3,
		Pid:           1234,
		PidStartTime:  100,
		Ppid:          1,
		PpidStartTime: 2,
		Type:          clisv.EventType_EVENT_TYPE_SYSCALL,
	}
}

func syscallRecord(data *clisv.SyscallEventData) *clisv.Eventrecord {
	return &clisv.Eventrecord{
		Head:  testHead(),
		Event: &clisv.Eventrecord_SyscallEv{SyscallEv: data},
	}
}

func TestConvertEventHead(t *testing.T) {
	got := convertEventHead(testHead())
	want := model.Head{
		RoleLabel:     "nginx:1.25",
		RoleID:        7,
		ContextID:     3,
		PID:           1234,
		PIDStartTime:  100,
		PPID:          1,
		PPIDStartTime: 2,
		Type:          model.EventTypeSyscall,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("convertEventHead = %+v, want %+v", got, want)
	}
	if got := convertEventHead(nil); !reflect.DeepEqual(got, model.Head{}) {
		t.Errorf("convertEventHead(nil) = %+v, want zero", got)
	}
}

func TestConvertEventTypes(t *testing.T) {
	tests := map[clisv.EventType]model.EventType{
		clisv.EventType_EVENT_TYPE_SYSCALL: model.EventTypeSyscall,
		clisv.EventType_EVENT_TYPE_FILE:    model.EventTypeFile,
		clisv.EventType_EVENT_TYPE_NETWORK: model.EventTypeNetwork,
		clisv.EventType_EVENT_TYPE_IPC:     model.EventTypeIPC,
		clisv.EventType(99):                "",
	}
	for in, want := range tests {
		if got := eventTypeFromProto(in); got != want {
			t.Errorf("eventTypeFromProto(%v) = %q, want %q", in, got, want)
		}
	}
}

func TestConvertSyscallPayloads(t *testing.T) {
	tests := []struct {
		name   string
		data   *clisv.SyscallEventData
		kind   string
		fields map[string]any
	}{
		{
			name: "process",
			data: &clisv.SyscallEventData{SData: &clisv.SyscallEventData_ProcessData{
				ProcessData: &hng.ProcessSemanticData{ExitCode: -9, SyscallName: "exit_group"},
			}},
			kind:   model.PayloadProcess,
			fields: map[string]any{"exit_code": int32(-9), "syscall_name": "exit_group"},
		},
		{
			name: "exec",
			data: &clisv.SyscallEventData{SData: &clisv.SyscallEventData_ExecData{
				ExecData: &hng.ExecSemanticData{
					SemanticFilename: "/usr/sbin/nginx",
					Argv0:            "nginx",
					Argv1:            "-g",
					Flags:            1,
					SyscallName:      "execve",
				},
			}},
			kind: model.PayloadExec,
			fields: map[string]any{
				"semantic_filename": "/usr/sbin/nginx",
				"argv0":             "nginx",
				"argv1":             "-g",
				"flags":             uint32(1),
				"syscall_name":      "execve",
			},
		},
		{
			name: "credential setuid",
			data: &clisv.SyscallEventData{SData: &clisv.SyscallEventData_CredentialData{
				CredentialData: &hng.CredentialSemanticData{
					Op:          &hng.CredentialSemanticData_SetuidUid{SetuidUid: 1000},
					SyscallName: "setuid",
				},
			}},
			kind:   model.PayloadCredential,
			fields: map[string]any{"setuid_uid": uint32(1000), "syscall_name": "setuid"},
		},
		{
			name: "credential capset",
			data: &clisv.SyscallEventData{SData: &clisv.SyscallEventData_CredentialData{
				CredentialData: &hng.CredentialSemanticData{
					Op: &hng.CredentialSemanticData_Capset{
						Capset: &hng.CredentialSemanticDataCapabilitySet{
							Effective: 1, Permitted: 2, Inheritable: 3,
						},
					},
					SyscallName: "capset",
				},
			}},
			kind: model.PayloadCredential,
			fields: map[string]any{
				"capset": map[string]any{
					"effective": uint64(1), "permitted": uint64(2), "inheritable": uint64(3),
				},
				"syscall_name": "capset",
			},
		},
		{
			name: "namespace",
			data: &clisv.SyscallEventData{SData: &clisv.SyscallEventData_NamespaceData{
				NamespaceData: &hng.NamespaceSemanticData{NsType: 1, Flags: 2, SyscallName: "unshare"},
			}},
			kind: model.PayloadNamespace,
			fields: map[string]any{
				"ns_type": uint32(1), "flags": uint64(2), "syscall_name": "unshare",
			},
		},
		{
			name: "file_syscall",
			data: &clisv.SyscallEventData{SData: &clisv.SyscallEventData_FileData{
				FileData: &hng.FileSyscallSemanticData{Flags: 3, Mode: 420, SyscallName: "openat"},
			}},
			kind: model.PayloadFileSyscall,
			fields: map[string]any{
				"flags": uint32(3), "mode": uint32(420), "syscall_name": "openat",
			},
		},
		{
			name: "memory",
			data: &clisv.SyscallEventData{SData: &clisv.SyscallEventData_MemoryData{
				MemoryData: &hng.MemorySemanticData{Prot: 4, Flags: 5, SyscallName: "mmap"},
			}},
			kind: model.PayloadMemory,
			fields: map[string]any{
				"prot": uint64(4), "flags": uint64(5), "syscall_name": "mmap",
			},
		},
		{
			name: "network_syscall",
			data: &clisv.SyscallEventData{SData: &clisv.SyscallEventData_NetData{
				NetData: &hng.NetworkSyscallSemanticData{
					Family: 2, Type: 1, Protocol: 6, SyscallName: "socket",
				},
			}},
			kind: model.PayloadNetworkSyscall,
			fields: map[string]any{
				"family": uint32(2), "type": uint32(1), "protocol": uint32(6),
				"syscall_name": "socket",
			},
		},
		{
			name: "kernel",
			data: &clisv.SyscallEventData{SData: &clisv.SyscallEventData_KernelData{
				KernelData: &hng.KernelSemanticData{Command: 7, Arg: 8, SyscallName: "ptrace"},
			}},
			kind: model.PayloadKernel,
			fields: map[string]any{
				"command": uint32(7), "arg": uint64(8), "syscall_name": "ptrace",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event, err := convertEventRecord(syscallRecord(tt.data))
			if err != nil {
				t.Fatalf("convertEventRecord: %v", err)
			}
			if event.Payload.Kind != tt.kind {
				t.Errorf("Kind = %q, want %q", event.Payload.Kind, tt.kind)
			}
			if !reflect.DeepEqual(event.Payload.Fields, tt.fields) {
				t.Errorf("Fields = %#v, want %#v", event.Payload.Fields, tt.fields)
			}
		})
	}
}

func TestConvertFileEvent(t *testing.T) {
	record := &clisv.Eventrecord{
		Head: testHead(),
		Event: &clisv.Eventrecord_FileEv{FileEv: &hng.FileEventData{
			SemanticFilename: "/etc/nginx/nginx.conf",
			Flags:            1,
			IsInnamespace:    true,
			Comm:             "nginx",
		}},
	}
	event, err := convertEventRecord(record)
	if err != nil {
		t.Fatalf("convertEventRecord: %v", err)
	}
	if event.Payload.Kind != model.PayloadFile {
		t.Errorf("Kind = %q, want file", event.Payload.Kind)
	}
	want := map[string]any{
		"semantic_filename": "/etc/nginx/nginx.conf",
		"flags":             uint32(1),
		"is_innamespace":    true,
		"comm":              "nginx",
	}
	if !reflect.DeepEqual(event.Payload.Fields, want) {
		t.Errorf("Fields = %#v, want %#v", event.Payload.Fields, want)
	}
}

func TestConvertStreamStats(t *testing.T) {
	response := &clisv.ReceiveEventResponse{
		Payload: &clisv.ReceiveEventResponse_Stats{Stats: &clisv.Streamstats{DroppedEvents: 12}},
	}
	items, err := convertEventResponse(response)
	if err != nil {
		t.Fatalf("convertEventResponse: %v", err)
	}
	if len(items) != 1 || items[0].Stats == nil || items[0].Stats.DroppedEvents != 12 {
		t.Fatalf("Stats = %+v, want 12 dropped", items)
	}
	if items[0].Event != nil {
		t.Errorf("Event = %+v, want nil", items[0].Event)
	}
}

func TestConvertBatch(t *testing.T) {
	response := &clisv.ReceiveEventResponse{
		Payload: &clisv.ReceiveEventResponse_Batch{Batch: &clisv.ReceiveEventBatch{
			Records: []*clisv.Eventrecord{
				syscallRecord(&clisv.SyscallEventData{SData: &clisv.SyscallEventData_ProcessData{
					ProcessData: &hng.ProcessSemanticData{SyscallName: "fork"},
				}}),
				{
					Head: testHead(),
					Event: &clisv.Eventrecord_FileEv{FileEv: &hng.FileEventData{
						SemanticFilename: "/tmp/a",
					}},
				},
			},
		}},
	}
	items, err := convertEventResponse(response)
	if err != nil {
		t.Fatalf("convertEventResponse: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("len(items) = %d, want 2", len(items))
	}
	if items[0].Event == nil || items[0].Event.Payload.Kind != model.PayloadProcess {
		t.Errorf("items[0] = %+v, want process payload", items[0])
	}
	if items[1].Event == nil || items[1].Event.Payload.Kind != model.PayloadFile {
		t.Errorf("items[1] = %+v, want file payload", items[1])
	}
}

func TestConvertUnknownPayload(t *testing.T) {
	if _, err := convertEventResponse(&clisv.ReceiveEventResponse{}); err == nil {
		t.Error("expected an error for a missing payload")
	}
	if _, err := convertEventRecord(&clisv.Eventrecord{}); err == nil {
		t.Error("expected an error for a missing record payload")
	}
	if _, err := convertSyscallPayload(&clisv.SyscallEventData{}); err == nil {
		t.Error("expected an error for a missing syscall payload")
	}
}
