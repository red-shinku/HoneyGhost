package client

import (
	"errors"
	"fmt"
	"io"

	"google.golang.org/grpc"

	"honeyghost/cli/internal/gen/hng"
	"honeyghost/cli/internal/gen/hng/clisv"
	"honeyghost/cli/internal/model"
)

type eventStream struct {
	stream grpc.ServerStreamingClient[clisv.ReceiveEventResponse]
}

func (s *eventStream) Recv() (model.StreamItem, error) {
	response, err := s.stream.Recv()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return model.StreamItem{}, io.EOF
		}
		return model.StreamItem{}, statusError("ReceiveEvent", err)
	}
	return convertEventResponse(response)
}

func (s *eventStream) Close() error {
	return s.stream.CloseSend()
}

func toProtoEventType(eventType model.EventType) (clisv.EventType, error) {
	switch eventType {
	case model.EventTypeSyscall:
		return clisv.EventType_EVENT_TYPE_SYSCALL, nil
	case model.EventTypeFile:
		return clisv.EventType_EVENT_TYPE_FILE, nil
	case model.EventTypeNetwork:
		return clisv.EventType_EVENT_TYPE_NETWORK, nil
	case model.EventTypeIPC:
		return clisv.EventType_EVENT_TYPE_IPC, nil
	default:
		return 0, fmt.Errorf("unknown event type %q", eventType)
	}
}

func eventTypeFromProto(eventType clisv.EventType) model.EventType {
	switch eventType {
	case clisv.EventType_EVENT_TYPE_SYSCALL:
		return model.EventTypeSyscall
	case clisv.EventType_EVENT_TYPE_FILE:
		return model.EventTypeFile
	case clisv.EventType_EVENT_TYPE_NETWORK:
		return model.EventTypeNetwork
	case clisv.EventType_EVENT_TYPE_IPC:
		return model.EventTypeIPC
	default:
		return ""
	}
}

func convertEventResponse(response *clisv.ReceiveEventResponse) (model.StreamItem, error) {
	switch event := response.GetEvent().(type) {
	case *clisv.ReceiveEventResponse_Stats:
		return model.StreamItem{Stats: &model.StreamStats{
			DroppedEvents: event.Stats.GetDroppedEvents(),
		}}, nil

	case *clisv.ReceiveEventResponse_SyscallEv:
		payload, err := convertSyscallPayload(event.SyscallEv)
		if err != nil {
			return model.StreamItem{}, err
		}
		return model.StreamItem{Event: &model.Event{
			Head:    convertEventHead(response.GetHead()),
			Payload: payload,
		}}, nil

	case *clisv.ReceiveEventResponse_FileEv:
		return model.StreamItem{Event: &model.Event{
			Head:    convertEventHead(response.GetHead()),
			Payload: convertFilePayload(event.FileEv),
		}}, nil

	default:
		return model.StreamItem{}, fmt.Errorf("ReceiveEvent: unknown event payload")
	}
}

func convertEventHead(in *clisv.Eventhead) model.Head {
	if in == nil {
		return model.Head{}
	}
	return model.Head{
		RoleLabel:     in.GetRoleLabel(),
		RoleID:        in.GetRoleID(),
		ContextID:     in.GetContextID(),
		PID:           in.GetPid(),
		PIDStartTime:  in.GetPidStartTime(),
		PPID:          in.GetPpid(),
		PPIDStartTime: in.GetPpidStartTime(),
		Type:          eventTypeFromProto(in.GetType()),
	}
}

func convertSyscallPayload(in *clisv.SyscallEventData) (model.Payload, error) {
	switch data := in.GetSData().(type) {
	case *clisv.SyscallEventData_ProcessData:
		value := data.ProcessData
		return payload(model.PayloadProcess, map[string]any{
			"exit_code":    value.GetExitCode(),
			"syscall_name": value.GetSyscallName(),
		}), nil

	case *clisv.SyscallEventData_ExecData:
		value := data.ExecData
		return payload(model.PayloadExec, map[string]any{
			"semantic_filename": value.GetSemanticFilename(),
			"argv0":             value.GetArgv0(),
			"argv1":             value.GetArgv1(),
			"flags":             value.GetFlags(),
			"syscall_name":      value.GetSyscallName(),
		}), nil

	case *clisv.SyscallEventData_CredentialData:
		return convertCredentialPayload(data.CredentialData), nil

	case *clisv.SyscallEventData_NamespaceData:
		value := data.NamespaceData
		return payload(model.PayloadNamespace, map[string]any{
			"ns_type":      value.GetNsType(),
			"flags":        value.GetFlags(),
			"syscall_name": value.GetSyscallName(),
		}), nil

	case *clisv.SyscallEventData_FileData:
		value := data.FileData
		return payload(model.PayloadFileSyscall, map[string]any{
			"flags":        value.GetFlags(),
			"mode":         value.GetMode(),
			"syscall_name": value.GetSyscallName(),
		}), nil

	case *clisv.SyscallEventData_MemoryData:
		value := data.MemoryData
		return payload(model.PayloadMemory, map[string]any{
			"prot":         value.GetProt(),
			"flags":        value.GetFlags(),
			"syscall_name": value.GetSyscallName(),
		}), nil

	case *clisv.SyscallEventData_NetData:
		value := data.NetData
		return payload(model.PayloadNetworkSyscall, map[string]any{
			"family":       value.GetFamily(),
			"type":         value.GetType(),
			"protocol":     value.GetProtocol(),
			"syscall_name": value.GetSyscallName(),
		}), nil

	case *clisv.SyscallEventData_KernelData:
		value := data.KernelData
		return payload(model.PayloadKernel, map[string]any{
			"command":      value.GetCommand(),
			"arg":          value.GetArg(),
			"syscall_name": value.GetSyscallName(),
		}), nil

	default:
		return model.Payload{}, fmt.Errorf("ReceiveEvent: unknown syscall payload")
	}
}

func convertCredentialPayload(in *hng.CredentialSemanticData) model.Payload {
	fields := map[string]any{
		"syscall_name": in.GetSyscallName(),
	}
	switch op := in.GetOp().(type) {
	case *hng.CredentialSemanticData_SetuidUid:
		fields["setuid_uid"] = op.SetuidUid
	case *hng.CredentialSemanticData_SetgidGid:
		fields["setgid_gid"] = op.SetgidGid
	case *hng.CredentialSemanticData_Capset:
		capset := op.Capset
		fields["capset"] = map[string]any{
			"effective":   capset.GetEffective(),
			"permitted":   capset.GetPermitted(),
			"inheritable": capset.GetInheritable(),
		}
	}
	return payload(model.PayloadCredential, fields)
}

func convertFilePayload(in *hng.FileEventData) model.Payload {
	return payload(model.PayloadFile, map[string]any{
		"semantic_filename": in.GetSemanticFilename(),
		"flags":             in.GetFlags(),
		"is_innamespace":    in.GetIsInnamespace(),
		"comm":              in.GetComm(),
	})
}

func payload(kind string, fields map[string]any) model.Payload {
	return model.Payload{Kind: kind, Fields: fields}
}
