package client

import (
	"context"
	"errors"
	"fmt"
	"io"

	"google.golang.org/grpc"

	"honeyghost/cli/internal/gen/hng"
	"honeyghost/cli/internal/gen/hng/clisv"
	"honeyghost/cli/internal/model"
)

type eventStream struct {
	stream  grpc.ServerStreamingClient[clisv.ReceiveEventResponse]
	pending []model.StreamItem
	cursor  int
}

// Recv 从当前事件批中逐条返回；批取完再读下一条消息。
func (s *eventStream) Recv() (model.StreamItem, error) {
	for s.cursor >= len(s.pending) {
		response, err := s.stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return model.StreamItem{}, io.EOF
			}
			return model.StreamItem{}, statusError("ReceiveEvent", err)
		}
		items, err := convertEventResponse(response)
		if err != nil {
			return model.StreamItem{}, err
		}
		s.pending = items
		s.cursor = 0
	}
	item := s.pending[s.cursor]
	s.cursor++
	return item, nil
}

func (s *eventStream) Close() error {
	return s.stream.CloseSend()
}

// Stats 查询服务端流水线各段的累计计数。
func (s eventService) Stats(ctx context.Context) (model.PipelineStats, error) {
	response, err := s.c.events.GetPipelineStats(ctx, &clisv.GetPipelineStatsRequest{})
	if err != nil {
		return model.PipelineStats{}, statusError("GetPipelineStats", err)
	}
	return convertPipelineStats(response.GetStats()), nil
}

func convertPipelineStats(in *clisv.PipelineStats) model.PipelineStats {
	if in == nil {
		return model.PipelineStats{Collector: []model.CollectorLineStats{}}
	}
	out := model.PipelineStats{
		Collector: make([]model.CollectorLineStats, 0, len(in.GetCollector())),
	}
	for _, line := range in.GetCollector() {
		out.Collector = append(out.Collector, model.CollectorLineStats{
			Line:            line.GetLine(),
			Consumed:        line.GetConsumed(),
			ConsumeErrors:   line.GetConsumeErrors(),
			ChannelDropped:  line.GetChannelDropped(),
			ChannelRejected: line.GetChannelRejected(),
			ReserveFailures: line.GetReserveFailures(),
			SkippedProbes:   line.GetSkippedProbes(),
			AttachFailed:    line.GetAttachFailed(),
			PendingLost:     line.GetPendingLost(),
			Malformed:       line.GetMalformed(),
			Attached:        line.GetAttached(),
			Polling:         line.GetPolling(),
		})
	}
	if semantic := in.GetSemantic(); semantic != nil {
		out.Semantic = &model.SemanticStats{
			ProcessedSyscall:   semantic.GetProcessedSyscall(),
			RawSyscallDropped:  semantic.GetRawSyscallDropped(),
			RawSyscallRejected: semantic.GetRawSyscallRejected(),
			OutSyscallDropped:  semantic.GetOutSyscallDropped(),
			OutSyscallRejected: semantic.GetOutSyscallRejected(),
			PathUnresolved:     semantic.GetPathUnresolved(),
		}
	}
	if engine := in.GetEngine(); engine != nil {
		out.Engine = &model.EngineStats{
			UnsettledEvents: engine.GetUnsettledEvents(),
			PeakCLIStreams:  engine.GetPeakCliStreams(),
			QueueRejected:   engine.GetQueueRejected(),
			IdleWaits:       engine.GetIdleWaits(),
			SyscallDropped:  engine.GetSyscallDropped(),
		}
	}
	if cli := in.GetCli(); cli != nil {
		out.CLI = &model.CLIStreamStats{
			Active:  cli.GetActive(),
			Peak:    cli.GetPeak(),
			Dropped: cli.GetDropped(),
		}
	}
	return out
}

func eventTypeFromProto(eventType clisv.EventType) model.EventType {
	switch eventType {
	case clisv.EventType_EVENT_TYPE_SYSCALL:
		return model.EventTypeSyscall
	default:
		return ""
	}
}

func subtypeFromProto(subtype clisv.Subtype) model.Subtype {
	switch subtype {
	case clisv.Subtype_SUBTYPE_PROCESS:
		return model.SubtypeProcess
	case clisv.Subtype_SUBTYPE_EXEC:
		return model.SubtypeExec
	case clisv.Subtype_SUBTYPE_CREDENTIAL:
		return model.SubtypeCredential
	case clisv.Subtype_SUBTYPE_NAMESPACE:
		return model.SubtypeNamespace
	case clisv.Subtype_SUBTYPE_FILE:
		return model.SubtypeFile
	case clisv.Subtype_SUBTYPE_MEMORY:
		return model.SubtypeMemory
	case clisv.Subtype_SUBTYPE_NETWORK:
		return model.SubtypeNetwork
	case clisv.Subtype_SUBTYPE_KERNEL:
		return model.SubtypeKernel
	default:
		return ""
	}
}

// convertEventResponse 把一条流消息展开成待消费的记录；stats 消息只产出一项。
func convertEventResponse(response *clisv.ReceiveEventResponse) ([]model.StreamItem, error) {
	if stats := response.GetStats(); stats != nil {
		return []model.StreamItem{{Stats: &model.StreamStats{
			DroppedEvents: stats.GetDroppedEvents(),
		}}}, nil
	}
	batch := response.GetBatch()
	if batch == nil {
		return nil, fmt.Errorf("ReceiveEvent: unknown response payload")
	}
	items := make([]model.StreamItem, 0, len(batch.GetRecords()))
	for _, record := range batch.GetRecords() {
		event, err := convertEventRecord(record)
		if err != nil {
			return nil, err
		}
		items = append(items, model.StreamItem{Event: &event})
	}
	return items, nil
}

func convertEventRecord(record *clisv.Eventrecord) (model.Event, error) {
	event, ok := record.GetEvent().(*clisv.Eventrecord_SyscallEv)
	if !ok {
		return model.Event{}, fmt.Errorf("ReceiveEvent: unknown event payload")
	}
	payload, err := convertSyscallPayload(event.SyscallEv)
	if err != nil {
		return model.Event{}, err
	}
	return model.Event{
		Head:    convertEventHead(record.GetHead()),
		Payload: payload,
	}, nil
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
		Subtype:       subtypeFromProto(in.GetSubtype()),
		UID:           in.GetUid(),
		EUID:          in.GetEuid(),
		Ret:           in.GetRet(),
		Comm:          in.GetComm(),
		MntNS:         in.GetMntNs(),
		Exe:           in.GetExe(),
	}
}

func convertSyscallPayload(in *clisv.SyscallEventData) (model.Payload, error) {
	switch data := in.GetSData().(type) {
	case *clisv.SyscallEventData_ProcessData:
		value := data.ProcessData
		return payload(model.SubtypeProcess, map[string]any{
			"exit_code":    value.GetExitCode(),
			"syscall_name": value.GetSyscallName(),
		}), nil

	case *clisv.SyscallEventData_ExecData:
		value := data.ExecData
		return payload(model.SubtypeExec, map[string]any{
			"semantic_filename": value.GetSemanticFilename(),
			"argv0":             value.GetArgv0(),
			"argv1":             value.GetArgv1(),
			"flags":             value.GetFlags(),
			"invoked":           value.GetInvoked(),
			"image":             value.GetImage(),
			"image_flags":       value.GetImageFlags(),
			"syscall_name":      value.GetSyscallName(),
		}), nil

	case *clisv.SyscallEventData_CredentialData:
		return convertCredentialPayload(data.CredentialData), nil

	case *clisv.SyscallEventData_NamespaceData:
		value := data.NamespaceData
		return payload(model.SubtypeNamespace, map[string]any{
			"flags":        value.GetFlags(),
			"ns_mask":      value.GetNsMask(),
			"fd":           value.GetFd(),
			"syscall_name": value.GetSyscallName(),
		}), nil

	case *clisv.SyscallEventData_FileData:
		value := data.FileData
		return payload(model.SubtypeFile, map[string]any{
			"flags":        value.GetFlags(),
			"mode":         value.GetMode(),
			"path":         value.GetPath(),
			"path_flags":   value.GetPathFlags(),
			"syscall_name": value.GetSyscallName(),
		}), nil

	case *clisv.SyscallEventData_MemoryData:
		value := data.MemoryData
		return payload(model.SubtypeMemory, map[string]any{
			"prot":         value.GetProt(),
			"flags":        value.GetFlags(),
			"syscall_name": value.GetSyscallName(),
		}), nil

	case *clisv.SyscallEventData_NetData:
		value := data.NetData
		dstIP := value.GetDstIp()
		if dstIP == nil {
			dstIP = []uint32{}
		}
		return payload(model.SubtypeNetwork, map[string]any{
			"family":       value.GetFamily(),
			"type":         value.GetType(),
			"protocol":     value.GetProtocol(),
			"dst_ip":       dstIP,
			"dst_port":     value.GetDstPort(),
			"src_port":     value.GetSrcPort(),
			"syscall_name": value.GetSyscallName(),
		}), nil

	case *clisv.SyscallEventData_KernelData:
		value := data.KernelData
		return payload(model.SubtypeKernel, map[string]any{
			"command":      value.GetCommand(),
			"arg":          value.GetArg(),
			"syscall_name": value.GetSyscallName(),
		}), nil

	default:
		return model.Payload{}, fmt.Errorf("ReceiveEvent: unknown syscall payload")
	}
}

func convertCredentialPayload(in *hng.CredentialSemanticData) model.Payload {
	requested := in.GetRequested()
	if requested == nil {
		requested = []uint32{}
	}
	fields := map[string]any{
		"syscall_name": in.GetSyscallName(),
		"kind":         in.GetKind(),
		"requested":    requested,
	}
	// capset 只在 kind=CAPS 时由内核侧填充；其余 kind 不呈现该字段
	if capset := in.GetCapset(); capset != nil {
		fields["capset"] = map[string]any{
			"effective":   capset.GetEffective(),
			"permitted":   capset.GetPermitted(),
			"inheritable": capset.GetInheritable(),
		}
	}
	return payload(model.SubtypeCredential, fields)
}

func payload(kind model.Subtype, fields map[string]any) model.Payload {
	return model.Payload{Kind: kind, Fields: fields}
}
