package cmd

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"honeyghost/cli/internal/api"
	"honeyghost/cli/internal/model"
	"honeyghost/cli/internal/render"
)

// failWriter 写入固定错误，用于验证错误传播。
type failWriter struct{ err error }

func (w failWriter) Write([]byte) (int, error) { return 0, w.err }

func sinkTestEvents() []model.Event {
	return []model.Event{
		{
			Head: model.Head{
				RoleLabel: "nginx:1.25", RoleID: 7, ContextID: 3,
				PID: 1234, PPID: 1, Type: model.EventTypeSyscall,
			},
			Payload: model.Payload{Kind: model.PayloadExec, Fields: map[string]any{
				"syscall_name": "execve", "semantic_filename": "/usr/sbin/nginx",
			}},
		},
		{
			Head: model.Head{RoleID: 7, PID: 2002, PPID: 1, Type: model.EventTypeFile},
			Payload: model.Payload{Kind: model.PayloadFile, Fields: map[string]any{
				"semantic_filename": "/etc/nginx/nginx.conf",
			}},
		},
	}
}

func TestRecordSinkTableBothTargets(t *testing.T) {
	var stdout, file bytes.Buffer
	sink := newRecordSink(render.New(render.FormatTable, render.Options{}), &stdout, &file)
	for _, ev := range sinkTestEvents() {
		if err := sink.Event(ev); err != nil {
			t.Fatalf("Event: %v", err)
		}
	}
	if stdout.String() != file.String() {
		t.Errorf("stdout and file differ:\nstdout:\n%s\nfile:\n%s", stdout.String(), file.String())
	}
	got := file.String()
	if n := strings.Count(got, "TYPE"); n != 1 {
		t.Errorf("header count = %d, want 1:\n%s", n, got)
	}
	if !strings.HasPrefix(got, "TYPE") {
		t.Errorf("file does not start with header:\n%s", got)
	}
	if !strings.Contains(got, "/usr/sbin/nginx") || !strings.Contains(got, "/etc/nginx/nginx.conf") {
		t.Errorf("file missing event rows:\n%s", got)
	}
}

func TestRecordSinkJSONBothTargets(t *testing.T) {
	var stdout, file bytes.Buffer
	sink := newRecordSink(render.New(render.FormatJSON, render.Options{}), &stdout, &file)
	if err := sink.Event(sinkTestEvents()[0]); err != nil {
		t.Fatalf("Event: %v", err)
	}
	if err := sink.Stats(model.StreamStats{DroppedEvents: 2}); err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if stdout.String() != file.String() {
		t.Errorf("stdout and file differ:\nstdout:\n%s\nfile:\n%s", stdout.String(), file.String())
	}
	got := file.String()
	for _, want := range []string{
		"\"kind\":\"event\"", "\"kind\":\"stats\"", "\"dropped_events\":2",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("file missing %q:\n%s", want, got)
		}
	}
}

func TestRecordSinkTableStatsSilent(t *testing.T) {
	var stdout, file bytes.Buffer
	sink := newRecordSink(render.New(render.FormatTable, render.Options{}), &stdout, &file)
	if err := sink.Stats(model.StreamStats{DroppedEvents: 1}); err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if stdout.Len() != 0 || file.Len() != 0 {
		t.Errorf("table stats wrote bytes: stdout=%q file=%q", stdout.String(), file.String())
	}
}

func TestRecordSinkStdoutEPIPEKeepsFile(t *testing.T) {
	for _, format := range []render.Format{render.FormatTable, render.FormatJSON} {
		events := sinkTestEvents()

		var file bytes.Buffer
		sink := newRecordSink(render.New(format, render.Options{}), epipeWriter{}, &file)
		var healthy bytes.Buffer
		fileOnly := newRecordSink(render.New(format, render.Options{}), nil, &healthy)
		for _, ev := range events {
			if err := sink.Event(ev); err != nil {
				t.Errorf("format %v: Event = %v, want nil", format, err)
			}
			if !sink.Active() {
				t.Errorf("format %v: sink should stay active for the file target", format)
			}
			if err := fileOnly.Event(ev); err != nil {
				t.Fatalf("format %v: file-only Event: %v", format, err)
			}
		}
		if err := sink.Stats(model.StreamStats{DroppedEvents: 3}); err != nil {
			t.Errorf("format %v: Stats = %v, want nil", format, err)
		}
		if !sink.Active() {
			t.Errorf("format %v: sink should stay active for the file target", format)
		}
		if err := fileOnly.Stats(model.StreamStats{DroppedEvents: 3}); err != nil {
			t.Fatalf("format %v: file-only Stats: %v", format, err)
		}
		if file.String() != healthy.String() {
			t.Errorf("format %v: file = %q, want %q", format, file.String(), healthy.String())
		}
	}
}

func TestRecordSinkStdoutEPIPEOnlyTargetInactive(t *testing.T) {
	sink := newRecordSink(render.New(render.FormatTable, render.Options{}), epipeWriter{}, nil)
	for _, ev := range sinkTestEvents() {
		if err := sink.Event(ev); err != nil {
			t.Fatalf("Event: %v", err)
		}
		if !sink.Active() {
			break
		}
	}
	if sink.Active() {
		t.Error("sink is still active after stdout EPIPE")
	}
	if err := sink.Event(sinkTestEvents()[0]); err != nil {
		t.Errorf("Event after EPIPE = %v, want nil", err)
	}
	if err := sink.Close(); err != nil {
		t.Errorf("Close = %v, want nil", err)
	}
}

func TestRecordSinkFileWriteError(t *testing.T) {
	want := errors.New("disk full")
	var stdout bytes.Buffer
	sink := newRecordSink(render.New(render.FormatJSON, render.Options{}), &stdout, failWriter{want})
	if err := sink.Event(sinkTestEvents()[0]); !errors.Is(err, want) {
		t.Errorf("Event = %v, want %v", err, want)
	}
	if err := sink.Stats(model.StreamStats{DroppedEvents: 1}); !errors.Is(err, want) {
		t.Errorf("Stats = %v, want %v", err, want)
	}
}

func TestRecordSinkCloseFlushes(t *testing.T) {
	var out bytes.Buffer
	sink := newRecordSink(render.New(render.FormatJSON, render.Options{}), &out, nil)
	if _, err := sink.targets[0].w.Write([]byte("tail\n")); err != nil {
		t.Fatalf("buffer write: %v", err)
	}
	if out.Len() != 0 {
		t.Fatal("data flushed before Close")
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := out.String(); got != "tail\n" {
		t.Errorf("out = %q, want tail", got)
	}
}

func TestRecordSinkCloseFlushError(t *testing.T) {
	want := errors.New("flush failed")
	sink := newRecordSink(render.New(render.FormatJSON, render.Options{}), nil, nil)
	sink.targets = append(sink.targets, &recordTarget{w: bufio.NewWriter(failWriter{want})})
	if _, err := sink.targets[0].w.Write([]byte("tail\n")); err != nil {
		t.Fatalf("buffer write: %v", err)
	}
	if err := sink.Close(); !errors.Is(err, want) {
		t.Errorf("Close = %v, want %v", err, want)
	}
}

func TestRecordSinkNilTargets(t *testing.T) {
	sink := newRecordSink(render.New(render.FormatJSON, render.Options{}), nil, nil)
	if sink.Active() {
		t.Error("sink without targets is active")
	}
	if err := sink.Event(sinkTestEvents()[0]); err != nil {
		t.Errorf("Event = %v, want nil", err)
	}
	if err := sink.Stats(model.StreamStats{DroppedEvents: 1}); err != nil {
		t.Errorf("Stats = %v, want nil", err)
	}
	if err := sink.Close(); err != nil {
		t.Errorf("Close = %v, want nil", err)
	}
}

// 触发 stdout EPIPE 的事件不计入 table 结束汇总。
func TestRunEventsStdoutEPIPEDoesNotCountReceived(t *testing.T) {
	svcs := api.Services{Events: fakeEventService{
		subscribe: func(context.Context, model.RuntimeSelector,
			[]model.EventType) (api.EventStream, error) {
			return testEventStream(), nil
		},
	}}
	var errOut bytes.Buffer
	err := runEvents(context.Background(), eventsRun{
		Out:      epipeWriter{},
		ErrOut:   &errOut,
		Renderer: render.New(render.FormatTable, render.Options{}),
		Format:   render.FormatTable,
		Service:  svcs.Events,
	})
	if err != nil {
		t.Fatalf("runEvents = %v, want nil", err)
	}
	if want := "events: 0 received, 0 dropped\n"; errOut.String() != want {
		t.Errorf("stderr = %q, want %q", errOut.String(), want)
	}
}
