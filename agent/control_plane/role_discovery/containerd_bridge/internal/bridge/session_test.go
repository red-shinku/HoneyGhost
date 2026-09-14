package bridge

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	apievents "github.com/containerd/containerd/api/events"
	"github.com/containerd/typeurl/v2"

	"honeyghost/containerd_bridge/internal/protocol"
	"honeyghost/containerd_bridge/internal/source"
)

// ============================================================
// 替身：containerd 侧与 C++ 侧
// ============================================================

type fakeSubscription struct {
	events chan *source.Envelope
	errs   chan error
}

// fakeSource 是 containerd 的替身。会话看到的接口与真实接入面用法一致。
type fakeSource struct {
	mu sync.Mutex

	namespaces []string
	tasks      map[string][]source.Task
	containers map[string]source.Container
	listErr    map[string]error
	listGate   map[string]chan struct{}
	subs       map[string]*fakeSubscription
}

func newFakeSource(namespaces ...string) *fakeSource {
	return &fakeSource{
		namespaces: namespaces,
		tasks:      make(map[string][]source.Task),
		containers: make(map[string]source.Container),
		listErr:    make(map[string]error),
		listGate:   make(map[string]chan struct{}),
		subs:       make(map[string]*fakeSubscription),
	}
}

func (f *fakeSource) withTask(namespace, id string, pid uint32) *fakeSource {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tasks[namespace] = append(f.tasks[namespace], source.Task{ID: id, Pid: pid})
	f.containers[namespace+"/"+id] = source.Container{
		ID: id, Image: "registry.k8s.io/" + id + ":1.0",
		Labels: map[string]string{
			"io.kubernetes.container.name": id,
			"io.kubernetes.pod.name":       "pod-" + id,
		},
	}
	return f
}

func (f *fakeSource) BackendVersion() string { return "2.2.4-test" }

func (f *fakeSource) Namespaces(context.Context) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.namespaces...), nil
}

func (f *fakeSource) dropNamespace(namespace string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	kept := f.namespaces[:0]
	for _, ns := range f.namespaces {
		if ns != namespace {
			kept = append(kept, ns)
		}
	}
	f.namespaces = kept
}

func (f *fakeSource) ListTasks(_ context.Context, namespace string) ([]source.Task, error) {
	f.mu.Lock()
	gate := f.listGate[namespace]
	err := f.listErr[namespace]
	tasks := append([]source.Task(nil), f.tasks[namespace]...)
	f.mu.Unlock()

	if gate != nil {
		<-gate // 枚举期间挂住，供测试构造「段内到达流内事件」的时序
	}
	return tasks, err
}

func (f *fakeSource) GetContainer(_ context.Context, namespace, id string) (source.Container, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	container, ok := f.containers[namespace+"/"+id]
	if !ok {
		return source.Container{}, errors.New("容器不存在")
	}
	return container, nil
}

func (f *fakeSource) Subscribe(
	_ context.Context, namespace string, _ ...string,
) (<-chan *source.Envelope, <-chan error) {
	sub := &fakeSubscription{
		events: make(chan *source.Envelope, 32),
		errs:   make(chan error, 1),
	}
	f.mu.Lock()
	f.subs[namespace] = sub
	f.mu.Unlock()
	return sub.events, sub.errs
}

func (f *fakeSource) Close() error { return nil }

func (f *fakeSource) subscription(t *testing.T, namespace string) *fakeSubscription {
	t.Helper()
	for range 3000 {
		f.mu.Lock()
		sub := f.subs[namespace]
		f.mu.Unlock()
		if sub != nil {
			return sub
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("等不到 %s 的订阅", namespace)
	return nil
}

func envelope(t *testing.T, namespace, topic string, payload any) *source.Envelope {
	t.Helper()
	packed, err := typeurl.MarshalAny(payload)
	if err != nil {
		t.Fatalf("封装事件失败: %v", err)
	}
	return &source.Envelope{
		Namespace: namespace, Topic: topic, Event: packed, Timestamp: time.Now(),
	}
}

func (f *fakeSource) pushUpsert(t *testing.T, namespace, id string, pid uint32) {
	t.Helper()
	f.mu.Lock()
	if _, ok := f.containers[namespace+"/"+id]; !ok {
		f.containers[namespace+"/"+id] = source.Container{
			ID: id, Image: "registry.k8s.io/" + id + ":1.0",
		}
	}
	f.mu.Unlock()
	f.subscription(t, namespace).events <- envelope(t, namespace, source.TopicStart,
		&apievents.TaskStart{ContainerID: id, Pid: pid})
}

func (f *fakeSource) pushRemove(t *testing.T, namespace, id string) {
	t.Helper()
	f.subscription(t, namespace).events <- envelope(t, namespace, source.TopicExit,
		&apievents.TaskExit{ContainerID: id, Pid: 0})
}

func (f *fakeSource) failStream(t *testing.T, namespace string, err error) {
	t.Helper()
	f.subscription(t, namespace).errs <- err
}

// recordingWriter 记录会话写出的帧，形如 "BEGIN(k8s.io)"、"UPSERT(a,in,pid=42)"。
type recordingWriter struct {
	mu     sync.Mutex
	frames []string
}

func (w *recordingWriter) Send(frame *protocol.Frame) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.frames = append(w.frames, describeFrame(frame))
	return nil
}

func (w *recordingWriter) written() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]string(nil), w.frames...)
}

// waitFrames 等到至少 n 帧写出，返回此刻的全部帧。
func (w *recordingWriter) waitFrames(t *testing.T, n int) []string {
	t.Helper()
	for range 3000 {
		if frames := w.written(); len(frames) >= n {
			return frames
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("等不到 %d 帧，现有 %v", n, w.written())
	return nil
}

// waitUntil 等到帧序列满足条件，返回此刻的全部帧。
func (w *recordingWriter) waitUntil(t *testing.T, why string, ok func([]string) bool) []string {
	t.Helper()
	for range 3000 {
		if frames := w.written(); ok(frames) {
			return frames
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("等不到「%s」，现有 %v", why, w.written())
	return nil
}

func describeFrame(frame *protocol.Frame) string {
	switch body := frame.GetBody().(type) {
	case *protocol.Frame_SnapshotBegin:
		return fmt.Sprintf("BEGIN(%s)", strings.Join(body.SnapshotBegin.GetNamespaces(), ","))
	case *protocol.Frame_Observation:
		observation := body.Observation
		switch observation.GetKind() {
		case protocol.Observation_REMOVE:
			return fmt.Sprintf("REMOVE(%s)", observation.GetContainerId())
		default:
			origin := "live"
			if observation.GetInSnapshot() {
				origin = "snap"
			}
			return fmt.Sprintf("UPSERT(%s,%s,%s,pid=%d)", observation.GetContainerId(),
				observation.GetNamespace(), origin, observation.GetPid())
		}
	case *protocol.Frame_SnapshotEnd:
		return fmt.Sprintf("END(%d)", body.SnapshotEnd.GetCount())
	}
	return "?"
}

// ============================================================
// 会话
// ============================================================

// startSession 起一个会话，返回出口与停止函数。
func startSession(t *testing.T, cfg Config, backend *fakeSource) *recordingWriter {
	t.Helper()
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	if cfg.BackoffBase == 0 {
		cfg.BackoffBase = time.Millisecond
	}
	if cfg.BackoffMax == 0 {
		cfg.BackoffMax = 5 * time.Millisecond
	}
	if cfg.MetadataAttempts == 0 {
		cfg.MetadataAttempts = 2
	}
	if cfg.MetadataRetryDelay == 0 {
		cfg.MetadataRetryDelay = time.Millisecond
	}
	if cfg.NamespacePollInterval == 0 {
		cfg.NamespacePollInterval = time.Hour
	}

	writer := &recordingWriter{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	session := NewSession(cfg, writer).WithDial(
		func(context.Context) (source.Source, error) { return backend, nil })
	go func() {
		defer close(done)
		session.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("会话没有在停止请求后退出")
		}
	})
	return writer
}

func expectFrames(t *testing.T, got []string, want ...string) {
	t.Helper()
	if len(got) < len(want) {
		t.Fatalf("帧数不足: 实际 %v 期望以 %v 开头", got, want)
	}
	for i, frame := range want {
		if got[i] != frame {
			t.Fatalf("第 %d 帧=%s 期望=%s（全部 %v）", i, got[i], frame, got)
		}
	}
}

// 快照段：先建流、后枚举、逐 namespace 成段，段内的枚举项标 in_snapshot
func TestSessionEmitsSnapshotSegment(t *testing.T) {
	backend := newFakeSource("k8s.io").withTask("k8s.io", "a", 42).
		withTask("k8s.io", "b", 7)
	writer := startSession(t, Config{Namespaces: []string{"k8s.io"}}, backend)

	expectFrames(t, writer.waitFrames(t, 4),
		"BEGIN(k8s.io)",
		"UPSERT(a,k8s.io,snap,pid=42)",
		"UPSERT(b,k8s.io,snap,pid=7)",
		"END(2)",
	)
}

// 段内到达的流内事件必须排在 SnapshotEnd 之后：否则段内停止的角色会被读成
// 加入，产出永不修正的幽灵角色
func TestSessionBuffersStreamEventsUntilSegmentEnds(t *testing.T) {
	backend := newFakeSource("k8s.io").withTask("k8s.io", "a", 42)
	backend.listGate["k8s.io"] = make(chan struct{})

	writer := startSession(t, Config{Namespaces: []string{"k8s.io"}}, backend)
	writer.waitFrames(t, 1) // BEGIN 已发出，枚举还挂在门上

	// 枚举期间容器 live 启动：此时它只能滞留在合并通道里
	backend.pushUpsert(t, "k8s.io", "live", 99)
	time.Sleep(20 * time.Millisecond)
	expectFrames(t, writer.written(), "BEGIN(k8s.io)")

	close(backend.listGate["k8s.io"])
	expectFrames(t, writer.waitFrames(t, 4),
		"BEGIN(k8s.io)",
		"UPSERT(a,k8s.io,snap,pid=42)",
		"END(1)",
		"UPSERT(live,k8s.io,live,pid=99)",
	)
}

// 流内事件：快照段收场后才放行，退出只带实例键
func TestSessionEmitsLiveEvents(t *testing.T) {
	backend := newFakeSource("k8s.io").withTask("k8s.io", "a", 42)
	writer := startSession(t, Config{Namespaces: []string{"k8s.io"}}, backend)
	writer.waitFrames(t, 3)

	backend.pushUpsert(t, "k8s.io", "c", 7)
	backend.pushRemove(t, "k8s.io", "a")

	expectFrames(t, writer.waitFrames(t, 5),
		"BEGIN(k8s.io)",
		"UPSERT(a,k8s.io,snap,pid=42)",
		"END(1)",
		"UPSERT(c,k8s.io,live,pid=7)",
		"REMOVE(a)",
	)
}

// 枚举任一步失败即整段作废：不发 SnapshotEnd，C++ 侧不结算
func TestSessionVoidsSegmentOnEnumerationFailure(t *testing.T) {
	backend := newFakeSource("k8s.io").withTask("k8s.io", "a", 42)
	delete(backend.containers, "k8s.io/a") // 逐项回查失败
	writer := startSession(t, Config{Namespaces: []string{"k8s.io"}}, backend)

	// 段开了场却没有收场，重走时再开一场
	writer.waitUntil(t, "两次开场且无收场", func(frames []string) bool {
		begins := 0
		for _, frame := range frames {
			if strings.HasPrefix(frame, "BEGIN(") {
				begins++
			}
			if strings.HasPrefix(frame, "END(") {
				return false
			}
		}
		return begins >= 2
	})
}

// namespace 配置了但后端没有：发零项段清除其残留条目，且不订阅它
func TestSessionRetiresNamespaceAbsentFromBackend(t *testing.T) {
	backend := newFakeSource("k8s.io").withTask("k8s.io", "a", 42)
	writer := startSession(t,
		Config{Namespaces: []string{"k8s.io", "moby"}}, backend)

	expectFrames(t, writer.waitFrames(t, 5),
		"BEGIN(moby)",
		"END(0)",
		"BEGIN(k8s.io)",
		"UPSERT(a,k8s.io,snap,pid=42)",
		"END(1)",
	)
}

// 运行期 namespace 消失：核对到之后发零项段
func TestSessionRetiresNamespaceAtRuntime(t *testing.T) {
	backend := newFakeSource("k8s.io", "moby").withTask("k8s.io", "a", 42).
		withTask("moby", "b", 7)
	writer := startSession(t, Config{
		Namespaces:            []string{"k8s.io", "moby"},
		NamespacePollInterval: 5 * time.Millisecond,
	}, backend)
	writer.waitFrames(t, 6)

	backend.dropNamespace("moby")
	writer.waitUntil(t, "moby 的零项段", func(frames []string) bool {
		for i, frame := range frames {
			if frame == "BEGIN(moby)" && i+1 < len(frames) && frames[i+1] == "END(0)" {
				return true
			}
		}
		return false
	})
}

// 订阅流断开：会话重连后端、重新订阅、重走快照
func TestSessionReconnectsAfterStreamFailure(t *testing.T) {
	backend := newFakeSource("k8s.io").withTask("k8s.io", "a", 42)
	writer := startSession(t, Config{Namespaces: []string{"k8s.io"}}, backend)
	writer.waitFrames(t, 3)

	backend.failStream(t, "k8s.io", errors.New("连接被对端关闭"))

	writer.waitUntil(t, "重走一次快照段", func(frames []string) bool {
		return strings.Count(strings.Join(frames, " "), "BEGIN(k8s.io)") >= 2 &&
			strings.Count(strings.Join(frames, " "), "END(1)") >= 2
	})
}
