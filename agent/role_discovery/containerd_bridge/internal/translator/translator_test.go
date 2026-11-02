package translator

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	apievents "github.com/containerd/containerd/api/events"
	"github.com/containerd/typeurl/v2"

	"honeyghost/containerd_bridge/internal/protocol"
	"honeyghost/containerd_bridge/internal/source"
)

// recorded 按 containerd 的真实封装构造一条事件：载荷是 api 侧生成的 proto，
// 外层是带 namespace 与时刻的信封。测试样本与线上流同形。
func recorded(t *testing.T, namespace, topic string, payload any) *source.Envelope {
	t.Helper()
	packed, err := typeurl.MarshalAny(payload)
	if err != nil {
		t.Fatalf("封装事件载荷失败: %v", err)
	}
	return &source.Envelope{
		Namespace: namespace,
		Topic:     topic,
		Event:     packed,
		Timestamp: time.Unix(1700000000, 123),
	}
}

type fakeContainers struct {
	containers map[string]source.Container
	err        error
	calls      int
}

func (f *fakeContainers) GetContainer(
	_ context.Context, _, id string,
) (source.Container, error) {
	f.calls++
	if f.err != nil {
		return source.Container{}, f.err
	}
	container, ok := f.containers[id]
	if !ok {
		return source.Container{}, errors.New("容器不存在")
	}
	return container, nil
}

// k8sContainer 是一份录自真实环境的 CRI 容器：标签齐备。
func k8sContainer() source.Container {
	return source.Container{
		ID:    "1a2b3c",
		Image: "registry.k8s.io/pause:3.10",
		Labels: map[string]string{
			LabelPodUID:              "b1f0-pod-uid",
			LabelPodName:             "nginx-7d9c",
			LabelPodNamespace:        "prod",
			LabelContainerName:       "nginx",
			"io.cri-containerd.kind": "container",
		},
	}
}

func TestDecodeTaskTopics(t *testing.T) {
	cases := []struct {
		name    string
		payload any
		kind    EventKind
	}{
		{"启动", &apievents.TaskStart{ContainerID: "c1", Pid: 42}, KindUpsert},
		{"退出", &apievents.TaskExit{ContainerID: "c1", Pid: 42, ExitStatus: 137}, KindRemove},
		{"OOM", &apievents.TaskOOM{ContainerID: "c1"}, KindOOM},
	}
	for _, c := range cases {
		got, err := Decode(recorded(t, "k8s.io", source.TopicStart, c.payload))
		if err != nil {
			t.Fatalf("%s: 解码失败: %v", c.name, err)
		}
		if got.Kind != c.kind {
			t.Fatalf("%s: 类型=%v 期望=%v", c.name, got.Kind, c.kind)
		}
		if got.Namespace != "k8s.io" || got.TimestampNs != time.Unix(1700000000, 123).UnixNano() {
			t.Fatalf("%s: 信封字段未透传: %+v", c.name, got)
		}
	}
}

func TestDecodeIgnoresUnrelatedPayload(t *testing.T) {
	// 订阅之外的主题（这里用 TaskCreate 代表）不得被当成未知错误中断整条流：
	// 解码失败由调用方记录后跳过
	env := recorded(t, "k8s.io", "/tasks/create",
		&apievents.TaskCreate{ContainerID: "c1", Pid: 42})
	if _, err := Decode(env); err == nil {
		t.Fatal("未订阅的载荷应解码失败")
	}
}

// badPayload 的 typeURL 指向不存在的类型：模拟对端给了本进程不认识的载荷
type badPayload struct{}

func (badPayload) GetTypeUrl() string { return "type.googleapis.com/nonexistent" }
func (badPayload) GetValue() []byte   { return []byte{0xff} }

func TestDecodeBadPayload(t *testing.T) {
	env := &source.Envelope{
		Namespace: "k8s.io",
		Topic:     source.TopicStart,
		Event:     badPayload{},
		Timestamp: time.Now(),
	}
	if _, err := Decode(env); err == nil {
		t.Fatal("无法解析的载荷应解码失败")
	}
}

func TestTranslateUpsertKeepsCRIFields(t *testing.T) {
	containers := &fakeContainers{containers: map[string]source.Container{"1a2b3c": k8sContainer()}}
	observation, err := New(containers).Translate(context.Background(), Decoded{
		Kind:        KindUpsert,
		Namespace:   "k8s.io",
		ContainerID: "1a2b3c",
		Pid:         4242,
		TimestampNs: 99,
	})
	if err != nil {
		t.Fatalf("翻译失败: %v", err)
	}

	if observation.GetKind() != protocol.Observation_UPSERT {
		t.Fatalf("类型=%v", observation.GetKind())
	}
	if observation.GetPid() != 4242 || observation.GetContainerId() != "1a2b3c" {
		t.Fatalf("实例键与锚点不符: %+v", observation)
	}
	if observation.GetPodUid() != "b1f0-pod-uid" ||
		observation.GetPodName() != "nginx-7d9c" ||
		observation.GetPodNamespace() != "prod" ||
		observation.GetContainerName() != "nginx" {
		t.Fatalf("Pod 聚类字段未从 CRI 标签取出: %+v", observation)
	}
	if observation.GetImage() != "registry.k8s.io/pause:3.10" {
		t.Fatalf("镜像未透传: %+v", observation)
	}
	if observation.GetLabels()["io.cri-containerd.kind"] != "container" {
		t.Fatalf("标签应原样透传: %+v", observation.GetLabels())
	}
	if observation.GetInSnapshot() {
		t.Fatal("in_snapshot 由调用方按来源标注，翻译层不该置位")
	}
}

func TestTranslateNonK8sContainerHasEmptyPodFields(t *testing.T) {
	// docker / ctr 创建的容器没有 CRI 标签，Pod 聚类字段留空，镜像仍透传
	containers := &fakeContainers{containers: map[string]source.Container{
		"9f8e": {ID: "9f8e", Image: "docker.io/library/nginx:1.27"},
	}}
	observation, err := New(containers).Translate(context.Background(), Decoded{
		Kind: KindUpsert, Namespace: "moby", ContainerID: "9f8e", Pid: 7,
	})
	if err != nil {
		t.Fatalf("翻译失败: %v", err)
	}
	if observation.GetPodUid() != "" || observation.GetContainerName() != "" {
		t.Fatalf("非 k8s 容器不应有 Pod 聚类字段: %+v", observation)
	}
	if observation.GetImage() != "docker.io/library/nginx:1.27" {
		t.Fatalf("镜像未透传: %+v", observation)
	}
}

func TestTranslateRemoveCarriesOnlyInstanceKey(t *testing.T) {
	// 退出时源侧已经查不到属性了：不回查、只带实例键
	containers := &fakeContainers{err: errors.New("容器已不存在")}
	observation, err := New(containers).Translate(context.Background(), Decoded{
		Kind: KindRemove, Namespace: "k8s.io", ContainerID: "gone", Pid: 42,
	})
	if err != nil {
		t.Fatalf("退出翻译不应依赖回查: %v", err)
	}
	if observation.GetKind() != protocol.Observation_REMOVE {
		t.Fatalf("类型=%v", observation.GetKind())
	}
	if observation.GetContainerId() != "gone" || observation.GetPid() != 0 {
		t.Fatalf("退出观察只应带实例键: %+v", observation)
	}
	if containers.calls != 0 {
		t.Fatal("退出不应回查元数据")
	}
}

func TestTranslateUpsertFailureIsAnError(t *testing.T) {
	// 取不到元数据既不是「存在」也不是「不存在」，必须是错误，由调用方重试
	containers := &fakeContainers{err: errors.New("网络抖动")}
	_, err := New(containers).Translate(context.Background(), Decoded{
		Kind: KindUpsert, Namespace: "k8s.io", ContainerID: "c1", Pid: 42,
	})
	if err == nil {
		t.Fatal("回查失败应返回错误")
	}
	if !strings.Contains(err.Error(), "c1") {
		t.Fatalf("错误应指出是哪个容器: %v", err)
	}
}

func TestTranslateOOMProducesNothing(t *testing.T) {
	observation, err := New(&fakeContainers{}).Translate(context.Background(),
		Decoded{Kind: KindOOM, Namespace: "k8s.io", ContainerID: "c1"})
	if err != nil || observation != nil {
		t.Fatalf("OOM 只记日志，不应产出观察量: %v %v", observation, err)
	}
}
