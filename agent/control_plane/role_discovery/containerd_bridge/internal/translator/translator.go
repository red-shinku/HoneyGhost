// Package translator 把 containerd 事件与容器元数据翻成协议观察量。
//
// 本包是纯翻译层：不订阅、不枚举、不判断角色是否加入退出。判断加入/退出在
// C++ 侧的状态表里，本包只负责把源侧的事实表达成协议消息。
package translator

import (
	"context"
	"fmt"

	apievents "github.com/containerd/containerd/api/events"
	"github.com/containerd/typeurl/v2"

	"honeyghost/containerd_bridge/internal/protocol"
	"honeyghost/containerd_bridge/internal/source"
)

// CRI 在容器对象上打的标签。Pod 聚类信息与容器名都取自这里；非 k8s 容器
// （docker、ctr 创建）没有这些标签，相应字段为空。
const (
	LabelPodUID        = "io.kubernetes.pod.uid"
	LabelPodName       = "io.kubernetes.pod.name"
	LabelPodNamespace  = "io.kubernetes.pod.namespace"
	LabelContainerName = "io.kubernetes.container.name"
)

// EventKind 是订阅到的主题的语义分类。
type EventKind int

const (
	// KindOOM 是 /tasks/oom：主进程被 OOM killer 打死。进程退出另有 exit 事件，
	// 本类只记日志，不产生观察量。
	KindOOM EventKind = iota
	// KindUpsert 是 /tasks/start。
	KindUpsert
	// KindRemove 是 /tasks/exit。
	KindRemove
)

func (k EventKind) String() string {
	switch k {
	case KindUpsert:
		return "UPSERT"
	case KindRemove:
		return "REMOVE"
	case KindOOM:
		return "OOM"
	default:
		return "UNKNOWN"
	}
}

// Decoded 是一条已脱离 typeurl 封装的事件。
type Decoded struct {
	Kind        EventKind
	Namespace   string
	ContainerID string
	Pid         uint32
	ExitStatus  uint32
	TimestampNs int64
}

// Decode 按载荷类型解出一条事件，主题字符串不参与判定。
//
// 解析失败即返回错误：一条坏消息只影响它自己，调用方记录后跳过，
// 不得中断该 namespace 的流。
func Decode(env *source.Envelope) (Decoded, error) {
	payload, err := typeurl.UnmarshalAny(env.Event)
	if err != nil {
		return Decoded{}, fmt.Errorf("解析事件载荷失败: %w", err)
	}

	decoded := Decoded{
		Namespace:   env.Namespace,
		TimestampNs: env.Timestamp.UnixNano(),
	}
	switch event := payload.(type) {
	case *apievents.TaskStart:
		decoded.Kind = KindUpsert
		decoded.ContainerID = event.GetContainerID()
		decoded.Pid = event.GetPid()
	case *apievents.TaskExit:
		decoded.Kind = KindRemove
		decoded.ContainerID = event.GetContainerID()
		decoded.Pid = event.GetPid()
		decoded.ExitStatus = event.GetExitStatus()
	case *apievents.TaskOOM:
		decoded.Kind = KindOOM
		decoded.ContainerID = event.GetContainerID()
	default:
		return Decoded{}, fmt.Errorf("未知事件类型: %T", payload)
	}
	return decoded, nil
}

// ContainerGetter 是回查容器元数据所需的最小接口。
type ContainerGetter interface {
	GetContainer(ctx context.Context, namespace, id string) (source.Container, error)
}

// Translator 组装协议观察量。
type Translator struct {
	containers ContainerGetter
}

// New 构造翻译器。
func New(containers ContainerGetter) *Translator {
	return &Translator{containers: containers}
}

// Translate 把一条已解码的事件翻成协议观察量。
//
// 返回 nil 表示该事件不产生观察量（OOM 只记日志）。
// UPSERT 需要回查容器标签，回查失败即返回错误——调用方不得把「取不到」读成
// 「不存在」，只能按未知处理。
// 观察量的 in_snapshot 由调用方按来源标注：枚举得来的项与流内项在这里无法区分。
func (t *Translator) Translate(ctx context.Context, d Decoded) (*protocol.Observation, error) {
	switch d.Kind {
	case KindUpsert:
		container, err := t.containers.GetContainer(ctx, d.Namespace, d.ContainerID)
		if err != nil {
			return nil, fmt.Errorf("回查容器 %s 元数据失败: %w", d.ContainerID, err)
		}
		return &protocol.Observation{
			Kind:          protocol.Observation_UPSERT,
			ContainerId:   d.ContainerID,
			Pid:           d.Pid,
			Namespace:     d.Namespace,
			PodUid:        container.Labels[LabelPodUID],
			PodName:       container.Labels[LabelPodName],
			PodNamespace:  container.Labels[LabelPodNamespace],
			ContainerName: container.Labels[LabelContainerName],
			Image:         container.Image,
			Labels:        container.Labels,
			TimestampNs:   d.TimestampNs,
		}, nil
	case KindRemove:
		// 退出时源侧本来就查不到属性了，只带实例键
		return &protocol.Observation{
			Kind:        protocol.Observation_REMOVE,
			ContainerId: d.ContainerID,
			TimestampNs: d.TimestampNs,
		}, nil
	default:
		return nil, nil
	}
}
