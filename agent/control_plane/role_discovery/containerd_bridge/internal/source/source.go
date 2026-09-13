// Package source 是翻译进程与 containerd 之间的接入面。
//
// 只暴露发现角色所需的操作，两个理由：会话逻辑（快照段装配、段内事件缓冲、
// 重连与作废）可以用替身完整覆盖；containerd 客户端版本的耦合面收缩到本包。
//
// namespace 一律作为显式参数传入，由本包翻译成 containerd 的 context 约定。
package source

import (
	"context"

	coreevents "github.com/containerd/containerd/v2/core/events"
)

// Envelope 是 containerd 事件的外层封装，别名出来供上层免于记住包路径。
type Envelope = coreevents.Envelope

// Task 是一个运行中的 task，即容器的主进程。ID 是容器 ID。
type Task struct {
	ID  string
	Pid uint32
}

// Container 是容器的元数据，标签与镜像都取自 containerd 侧的容器对象。
type Container struct {
	ID     string
	Image  string
	Labels map[string]string
}

// Source 是一次后端连接。会话在每次重连时重新 Dial，不复用旧连接。
type Source interface {
	// BackendVersion 是后端版本，随协议一起上报，仅供日志与校验。
	BackendVersion() string

	// Namespaces 列出此刻存在的全部 namespace。
	// 它是「某 namespace 是否还在」这一事实的权威来源：删掉 namespace 不会
	// 让该 namespace 上的事件流报错。
	Namespaces(ctx context.Context) ([]string, error)

	// Subscribe 订阅一个 namespace 上的事件主题。
	// 返回事件通道与错误通道，两者都不由调用方关闭；ctx 结束或流断开时错误
	// 通道收到一条错误后关闭。
	Subscribe(ctx context.Context, namespace string, topics ...string) (<-chan *Envelope, <-chan error)

	// ListTasks 枚举该 namespace 中运行中的 task。
	// 这就是快照的权威集：Containers.List 含已停止但未删除的容器，据它构造
	// 权威集会让这些容器被判「本段已见」而永不退出。
	ListTasks(ctx context.Context, namespace string) ([]Task, error)

	// GetContainer 回查容器元数据。取不到即返回错误，调用方按「未知」处理。
	GetContainer(ctx context.Context, namespace, id string) (Container, error)

	// Close 释放连接。
	Close() error
}
