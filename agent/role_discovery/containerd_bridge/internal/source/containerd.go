package source

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	tasksapi "github.com/containerd/containerd/api/services/tasks/v1"
	"github.com/containerd/containerd/api/types/task"
	"github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/pkg/namespaces"
)

// TopicStart / TopicExit / TopicOOM 是本进程订阅的三个主题。
//
// 不订阅 /containers/delete：容器对象在进程退出后可能长期保留，删对象与进程
// 退出是两件事，据它判退出会漏掉「进程已死、对象还在」的容器。
const (
	TopicStart = "/tasks/start"
	TopicExit  = "/tasks/exit"
	TopicOOM   = "/tasks/oom"
)

// Topics 是会话使用的订阅主题全集。
var Topics = []string{TopicStart, TopicExit, TopicOOM}

// subscribeFilters 把主题列表拼成订阅过滤串，一个主题一个串。
//
// 三条均为实测（containerd v2.2.4）：
//   - 裸主题（如 /tasks/start）会被当成表达式解析，报 invalid quote；
//   - 值改用反引号能通过解析，但**永不匹配**——引号被当成了值的一部分；
//   - 逗号是 AND（filters 包的语法），故多个主题不能写进一个串里。
//
// 因此值用双引号（Go 字符串字面量语法），多个主题并列成多个串：containerd 用
// ParseAll 取或，它的 CRI 侧订阅也是这么写的。
func subscribeFilters(topics []string) []string {
	filters := make([]string, 0, len(topics))
	for _, topic := range topics {
		filters = append(filters, `topic=="`+topic+`"`)
	}
	return filters
}

// Options 是后端连接的构造选项。
type Options struct {
	// DockerSocket 是 Docker API 的 socket 路径；空表示不查询 Docker。
	DockerSocket string
	// DockerNamespaces 列出 Docker 管理的 containerd namespace；空表示不限定。
	DockerNamespaces []string
	// Log 是日志出口，为空则用默认出口。
	Log *slog.Logger
}

// Dial 连上 containerd 并确认其已就绪。
//
// 就绪判据不可省：containerd 的 grpc 连接是惰性建立的，socket 不存在时
// Dial 也会成功，随后把「连不上」表现为空枚举——空枚举一旦被当成权威，
// 全部存活容器都会被对账掉。故此处先向 health 服务要一次 SERVING。
func Dial(ctx context.Context, address string, opts Options) (Source, error) {
	c, err := client.New(address)
	if err != nil {
		return nil, fmt.Errorf("建立 containerd 客户端失败: %w", err)
	}

	serving, err := c.IsServing(ctx)
	if err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("探测 containerd 就绪失败: %w", err)
	}
	if !serving {
		_ = c.Close()
		return nil, errors.New("containerd 未就绪")
	}

	version, err := c.Version(ctx)
	if err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("取 containerd 版本失败: %w", err)
	}

	return &containerdSource{
		client:  c,
		version: version.Version,
		images:  newImageResolver(opts.DockerSocket, opts.DockerNamespaces, opts.Log),
	}, nil
}

type containerdSource struct {
	client  *client.Client
	version string
	images  *imageResolver
}

func (s *containerdSource) BackendVersion() string { return s.version }

func (s *containerdSource) Namespaces(ctx context.Context) ([]string, error) {
	return s.client.NamespaceService().List(ctx)
}

func (s *containerdSource) Subscribe(
	ctx context.Context, namespace string, topics ...string,
) (<-chan *Envelope, <-chan error) {
	return s.client.Subscribe(namespaces.WithNamespace(ctx, namespace),
		subscribeFilters(topics)...)
}

func (s *containerdSource) ListTasks(ctx context.Context, namespace string) ([]Task, error) {
	resp, err := s.client.TaskService().List(
		namespaces.WithNamespace(ctx, namespace), &tasksapi.ListTasksRequest{})
	if err != nil {
		return nil, err
	}

	tasks := make([]Task, 0, len(resp.GetTasks()))
	for _, process := range resp.GetTasks() {
		if !alive(process.GetStatus()) || process.GetID() == "" {
			continue
		}
		// 取 ID 而不是 ContainerID：List 的转换只填 ID（实测 v2.2.4，ContainerID
		// 恒为空串）。task 的 ID 与容器 ID 是同一个值——事件侧给的是后者
		// （TaskStart.ContainerID），两处必须落在同一个实例键上。
		tasks = append(tasks, Task{ID: process.GetID(), Pid: process.GetPid()})
	}
	return tasks, nil
}

// alive 报告该 task 的主进程是否还在。
//
// List 返回的是本 namespace 的全部 task，含已停止但未删除的（实测：ctr 默认不删，
// 本机 default 命名空间就常驻若干 STOPPED 的 task）。据它构造权威集会让这些容器
// 被判「本段已见」而永不退出，成为幽灵。
//
// 只排除确定没有主进程的两态：未启动（CREATED）与已退出（STOPPED）。未知态留在
// 权威集里——把「不知道」当成「不存在」会产出幻影退出，而幻影退出不可撤回，宁可
// 留幽灵等下一次对账。
func alive(status task.Status) bool {
	return status != task.Status_CREATED && status != task.Status_STOPPED
}

func (s *containerdSource) GetContainer(
	ctx context.Context, namespace, id string,
) (Container, error) {
	got, err := s.client.ContainerService().Get(
		namespaces.WithNamespace(ctx, namespace), id)
	if err != nil {
		return Container{}, err
	}
	return Container{
		ID:     got.ID,
		Image:  s.images.image(ctx, namespace, got),
		Labels: got.Labels,
	}, nil
}

func (s *containerdSource) Close() error {
	if s.images != nil {
		s.images.close()
	}
	return s.client.Close()
}
