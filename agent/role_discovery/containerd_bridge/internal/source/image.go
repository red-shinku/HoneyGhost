package source

// 容器镜像引用的补齐。
//
// containerd 的容器对象上 Image 是可选字段：ctr 与启用 containerd 镜像存储的
// Docker 会填，传统镜像存储（overlay2 graphdriver）的 Docker 不填。Docker 侧
// 的镜像引用只能回查 Docker 自己，故提供一条可选的 Docker API 旁路：只有配置了
// socket 且容器所在 namespace 被列入时才查。

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/containerd/containerd/v2/core/containers"
	"github.com/containerd/typeurl/v2"
)

const (
	// CRI 写在容器 OCI spec 注解里的镜像引用：普通容器与沙箱各一个。
	annotationImageName        = "io.kubernetes.cri.image-name"
	annotationSandboxImageName = "io.kubernetes.cri.podsandbox.image-name"

	// Docker API 回查的等待上限：取不到按未知处理，不得拖住快照段。
	dockerImageTimeout = 2 * time.Second
	// 回查结果的缓存上限：容器 ID 对应的镜像引用不会变，但容器会不断新建。
	dockerImageCacheLimit = 4096
)

// imageResolver 补齐容器镜像引用。
//
// 取第一个可得来源：容器对象的 Image、OCI spec 的 CRI 注解、Docker API。
// Docker 旁路只对 DockerNamespaces 中的 namespace 生效，列表为空表示不限定。
//
// 并发安全：cache 由 dockerImageClient 自行加锁，本类型其余字段只读。
type imageResolver struct {
	docker     *dockerImageClient
	namespaces map[string]bool
	log        *slog.Logger
}

// newImageResolver 构造补齐器。socket 为空表示不启用 Docker 旁路。
func newImageResolver(socket string, namespaces []string, log *slog.Logger) *imageResolver {
	if log == nil {
		log = slog.Default()
	}
	resolver := &imageResolver{log: log}
	if socket == "" {
		return resolver
	}
	resolver.docker = newDockerImageClient(socket)
	if len(namespaces) > 0 {
		resolver.namespaces = make(map[string]bool, len(namespaces))
		for _, namespace := range namespaces {
			resolver.namespaces[namespace] = true
		}
	}
	return resolver
}

// image 返回容器的镜像引用；所有来源都取不到时为空。
func (r *imageResolver) image(
	ctx context.Context, namespace string, container containers.Container,
) string {
	if container.Image != "" {
		return container.Image
	}
	if image := imageFromSpec(container.Spec); image != "" {
		return image
	}
	if r.docker == nil || !r.allows(namespace) {
		return ""
	}
	image, err := r.docker.image(ctx, container.ID)
	if err != nil {
		// 旁路失败只让镜像引用缺席，不能让元数据回查本身失败：失败会让调用方
		// 按「未知」重试并丢弃该容器
		r.log.Debug("failed to look up image via Docker API",
			"namespace", namespace, "container", container.ID, "err", err)
		return ""
	}
	return image
}

// close 释放 Docker 旁路的空闲连接。
func (r *imageResolver) close() {
	if r.docker != nil {
		r.docker.client.CloseIdleConnections()
	}
}

// allows 报告该 namespace 是否归 Docker 管。
func (r *imageResolver) allows(namespace string) bool {
	if len(r.namespaces) == 0 {
		return true
	}
	return r.namespaces[namespace]
}

// imageFromSpec 从容器 OCI spec 的 CRI 注解取镜像引用。
//
// CRI 不把镜像写进容器对象，而是写进 spec 注解：普通容器用 image-name，
// 沙箱（pause）容器用 podsandbox.image-name。spec 以 JSON 存储，解析失败
// 按取不到处理。
func imageFromSpec(spec typeurl.Any) string {
	if spec == nil {
		return ""
	}
	var parsed struct {
		Annotations map[string]string `json:"annotations"`
	}
	if err := json.Unmarshal(spec.GetValue(), &parsed); err != nil {
		return ""
	}
	if image := parsed.Annotations[annotationImageName]; image != "" {
		return image
	}
	return parsed.Annotations[annotationSandboxImageName]
}

// dockerImageClient 经 Unix socket 调 Docker API 回查容器镜像引用。
//
// Docker 的容器 ID 与 containerd 的实例键相同，故按 ID 直查
// /containers/<id>/json，取创建时指定的镜像引用（Config.Image）。
type dockerImageClient struct {
	client *http.Client

	mu    sync.Mutex
	cache map[string]string
}

// newDockerImageClient 构造回查客户端。socket 是 Docker 的 Unix socket 路径。
func newDockerImageClient(socket string) *dockerImageClient {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "unix", socket)
		},
	}
	return &dockerImageClient{
		client: &http.Client{Transport: transport, Timeout: dockerImageTimeout},
		cache:  make(map[string]string),
	}
}

// image 返回容器的镜像引用。容器不归该 Docker 管时返回空且无错误。
func (c *dockerImageClient) image(ctx context.Context, id string) (string, error) {
	c.mu.Lock()
	cached, hit := c.cache[id]
	c.mu.Unlock()
	if hit {
		return cached, nil
	}

	image, err := c.fetch(ctx, id)
	if err != nil {
		return "", err
	}

	c.mu.Lock()
	if len(c.cache) >= dockerImageCacheLimit {
		c.cache = make(map[string]string)
	}
	c.cache[id] = image
	c.mu.Unlock()
	return image, nil
}

// fetch 查一次 Docker API。404 表示该容器不归这个 Docker 管，不是错误。
func (c *dockerImageClient) fetch(ctx context.Context, id string) (string, error) {
	endpoint := "http://docker/containers/" + url.PathEscape(id) + "/json"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}

	response, err := c.client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusNotFound {
		return "", nil
	}
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Docker API 返回状态码 %d", response.StatusCode)
	}

	var body struct {
		Config struct {
			Image string
		}
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		return "", fmt.Errorf("解析容器元数据失败: %w", err)
	}
	return body.Config.Image, nil
}
