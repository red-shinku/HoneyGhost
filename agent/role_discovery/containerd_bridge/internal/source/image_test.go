package source

import (
	"context"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/containerd/containerd/v2/core/containers"
	"github.com/containerd/typeurl/v2"
)

// fakeDocker 是由 Unix socket 侍奉的伪造 Docker API：按容器 ID 返回
// Config.Image，未登记的容器返回 404。
type fakeDocker struct {
	socket   string
	failCode int
	requests atomic.Int32
}

func newFakeDocker(t *testing.T, images map[string]string) *fakeDocker {
	t.Helper()
	fake := &fakeDocker{socket: filepath.Join(t.TempDir(), "docker.sock")}
	listener, err := net.Listen("unix", fake.socket)
	if err != nil {
		t.Fatalf("监听伪造的 Docker socket 失败: %v", err)
	}

	server := &http.Server{Handler: http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			fake.requests.Add(1)
			if fake.failCode != 0 {
				w.WriteHeader(fake.failCode)
				return
			}
			id := strings.TrimSuffix(
				strings.TrimPrefix(r.URL.Path, "/containers/"), "/json")
			image, ok := images[id]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_, _ = io.WriteString(w, `{"Config":{"Image":"`+image+`"}}`)
		})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	return fake
}

// rawSpec 把 OCI spec 的 JSON 直接当作 typeurl.Any，避免测试依赖类型注册。
type rawSpec []byte

func (r rawSpec) GetTypeUrl() string {
	return "types.containerd.io/opencontainers/runtime-spec/1/Spec"
}

func (r rawSpec) GetValue() []byte { return r }

// CRI 把镜像引用放在 spec 注解里：普通容器与沙箱各一个键。
func TestImageFromSpec(t *testing.T) {
	cases := map[string]struct {
		spec typeurl.Any
		want string
	}{
		"普通容器": {
			rawSpec(`{"annotations":{"io.kubernetes.cri.image-name":"nginx:1.27"}}`),
			"nginx:1.27",
		},
		"沙箱": {
			rawSpec(`{"annotations":{"io.kubernetes.cri.podsandbox.image-name":"registry.k8s.io/pause:3.10"}}`),
			"registry.k8s.io/pause:3.10",
		},
		"普通容器注解优先": {
			rawSpec(`{"annotations":{"io.kubernetes.cri.image-name":"nginx:1.27","io.kubernetes.cri.podsandbox.image-name":"registry.k8s.io/pause:3.10"}}`),
			"nginx:1.27",
		},
		"无注解":     {rawSpec(`{}`), ""},
		"spec 为空": {nil, ""},
		"坏 JSON":  {rawSpec(`{`), ""},
	}
	for name, c := range cases {
		if got := imageFromSpec(c.spec); got != c.want {
			t.Fatalf("%s: 镜像引用=%q 期望=%q", name, got, c.want)
		}
	}
}

// 容器对象缺镜像引用时，spec 注解先于 Docker 旁路。
func TestImageResolverPrefersSpecAnnotation(t *testing.T) {
	fake := newFakeDocker(t, map[string]string{"c1": "redis:7"})
	resolver := newImageResolver(fake.socket, []string{"moby"}, nil)

	container := containers.Container{
		ID:   "c1",
		Spec: rawSpec(`{"annotations":{"io.kubernetes.cri.image-name":"nginx:1.27"}}`),
	}
	if got := resolver.image(context.Background(), "k8s.io", container); got != "nginx:1.27" {
		t.Fatalf("镜像引用=%q 期望=nginx:1.27", got)
	}
	if fake.requests.Load() != 0 {
		t.Fatalf("spec 注解已有镜像引用时不应查询 Docker API")
	}
}

// 容器对象自带的镜像引用优先，且不再查 Docker。
func TestImageResolverPrefersContainerImage(t *testing.T) {
	fake := newFakeDocker(t, map[string]string{"c1": "redis:7"})
	resolver := newImageResolver(fake.socket, []string{"moby"}, nil)

	got := resolver.image(context.Background(), "moby",
		containers.Container{ID: "c1", Image: "nginx:1.27"})
	if got != "nginx:1.27" {
		t.Fatalf("镜像引用=%q 期望=nginx:1.27", got)
	}
	if fake.requests.Load() != 0 {
		t.Fatalf("容器对象已有镜像引用时不应查询 Docker API")
	}
}

// 容器对象缺镜像引用时回查 Docker。
func TestImageResolverFallsBackToDocker(t *testing.T) {
	fake := newFakeDocker(t, map[string]string{"c1": "redis:7"})
	resolver := newImageResolver(fake.socket, []string{"moby"}, nil)

	if got := resolver.image(context.Background(), "moby",
		containers.Container{ID: "c1"}); got != "redis:7" {
		t.Fatalf("镜像引用=%q 期望=redis:7", got)
	}
}

// 不在 Docker namespace 列表内的容器不查 Docker。
func TestImageResolverNamespaceScope(t *testing.T) {
	fake := newFakeDocker(t, map[string]string{"c1": "redis:7"})
	resolver := newImageResolver(fake.socket, []string{"moby"}, nil)

	if got := resolver.image(context.Background(), "k8s.io",
		containers.Container{ID: "c1"}); got != "" {
		t.Fatalf("namespace 不在列表内时不应补镜像引用，得到 %q", got)
	}
	if fake.requests.Load() != 0 {
		t.Fatalf("namespace 不在列表内时不应查询 Docker API")
	}
}

// namespace 列表为空表示不限定。
func TestImageResolverEmptyNamespacesAllowsAll(t *testing.T) {
	fake := newFakeDocker(t, map[string]string{"c1": "redis:7"})
	resolver := newImageResolver(fake.socket, nil, nil)

	if got := resolver.image(context.Background(), "k8s.io",
		containers.Container{ID: "c1"}); got != "redis:7" {
		t.Fatalf("namespace 列表为空时应对全部 namespace 生效，得到 %q", got)
	}
}

// 未配置 socket 时不启用旁路。
func TestImageResolverDisabledWithoutSocket(t *testing.T) {
	resolver := newImageResolver("", []string{"moby"}, nil)
	if got := resolver.image(context.Background(), "moby",
		containers.Container{ID: "c1"}); got != "" {
		t.Fatalf("未配置 Docker socket 时应返回空，得到 %q", got)
	}
}

// 不归该 Docker 管的容器返回空且无错误。
func TestDockerImageClientUnknownContainer(t *testing.T) {
	fake := newFakeDocker(t, map[string]string{"c1": "redis:7"})
	client := newDockerImageClient(fake.socket)

	image, err := client.image(context.Background(), "missing")
	if err != nil || image != "" {
		t.Fatalf("未知容器应返回空且无错误：image=%q err=%v", image, err)
	}
}

// 镜像引用按容器 ID 缓存，同一容器只查一次 Docker API。
func TestDockerImageClientCaches(t *testing.T) {
	fake := newFakeDocker(t, map[string]string{"c1": "redis:7"})
	client := newDockerImageClient(fake.socket)

	for range 3 {
		if image, err := client.image(context.Background(), "c1"); err != nil || image != "redis:7" {
			t.Fatalf("image=%q err=%v", image, err)
		}
	}
	if fake.requests.Load() != 1 {
		t.Fatalf("Docker API 请求次数=%d 期望=1", fake.requests.Load())
	}
}

// 非 404 的失败以错误返回，由补齐器降级为空。
func TestDockerImageClientReportsFailure(t *testing.T) {
	fake := newFakeDocker(t, nil)
	fake.failCode = http.StatusInternalServerError
	client := newDockerImageClient(fake.socket)

	if _, err := client.image(context.Background(), "c1"); err == nil {
		t.Fatalf("500 应返回错误")
	}
}
