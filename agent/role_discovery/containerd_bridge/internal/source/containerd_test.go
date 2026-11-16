package source

import (
	"testing"

	"github.com/containerd/containerd/api/types/task"
)

// 过滤表达式是 containerd 侧的语法：写错的表现是整条订阅流报错或永不来事件，
// 而两种表现都不会在别处被发现。ParseAll 对多个串取或，故 namespace 必须和
// 每个 topic 写在同一个串里；单独一个 namespace 串会泄漏其他 namespace 的
// 主题事件。
func TestSubscribeFilters(t *testing.T) {
	cases := []struct {
		name      string
		namespace string
		topics    []string
		want      []string
	}{
		{
			name:      "moby",
			namespace: "moby",
			topics:    []string{TopicStart, TopicExit, TopicOOM},
			want: []string{
				`namespace==moby,topic=="/tasks/start"`,
				`namespace==moby,topic=="/tasks/exit"`,
				`namespace==moby,topic=="/tasks/oom"`,
			},
		},
		{
			// namespace 值不加引号；带点的 k8s.io 也必须是合法过滤串
			name:      "k8s.io",
			namespace: "k8s.io",
			topics:    []string{TopicExit},
			want: []string{
				`namespace==k8s.io,topic=="/tasks/exit"`,
			},
		},
	}
	for _, c := range cases {
		got := subscribeFilters(c.namespace, c.topics)
		if len(got) != len(c.want) {
			t.Fatalf("%s: 过滤串个数不符: %v", c.name, got)
		}
		for i := range c.want {
			if got[i] != c.want[i] {
				t.Fatalf("%s: 第 %d 个过滤串=%s 期望=%s", c.name, i, got[i], c.want[i])
			}
		}
	}
}

// 权威集只收主进程仍在的 task：STOPPED 的 task 常驻（ctr 默认不删），
// 收进来会让容器被判「本段已见」而永不退出。
func TestAlive(t *testing.T) {
	alive_cases := map[task.Status]bool{
		task.Status_RUNNING: true,
		task.Status_PAUSED:  true,
		task.Status_PAUSING: true,
		task.Status_UNKNOWN: true,
		task.Status_CREATED: false,
		task.Status_STOPPED: false,
	}
	for status, want := range alive_cases {
		if got := alive(status); got != want {
			t.Fatalf("%v: alive=%v 期望=%v", status, got, want)
		}
	}
}
