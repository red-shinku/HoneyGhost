package source

import (
	"testing"

	"github.com/containerd/containerd/api/types/task"
)

// 过滤表达式是 containerd 侧的语法：写错的表现是整条订阅流报错或永不来事件，
// 而两种表现都不会在别处被发现。
func TestSubscribeFilters(t *testing.T) {
	got := subscribeFilters([]string{TopicStart, TopicExit, TopicOOM})
	want := []string{
		`topic=="/tasks/start"`,
		`topic=="/tasks/exit"`,
		`topic=="/tasks/oom"`,
	}
	if len(got) != len(want) {
		t.Fatalf("过滤串个数不符: %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("第 %d 个过滤串=%s 期望=%s", i, got[i], want[i])
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
