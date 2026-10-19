// Package model 定义 CLI 的输出视图模型。
//
// 本包是命令层、传输层与渲染层的共同语言，不依赖 proto、Cobra 与 IO。
// JSON tag 是脚本消费者的稳定契约：字段名与 proto 同形，但不随生成代码变化。
package model

// Role 是角色的最小视图。
type Role struct {
	ID    uint32 `json:"role_id"`
	Label string `json:"role_label"`
}

// ProcessSet 是角色或上下文的进程集合。
//
// RootPID 为 0 表示服务端未提供锚点；PIDs 为空切片表示确实没有成员。
type ProcessSet struct {
	RootPID uint32   `json:"root_pid"`
	PIDs    []uint32 `json:"pids"`
}

// RoleDetail 是 role show 的输出。
//
// 指针字段为 nil 表示该段查询失败或未提供，与空集合（非 nil）区分。
type RoleDetail struct {
	RoleID     uint32      `json:"role_id"`
	Label      *string     `json:"role_label"`
	Processes  *ProcessSet `json:"processes"`
	ContextIDs *[]uint32   `json:"context_ids"`
}

// RoleScope 选择 role list 的查询范围。
type RoleScope int

const (
	// RoleScopeSupervision 只返回系统监管的角色。
	RoleScopeSupervision RoleScope = iota
	// RoleScopeAll 返回节点上发现的全部角色。
	RoleScopeAll
)

// RoleStats 是角色管理器的计数快照。
//
// 每个计数为 nil 表示服务端未提供该 optional 字段。
type RoleStats struct {
	Rejected        *uint64 `json:"rejected"`
	UnknownInstance *uint64 `json:"unknown_instance"`
	OwnerConflict   *uint64 `json:"owner_conflict"`
	AnchorsRemoved  *uint64 `json:"anchors_removed"`
	CgroupReadEmpty *uint64 `json:"cgroup_read_empty"`
	QueueRejected   *uint64 `json:"queue_rejected"`
}

// ContextStats 是上下文管理器的计数快照。
type ContextStats struct {
	CtxrootParentUnsettled *uint64 `json:"ctxroot_parent_unsettled"`
	UnknownUnregister      *uint64 `json:"unknown_unregister"`
}

// Status 是 status 命令的总览。
//
// 计数字段为 nil 表示对应段查询失败。
type Status struct {
	SupervisedRoleCount   *int          `json:"supervised_role_count"`
	ExceptionContextCount *int          `json:"exception_context_count"`
	ExtraContextCount     *int          `json:"extra_context_count"`
	RoleStats             *RoleStats    `json:"role_stats"`
	ContextStats          *ContextStats `json:"context_stats"`
}

// 上下文属性名，同时用作 context list 的 KIND 列与 JSON 的 kind 值。
const (
	ContextKindException = "excep"
	ContextKindExtra     = "extra"
)

// ContextRef 是 context list 的一行。
type ContextRef struct {
	Kind string `json:"kind"`
	ID   uint32 `json:"context_id"`
}

// RuntimeSelector 是 events 的 -i 过滤条件。
//
// 维度之内取并集，维度之间取交集；空值表示该维度不加过滤。
type RuntimeSelector struct {
	RoleIDs    []uint32
	RoleLabels []string
	ContextIDs []uint32
	PIDs       []uint32
}

// IsZero 报告是否没有任何过滤条件。
func (s RuntimeSelector) IsZero() bool {
	return len(s.RoleIDs) == 0 && len(s.RoleLabels) == 0 &&
		len(s.ContextIDs) == 0 && len(s.PIDs) == 0
}

// EventType 是事件的大类。
type EventType string

const (
	EventTypeSyscall EventType = "syscall"
	EventTypeFile    EventType = "file"
	EventTypeNetwork EventType = "network"
	EventTypeIPC     EventType = "ipc"
)

// Head 是事件头。proto 没有事件时间戳，故本类型不含时间字段。
type Head struct {
	RoleLabel     string    `json:"role_label"`
	RoleID        uint32    `json:"role_id"`
	ContextID     uint32    `json:"context_id"`
	PID           uint32    `json:"pid"`
	PIDStartTime  uint64    `json:"pid_start_time"`
	PPID          uint32    `json:"ppid"`
	PPIDStartTime uint64    `json:"ppid_start_time"`
	Type          EventType `json:"type"`
}

// Payload 是事件载荷。Kind 为变体名，Fields 的键与 proto 字段同名。
type Payload struct {
	Kind   string         `json:"kind"`
	Fields map[string]any `json:"fields"`
}

// Event 是 events 输出的一条事件。
type Event struct {
	Head    Head    `json:"head"`
	Payload Payload `json:"payload"`
}

// StreamStats 是服务端上报的累计丢弃计数。
type StreamStats struct {
	DroppedEvents uint64 `json:"dropped_events"`
}

// StreamItem 是订阅流的一次接收结果；Event 与 Stats 恰有一个非 nil。
type StreamItem struct {
	Event *Event
	Stats *StreamStats
}
