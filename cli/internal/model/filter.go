package model

// FilterField 是过滤原子谓词作用的字段。
type FilterField int

const (
	FilterFieldType FilterField = iota + 1
	FilterFieldKind
	FilterFieldPID
	FilterFieldPPID
	FilterFieldRoleID
	FilterFieldRoleLabel
	FilterFieldContextID
)

// FilterCompare 是原子谓词的比较方式。
//
// Eq 命中任一取值，Ne 不命中任何取值，Prefix 按字符串前缀命中。
type FilterCompare int

const (
	FilterCompareEq FilterCompare = iota + 1
	FilterCompareNe
	FilterComparePrefix
)

// FilterLogic 是表达式节点种类。FilterLogicAtom 表示叶子，使用 Atom 字段；
// 其余节点使用 Kids 字段，FilterLogicNot 恰好有一个 kid。
type FilterLogic int

const (
	FilterLogicAtom FilterLogic = iota
	FilterLogicAnd
	FilterLogicOr
	FilterLogicNot
)

// EventKind 是事件的语义子类型，与输出 payload.kind 同名。
type EventKind string

const (
	EventKindProcess        EventKind = "process"
	EventKindExec           EventKind = "exec"
	EventKindCredential     EventKind = "credential"
	EventKindNamespace      EventKind = "namespace"
	EventKindFileSyscall    EventKind = "file_syscall"
	EventKindMemory         EventKind = "memory"
	EventKindNetworkSyscall EventKind = "network_syscall"
	EventKindKernel         EventKind = "kernel"
	EventKindFile           EventKind = "file"
)

// FilterAtom 是单个谓词。
//
// 取值按字段分列：数值字段用 Numbers，type 用 Types，kind 用 Kinds，
// role 标签用 Strings。每个取值集合在解析期排序去重。
type FilterAtom struct {
	Field   FilterField
	Compare FilterCompare
	Numbers []uint32
	Strings []string
	Types   []EventType
	Kinds   []EventKind
}

// FilterExpr 是不可变布尔表达式；零值为没有原子与 kid 的叶子。
type FilterExpr struct {
	Logic FilterLogic
	Kids  []FilterExpr
	Atom  *FilterAtom
}

// UsesField 报告表达式是否含作用于 field 的原子。
func UsesField(expr *FilterExpr, field FilterField) bool {
	if expr == nil {
		return false
	}
	if expr.Atom != nil && expr.Atom.Field == field {
		return true
	}
	for i := range expr.Kids {
		if UsesField(&expr.Kids[i], field) {
			return true
		}
	}
	return false
}
