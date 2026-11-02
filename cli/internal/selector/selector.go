// Package selector 解析 events 命令的 -t 与 -i 选项。
//
// 本包是纯函数：不读环境、不发起 IO、不打印。结果中的集合去重并排序，
// 使相同的命令行输入总是产生相同的请求。
package selector

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"honeyghost/cli/internal/model"
)

var eventTypeOrder = map[model.EventType]int{
	model.EventTypeSyscall: 0,
	model.EventTypeFile:    1,
	model.EventTypeNetwork: 2,
	model.EventTypeIPC:     3,
}

// ParseTypes 解析 -t 的取值：可重复或逗号分隔，大小写不敏感。
// 没有取值时返回空切片，表示全部类型。
func ParseTypes(values []string) ([]model.EventType, error) {
	if len(values) == 0 {
		return []model.EventType{}, nil
	}
	seen := make(map[model.EventType]bool)
	for _, value := range values {
		for _, token := range strings.Split(value, ",") {
			eventType := model.EventType(strings.ToLower(token))
			if _, ok := eventTypeOrder[eventType]; !ok {
				return nil, fmt.Errorf(
					"invalid event type %q (want syscall, file, network, or ipc)", token)
			}
			seen[eventType] = true
		}
	}
	out := make([]model.EventType, 0, len(seen))
	for eventType := range seen {
		out = append(out, eventType)
	}
	sort.Slice(out, func(i, j int) bool {
		return eventTypeOrder[out[i]] < eventTypeOrder[out[j]]
	})
	return out, nil
}

// ParseSelector 解析 -i 的取值。
//
// 语法为 key=value[,value...]；值内的逗号写作 \,。维度之内取并集，
// 维度之间取交集；空结果表示不过滤。
func ParseSelector(values []string) (model.RuntimeSelector, error) {
	var result model.RuntimeSelector
	roleIDs := make(map[uint32]bool)
	roleLabels := make(map[string]bool)
	contextIDs := make(map[uint32]bool)
	pids := make(map[uint32]bool)

	for _, token := range values {
		key, rawValues, ok := strings.Cut(token, "=")
		if !ok {
			return model.RuntimeSelector{}, fmt.Errorf(
				"invalid -i value %q: want key=value[,value...]", token)
		}
		if key == "" {
			return model.RuntimeSelector{}, fmt.Errorf(
				"invalid -i value %q: empty key", token)
		}
		items := splitEscapedCommas(rawValues)
		if len(items) == 1 && items[0] == "" {
			return model.RuntimeSelector{}, fmt.Errorf(
				"invalid -i value %q: empty value", token)
		}

		switch key {
		case "roleID":
			for _, item := range items {
				id, err := parseSelectorID(token, item)
				if err != nil {
					return model.RuntimeSelector{}, err
				}
				roleIDs[id] = true
			}
		case "role":
			for _, item := range items {
				if item == "" {
					return model.RuntimeSelector{}, fmt.Errorf(
						"invalid -i value %q: empty value in list", token)
				}
				roleLabels[item] = true
			}
		case "contextID":
			for _, item := range items {
				id, err := parseSelectorID(token, item)
				if err != nil {
					return model.RuntimeSelector{}, err
				}
				contextIDs[id] = true
			}
		case "pid":
			for _, item := range items {
				id, err := parseSelectorID(token, item)
				if err != nil {
					return model.RuntimeSelector{}, err
				}
				pids[id] = true
			}
		default:
			return model.RuntimeSelector{}, fmt.Errorf(
				"invalid -i value %q: unknown key %q (want roleID, role, contextID, or pid)",
				token, key)
		}
	}

	result.RoleIDs = sortedUint32s(roleIDs)
	result.ContextIDs = sortedUint32s(contextIDs)
	result.PIDs = sortedUint32s(pids)
	for label := range roleLabels {
		result.RoleLabels = append(result.RoleLabels, label)
	}
	sort.Strings(result.RoleLabels)
	return result, nil
}

func splitEscapedCommas(s string) []string {
	var items []string
	var current strings.Builder
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '\\' && i+1 < len(s) && s[i+1] == ',':
			current.WriteByte(',')
			i++
		case s[i] == ',':
			items = append(items, current.String())
			current.Reset()
		default:
			current.WriteByte(s[i])
		}
	}
	items = append(items, current.String())
	return items
}

func parseSelectorID(token, item string) (uint32, error) {
	value, err := strconv.ParseUint(item, 10, 32)
	if err != nil {
		return 0, fmt.Errorf(
			"invalid -i value %q: %q is not a uint32", token, item)
	}
	if value == 0 {
		return 0, fmt.Errorf(
			"invalid -i value %q: %q must be greater than 0", token, item)
	}
	return uint32(value), nil
}

func sortedUint32s(set map[uint32]bool) []uint32 {
	if len(set) == 0 {
		return nil
	}
	out := make([]uint32, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
