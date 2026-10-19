// Package render 把视图模型渲染成表格或 JSON。
package render

import "fmt"

// Format 是输出格式。
type Format int

const (
	FormatTable Format = iota
	FormatJSON
)

// ParseFormat 解析 --output 的取值。
func ParseFormat(s string) (Format, error) {
	switch s {
	case "table":
		return FormatTable, nil
	case "json":
		return FormatJSON, nil
	}
	return 0, fmt.Errorf("invalid output format %q (want table or json)", s)
}

// Options 是所有渲染器共享的选项。NoHeaders 只对表格生效。
type Options struct {
	NoHeaders bool
}
