package selector

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"honeyghost/cli/internal/model"
)

// 表达式上限，见 docs/plan/plan13_event_filter.md §3.3。
const (
	maxExprBytes  = 4096
	maxExprNodes  = 128
	maxExprDepth  = 16
	maxAtomValues = 4096
)

// kindOrder 是 kind 取值的输出顺序，与 plan13 §2.1 的编号一致。
var kindOrder = map[model.EventKind]int{
	model.EventKindProcess:        0,
	model.EventKindExec:           1,
	model.EventKindCredential:     2,
	model.EventKindNamespace:      3,
	model.EventKindFileSyscall:    4,
	model.EventKindMemory:         5,
	model.EventKindNetworkSyscall: 6,
	model.EventKindKernel:         7,
	model.EventKindFile:           8,
}

// exprKeys 是 -e 允许的 key；key 大小写敏感。
var exprKeys = map[string]model.FilterField{
	"type":      model.FilterFieldType,
	"kind":      model.FilterFieldKind,
	"pid":       model.FilterFieldPID,
	"ppid":      model.FilterFieldPPID,
	"roleID":    model.FilterFieldRoleID,
	"role":      model.FilterFieldRoleLabel,
	"contextID": model.FilterFieldContextID,
}

// ParseExpr 解析 -e 的取值并合并为单个表达式。
//
// 空切片返回 nil；重复的 -e 取交。语法错误与上限错误都按用法错误返回，
// 语法错误带 1-based 列号。
func ParseExpr(values []string) (*model.FilterExpr, error) {
	if len(values) == 0 {
		return nil, nil
	}
	parsed := make([]*model.FilterExpr, 0, len(values))
	for _, source := range values {
		if strings.TrimSpace(source) == "" {
			return nil, fmt.Errorf("invalid -e value %q: empty expression", source)
		}
		if len(source) > maxExprBytes {
			return nil, fmt.Errorf(
				"invalid -e value %q: expression is larger than %d bytes", source, maxExprBytes)
		}
		expr, err := newExprParser(source).parse()
		if err != nil {
			return nil, err
		}
		parsed = append(parsed, expr)
	}

	merged := parsed[0]
	if len(parsed) > 1 {
		kids := make([]model.FilterExpr, 0, len(parsed))
		for _, expr := range parsed {
			if expr.Logic == model.FilterLogicAnd {
				kids = append(kids, expr.Kids...)
				continue
			}
			kids = append(kids, *expr)
		}
		merged = &model.FilterExpr{Logic: model.FilterLogicAnd, Kids: kids}
	}
	if nodes := countExprNodes(merged); nodes > maxExprNodes {
		return nil, fmt.Errorf("-e expressions combine to %d nodes (max %d)", nodes, maxExprNodes)
	}
	if depth := exprDepth(merged); depth > maxExprDepth {
		return nil, fmt.Errorf("-e expressions combine to depth %d (max %d)", depth, maxExprDepth)
	}
	return merged, nil
}

// exprParser 是单条 -e 源文本的递归下降解析器。
type exprParser struct {
	source string
	pos    int // 下一个待读字节的偏移
	nodes  int
}

func newExprParser(source string) *exprParser {
	return &exprParser{source: source}
}

// parse 解析整条源文本并要求恰好消费完。
func (p *exprParser) parse() (*model.FilterExpr, error) {
	expr, _, err := p.parseOr(0)
	if err != nil {
		return nil, err
	}
	p.skipSpaces()
	if p.pos < len(p.source) {
		return nil, p.errorf(p.pos+1, "unexpected %q", string(p.source[p.pos]))
	}
	return expr, nil
}

// parseOr 解析 or 层；返回节点与 AST 深度。
func (p *exprParser) parseOr(nest int) (*model.FilterExpr, int, error) {
	if nest > maxExprDepth {
		return nil, 0, p.errorf(p.pos+1, "expression exceeds nesting depth %d", maxExprDepth)
	}
	left, depth, err := p.parseAnd(nest)
	if err != nil {
		return nil, 0, err
	}
	kids := []model.FilterExpr{*left}
	maxDepth := depth
	operatorColumn := 0
	for {
		p.skipSpaces()
		switch {
		case p.peekSymbol("||"):
			operatorColumn = p.pos + 1
			p.pos += 2
		case p.peekKeyword("or"):
			operatorColumn = p.pos + 1
			p.pos += 2
		default:
			if len(kids) == 1 {
				return left, depth, nil
			}
			nodeDepth := maxDepth + 1
			if err := p.addNode(nodeDepth, operatorColumn); err != nil {
				return nil, 0, err
			}
			return &model.FilterExpr{Logic: model.FilterLogicOr, Kids: kids}, nodeDepth, nil
		}
		right, rightDepth, err := p.parseAnd(nest)
		if err != nil {
			return nil, 0, err
		}
		kids = append(kids, *right)
		if rightDepth > maxDepth {
			maxDepth = rightDepth
		}
	}
}

// parseAnd 解析 and 层。
func (p *exprParser) parseAnd(nest int) (*model.FilterExpr, int, error) {
	left, depth, err := p.parseUnary(nest)
	if err != nil {
		return nil, 0, err
	}
	kids := []model.FilterExpr{*left}
	maxDepth := depth
	operatorColumn := 0
	for {
		p.skipSpaces()
		switch {
		case p.peekSymbol("&&"):
			operatorColumn = p.pos + 1
			p.pos += 2
		case p.peekKeyword("and"):
			operatorColumn = p.pos + 1
			p.pos += 3
		default:
			if len(kids) == 1 {
				return left, depth, nil
			}
			nodeDepth := maxDepth + 1
			if err := p.addNode(nodeDepth, operatorColumn); err != nil {
				return nil, 0, err
			}
			return &model.FilterExpr{Logic: model.FilterLogicAnd, Kids: kids}, nodeDepth, nil
		}
		right, rightDepth, err := p.parseUnary(nest)
		if err != nil {
			return nil, 0, err
		}
		kids = append(kids, *right)
		if rightDepth > maxDepth {
			maxDepth = rightDepth
		}
	}
}

// parseUnary 解析 not、括号与原子。
func (p *exprParser) parseUnary(nest int) (*model.FilterExpr, int, error) {
	if nest > maxExprDepth {
		return nil, 0, p.errorf(p.pos+1, "expression exceeds nesting depth %d", maxExprDepth)
	}
	p.skipSpaces()
	if p.pos >= len(p.source) {
		return nil, 0, p.errorf(p.pos+1, "expected a predicate")
	}
	if p.source[p.pos] == '(' {
		p.pos++
		inner, depth, err := p.parseOr(nest + 1)
		if err != nil {
			return nil, 0, err
		}
		p.skipSpaces()
		if p.pos >= len(p.source) || p.source[p.pos] != ')' {
			return nil, 0, p.errorf(p.pos+1, "expected ')'")
		}
		p.pos++
		return inner, depth, nil
	}

	negate := false
	operatorColumn := 0
	switch {
	case p.peekSymbol("!") && !p.peekSymbol("!="):
		negate = true
		operatorColumn = p.pos + 1
		p.pos++
	case p.peekKeyword("not"):
		negate = true
		operatorColumn = p.pos + 1
		p.pos += 3
	}
	if negate {
		inner, depth, err := p.parseUnary(nest + 1)
		if err != nil {
			return nil, 0, err
		}
		nodeDepth := depth + 1
		if err := p.addNode(nodeDepth, operatorColumn); err != nil {
			return nil, 0, err
		}
		return &model.FilterExpr{
			Logic: model.FilterLogicNot,
			Kids:  []model.FilterExpr{*inner},
		}, nodeDepth, nil
	}
	return p.parseAtom()
}

// parseAtom 解析 key compare values。
func (p *exprParser) parseAtom() (*model.FilterExpr, int, error) {
	p.skipSpaces()
	start := p.pos
	key := p.scanIdentifier()
	if key == "" {
		return nil, 0, p.errorf(start+1, "expected a predicate")
	}
	field, ok := exprKeys[key]
	if !ok {
		return nil, 0, p.errorf(start+1,
			"unknown key %q (want type, kind, pid, ppid, roleID, role, or contextID)", key)
	}

	p.skipSpaces()
	compare, compareColumn, err := p.scanCompare()
	if err != nil {
		return nil, 0, err
	}
	values, columns, err := p.parseValues()
	if err != nil {
		return nil, 0, err
	}
	if compare == model.FilterComparePrefix && field != model.FilterFieldRoleLabel {
		return nil, 0, p.errorf(compareColumn, "~= is only supported for role")
	}
	if len(values) > maxAtomValues {
		return nil, 0, p.errorf(start+1,
			"predicate has %d values (max %d)", len(values), maxAtomValues)
	}

	atom := &model.FilterAtom{Field: field, Compare: compare}
	switch field {
	case model.FilterFieldType:
		set := make(map[model.EventType]bool, len(values))
		for i, value := range values {
			eventType, ok := parseExprEventType(value)
			if !ok {
				return nil, 0, p.errorf(columns[i],
					"invalid type %q (want syscall, file, network, or ipc)", value)
			}
			set[eventType] = true
		}
		atom.Types = sortedExprEventTypes(set)
	case model.FilterFieldKind:
		set := make(map[model.EventKind]bool, len(values))
		for i, value := range values {
			kind, ok := parseExprEventKind(value)
			if !ok {
				return nil, 0, p.errorf(columns[i],
					"invalid kind %q (want process, exec, credential, namespace, "+
						"file_syscall, memory, network_syscall, kernel, or file)", value)
			}
			set[kind] = true
		}
		atom.Kinds = sortedExprEventKinds(set)
	case model.FilterFieldRoleLabel:
		atom.Strings = sortedExprStrings(values)
	default:
		set := make(map[uint32]bool, len(values))
		for i, value := range values {
			number, err := strconv.ParseUint(value, 10, 32)
			if err != nil {
				return nil, 0, p.errorf(columns[i], "%q is not a uint32", value)
			}
			if field == model.FilterFieldPID && number == 0 {
				return nil, 0, p.errorf(columns[i], "%q must be greater than 0", value)
			}
			set[uint32(number)] = true
		}
		atom.Numbers = sortedUint32s(set)
	}

	if err := p.addNode(1, start+1); err != nil {
		return nil, 0, err
	}
	return &model.FilterExpr{Atom: atom}, 1, nil
}

// parseValues 解析逗号分隔的取值列表，返回取值与各自的列号。
func (p *exprParser) parseValues() ([]string, []int, error) {
	values := make([]string, 0, 1)
	columns := make([]int, 0, 1)
	for {
		p.skipSpaces()
		column := p.pos + 1
		if p.pos >= len(p.source) || p.atValueEnd() || p.source[p.pos] == ',' {
			return nil, nil, p.errorf(column, "expected a value")
		}
		value, err := p.parseValue()
		if err != nil {
			return nil, nil, err
		}
		values = append(values, value)
		columns = append(columns, column)

		p.skipSpaces()
		if p.pos >= len(p.source) || p.source[p.pos] != ',' {
			return values, columns, nil
		}
		p.pos++
	}
}

// parseValue 解析一个 bare 或 quoted 取值。
//
// quoted 值用反斜杠转义任意下一个字符；bare 值只有 \, 是转义，
// 其余位置的 \ 按字面保留。
func (p *exprParser) parseValue() (string, error) {
	if quote := p.source[p.pos]; quote == '\'' || quote == '"' {
		openColumn := p.pos + 1
		p.pos++
		var value strings.Builder
		for p.pos < len(p.source) {
			c := p.source[p.pos]
			switch {
			case c == '\\':
				if p.pos+1 >= len(p.source) {
					return "", p.errorf(openColumn, "unterminated quoted value")
				}
				value.WriteByte(p.source[p.pos+1])
				p.pos += 2
			case c == quote:
				p.pos++
				if value.Len() == 0 {
					return "", p.errorf(openColumn, "empty value")
				}
				if p.pos < len(p.source) && p.source[p.pos] != ',' &&
					!p.atValueEnd() && !isExprSpace(p.source[p.pos]) {
					return "", p.errorf(p.pos+1,
						"unexpected %q after a quoted value", string(p.source[p.pos]))
				}
				return value.String(), nil
			default:
				value.WriteByte(c)
				p.pos++
			}
		}
		return "", p.errorf(openColumn, "unterminated quoted value")
	}

	start := p.pos
	var value strings.Builder
	for p.pos < len(p.source) {
		c := p.source[p.pos]
		if c == '\\' && p.pos+1 < len(p.source) && p.source[p.pos+1] == ',' {
			value.WriteByte(',')
			p.pos += 2
			continue
		}
		if c == ',' || isExprSpace(c) || p.atValueEnd() {
			break
		}
		value.WriteByte(c)
		p.pos++
	}
	if value.Len() == 0 {
		return "", p.errorf(start+1, "empty value")
	}
	return value.String(), nil
}

// atValueEnd 报告当前位置是否是取值的语法边界。
func (p *exprParser) atValueEnd() bool {
	if p.pos >= len(p.source) {
		return true
	}
	switch p.source[p.pos] {
	case ')', '&', '|':
		return true
	}
	return false
}

func (p *exprParser) scanIdentifier() string {
	start := p.pos
	for p.pos < len(p.source) && isExprIdentByte(p.source[p.pos]) {
		p.pos++
	}
	return p.source[start:p.pos]
}

func (p *exprParser) scanCompare() (model.FilterCompare, int, error) {
	column := p.pos + 1
	if p.pos >= len(p.source) {
		return 0, 0, p.errorf(column, "expected a comparison operator")
	}
	switch p.source[p.pos] {
	case '=':
		p.pos++
		return model.FilterCompareEq, column, nil
	case '!':
		if p.pos+1 < len(p.source) && p.source[p.pos+1] == '=' {
			p.pos += 2
			return model.FilterCompareNe, column, nil
		}
	case '~':
		if p.pos+1 < len(p.source) && p.source[p.pos+1] == '=' {
			p.pos += 2
			return model.FilterComparePrefix, column, nil
		}
	}
	return 0, 0, p.errorf(column, "expected a comparison operator")
}

// peekKeyword 报告当前位置是否是一个独立的关键字（大小写不敏感）。
func (p *exprParser) peekKeyword(word string) bool {
	if p.pos+len(word) > len(p.source) {
		return false
	}
	if !strings.EqualFold(p.source[p.pos:p.pos+len(word)], word) {
		return false
	}
	end := p.pos + len(word)
	if end < len(p.source) {
		switch p.source[end] {
		case '=', '!', '~':
			return false
		}
		if isExprIdentByte(p.source[end]) {
			return false
		}
	}
	return true
}

func (p *exprParser) peekSymbol(symbol string) bool {
	return strings.HasPrefix(p.source[p.pos:], symbol)
}

func (p *exprParser) skipSpaces() {
	for p.pos < len(p.source) && isExprSpace(p.source[p.pos]) {
		p.pos++
	}
}

// addNode 计入一个节点并检查节点数与深度上限。
func (p *exprParser) addNode(depth, column int) error {
	p.nodes++
	if p.nodes > maxExprNodes {
		return p.errorf(column, "expression exceeds %d nodes", maxExprNodes)
	}
	if depth > maxExprDepth {
		return p.errorf(column, "expression exceeds nesting depth %d", maxExprDepth)
	}
	return nil
}

func (p *exprParser) errorf(column int, format string, args ...any) error {
	return fmt.Errorf("invalid -e value %q: %s at column %d",
		p.source, fmt.Sprintf(format, args...), column)
}

func isExprSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n'
}

func isExprIdentByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' ||
		c >= '0' && c <= '9' || c == '_'
}

func parseExprEventType(value string) (model.EventType, bool) {
	eventType := model.EventType(strings.ToLower(value))
	_, ok := eventTypeOrder[eventType]
	return eventType, ok
}

func parseExprEventKind(value string) (model.EventKind, bool) {
	kind := model.EventKind(strings.ToLower(value))
	_, ok := kindOrder[kind]
	return kind, ok
}

func sortedExprEventTypes(set map[model.EventType]bool) []model.EventType {
	out := make([]model.EventType, 0, len(set))
	for eventType := range set {
		out = append(out, eventType)
	}
	sort.Slice(out, func(i, j int) bool {
		return eventTypeOrder[out[i]] < eventTypeOrder[out[j]]
	})
	return out
}

func sortedExprEventKinds(set map[model.EventKind]bool) []model.EventKind {
	out := make([]model.EventKind, 0, len(set))
	for kind := range set {
		out = append(out, kind)
	}
	sort.Slice(out, func(i, j int) bool {
		return kindOrder[out[i]] < kindOrder[out[j]]
	})
	return out
}

func sortedExprStrings(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func countExprNodes(expr *model.FilterExpr) int {
	if expr == nil {
		return 0
	}
	nodes := 1
	for i := range expr.Kids {
		nodes += countExprNodes(&expr.Kids[i])
	}
	return nodes
}

func exprDepth(expr *model.FilterExpr) int {
	if expr == nil {
		return 0
	}
	depth := 0
	for i := range expr.Kids {
		if kidDepth := exprDepth(&expr.Kids[i]); kidDepth > depth {
			depth = kidDepth
		}
	}
	return depth + 1
}
